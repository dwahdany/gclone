//! Small shared helpers (SPEC §9.3): encodings, constant-time compare, randomness, atomic
//! file writes, clocks, date/time parsing and formatting.
//!
//! No calendar crate: RFC 3339 parsing and civil-date arithmetic are hand-written here, HTTP
//! dates go through `httpdate`, local time through `libc::localtime_r`.

use base64::Engine as _;
#[cfg(unix)]
use std::io::{self, Write as _};
#[cfg(unix)]
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

// ---------------------------------------------------------------------------------------------
// encodings
// ---------------------------------------------------------------------------------------------

const HEX: &[u8; 16] = b"0123456789abcdef";

/// Lowercase hex.
pub fn hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for &x in b {
        s.push(HEX[(x >> 4) as usize] as char);
        s.push(HEX[(x & 15) as usize] as char);
    }
    s
}

/// Strict inverse of [`hex`]: an even number of **lowercase** hex digits. Upper-case digits are
/// rejected so that every byte string has exactly one accepted spelling (object names, ids).
/// Lower-case user input first if it may be upper case.
pub fn unhex(s: &str) -> Option<Vec<u8>> {
    let b = s.as_bytes();
    if !b.len().is_multiple_of(2) {
        return None;
    }
    fn val(c: u8) -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            _ => None,
        }
    }
    let mut out = Vec::with_capacity(b.len() / 2);
    for pair in b.as_chunks::<2>().0 {
        out.push(val(pair[0])? << 4 | val(pair[1])?);
    }
    Some(out)
}

/// base64url without padding.
pub fn b64url(b: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

/// Inverse of [`b64url`]; padding, other alphabets and non-canonical trailing bits are rejected.
pub fn unb64url(s: &str) -> Option<Vec<u8>> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .ok()
}

/// The Crockford base32 alphabet (no I, L, O, U).
pub const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// 5 bits per character, MSB first. `len(b) * 8` must be a multiple of 5 (the head fingerprint
/// encodes 5 bytes into 8 symbols); a trailing partial group — a caller bug, caught by a
/// debug assertion — is padded with zero bits.
pub fn crockford_encode(b: &[u8]) -> String {
    debug_assert!(
        (b.len() * 8).is_multiple_of(5),
        "crockford_encode: bit length must be a multiple of 5"
    );
    let mut out = String::with_capacity((b.len() * 8).div_ceil(5));
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    for &x in b {
        acc = (acc << 8) | x as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(CROCKFORD[((acc >> bits) & 31) as usize] as char);
        }
        acc &= (1 << bits) - 1;
    }
    if bits > 0 {
        out.push(CROCKFORD[((acc << (5 - bits)) & 31) as usize] as char);
    }
    out
}

/// Constant time for equal lengths (the lengths themselves are not secret).
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut acc = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        acc |= x ^ y;
    }
    std::hint::black_box(acc) == 0
}

/// `N` bytes from the OS CSPRNG (`getrandom::fill`). Aborts the process on failure: there is no
/// safe way to continue without randomness.
pub fn random<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    if getrandom::fill(&mut b).is_err() {
        eprintln!("gclone: the operating system's random number generator failed");
        std::process::abort();
    }
    b
}

// ---------------------------------------------------------------------------------------------
// clocks
// ---------------------------------------------------------------------------------------------

/// Local wall clock, milliseconds since the Unix epoch.
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Local wall clock, nanoseconds since the Unix epoch.
pub fn now_ns() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------------------------
// files
// ---------------------------------------------------------------------------------------------

/// Writes `bytes` to `path` atomically: a temp file in the same directory, opened
/// `O_CREAT | O_EXCL | O_NOFOLLOW` and created with `mode` (never chmod-ed afterwards), then
/// `fsync`, `rename`, `fsync` of the directory (§8.1).
#[cfg(unix)]
pub fn write_atomic(path: &Path, bytes: &[u8], mode: u32) -> io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let name = path.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "write_atomic: path has no file name",
        )
    })?;
    let dir = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let mut tmp_name = atomic_temp_prefix(name);
    tmp_name.push(hex(&random::<8>()));
    let tmp = dir.join(tmp_name);

    let write = || -> io::Result<()> {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        drop(f);
        std::fs::rename(&tmp, path)
    };
    if let Err(e) = write() {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    std::fs::File::open(dir)?.sync_all()
}

/// `.<name>.tmp-`: what the temp files of `write_atomic` for a file called `name` start with;
/// 16 lowercase hex digits follow.
#[cfg(unix)]
fn atomic_temp_prefix(name: &std::ffi::OsStr) -> std::ffi::OsString {
    let mut prefix = std::ffi::OsString::from(".");
    prefix.push(name);
    prefix.push(".tmp-");
    prefix
}

/// Removes the temp files that interrupted `write_atomic(path, ..)` calls left beside `path`
/// (a process killed between creating the temp file and the rename): each is a full copy of
/// what was being written. Returns how many were removed; a missing directory is `Ok(0)`.
/// The caller must know that no other process is writing `path` at this moment, or accept that
/// such a write fails.
#[cfg(unix)]
pub fn remove_atomic_leftovers(path: &Path) -> io::Result<usize> {
    let Some(name) = path.file_name() else {
        return Ok(0);
    };
    let dir = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let prefix = atomic_temp_prefix(name);
    let prefix = prefix.as_encoded_bytes();
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(e),
    };
    let mut removed = 0;
    for entry in entries {
        let entry = entry?;
        let file_name = entry.file_name();
        let is_temp = file_name
            .as_encoded_bytes()
            .strip_prefix(prefix)
            .is_some_and(|rest| {
                rest.len() == 16
                    && rest
                        .iter()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
            });
        if !is_temp {
            continue;
        }
        match std::fs::remove_file(entry.path()) {
            Ok(()) => removed += 1,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
    }
    Ok(removed)
}

/// `mkdir -p` where every level this call creates gets mode 0700 **at creation**
/// (`DirBuilder::mode`), not created and then tightened. Existing directories are left alone.
#[cfg(unix)]
pub fn create_dir_private(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)
}

/// §8.1 strict loading (used by `config::FileSecretStore` and `auth::TokenProvider`): true iff
/// `md` is owned by the effective uid and has no group/other permission bits.
#[cfg(unix)]
pub fn is_private(md: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    // SAFETY: geteuid has no preconditions and cannot fail.
    let euid = unsafe { libc::geteuid() };
    md.uid() == euid && md.mode() & 0o077 == 0
}

// ---------------------------------------------------------------------------------------------
// human-readable output
// ---------------------------------------------------------------------------------------------

/// Binary units with at most one decimal: `0 B`, `310 MiB`, `4.2 MiB`, `2 TiB`.
pub fn human_size(n: u64) -> String {
    const UNITS: [&str; 6] = ["KiB", "MiB", "GiB", "TiB", "PiB", "EiB"];
    if n < 1024 {
        return format!("{n} B");
    }
    let mut v = n as f64 / 1024.0;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    let mut r = (v * 10.0).round() / 10.0;
    if r >= 1024.0 && u < UNITS.len() - 1 {
        r = 1.0;
        u += 1;
    }
    if r.fract() == 0.0 {
        format!("{r:.0} {}", UNITS[u])
    } else {
        format!("{r:.1} {}", UNITS[u])
    }
}

/// A time span as one unit, without "ago": `45 s`, `12 min`, `2 h`, `3 d` (seconds below one
/// minute, minutes below one hour, hours below one day, days from there on).
pub fn human_age(ms_ago: u64) -> String {
    let s = ms_ago / 1000;
    if s < 60 {
        format!("{s} s")
    } else if s < 3600 {
        format!("{} min", s / 60)
    } else if s < 86_400 {
        format!("{} h", s / 3600)
    } else {
        format!("{} d", s / 86_400)
    }
}

/// Decimal with thousands separators: `38,201`.
pub fn group_thousands(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

// ---------------------------------------------------------------------------------------------
// host identity
// ---------------------------------------------------------------------------------------------

/// The short host name (up to the first `.`), `"unknown"` if it cannot be read. Default device
/// name and the `host` field of segments.
#[cfg(unix)]
pub fn hostname() -> String {
    let mut buf = [0u8; 256];
    // SAFETY: the buffer is valid for `buf.len()` bytes; gethostname writes at most that many.
    let rc = unsafe { libc::gethostname(buf.as_mut_ptr().cast(), buf.len()) };
    if rc != 0 {
        return "unknown".to_string();
    }
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    let full = String::from_utf8_lossy(&buf[..end]);
    let short = full.split('.').next().unwrap_or("").trim();
    if short.is_empty() {
        "unknown".to_string()
    } else {
        short.to_string()
    }
}

/// A stable machine identifier for the machine fingerprint (§5.3): `gethostuuid(2)` on macOS
/// (16 bytes), the trimmed contents of `/etc/machine-id` on Linux, empty if unavailable. The
/// hostname is deliberately not part of it.
#[cfg(unix)]
pub fn host_id() -> Vec<u8> {
    #[cfg(target_os = "macos")]
    {
        let mut id = [0u8; 16];
        let wait = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: `id` is a valid 16-byte buffer (uuid_t) and `wait` a valid timespec.
        let rc = unsafe { libc::gethostuuid(id.as_mut_ptr(), &wait) };
        if rc == 0 { id.to_vec() } else { Vec::new() }
    }
    #[cfg(not(target_os = "macos"))]
    {
        match std::fs::read("/etc/machine-id") {
            Ok(b) => b.trim_ascii().to_vec(),
            Err(_) => Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------------------------------
// date / time
// ---------------------------------------------------------------------------------------------

/// Days since 1970-01-01 of a proleptic Gregorian date (Howard Hinnant's algorithm).
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m as i64 + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Inverse of [`days_from_civil`]: `(year, month, day)`.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    let y = yoe + era * 400 + if m <= 2 { 1 } else { 0 };
    (y, m, d)
}

fn days_in_month(y: i64, m: u32) -> u32 {
    match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        _ => {
            if (y % 4 == 0 && y % 100 != 0) || y % 400 == 0 {
                29
            } else {
                28
            }
        }
    }
}

/// Fixed-width decimal field.
fn digits(b: &[u8]) -> Option<u32> {
    if b.is_empty() || !b.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let mut v = 0u32;
    for &c in b {
        v = v.checked_mul(10)?.checked_add((c - b'0') as u32)?;
    }
    Some(v)
}

/// RFC 3339 timestamp → milliseconds since the Unix epoch. Drive's `createdTime` looks like
/// `2026-11-11T09:14:03.123Z`; the fraction is optional (any number of digits, truncated to
/// milliseconds) and the zone is `Z` or `±hh:mm`. Anything else, and any time before 1970, is
/// `None`.
pub fn parse_rfc3339_ms(s: &str) -> Option<u64> {
    let b = s.as_bytes();
    if b.len() < 20 {
        return None;
    }
    if b[4] != b'-'
        || b[7] != b'-'
        || !matches!(b[10], b'T' | b't')
        || b[13] != b':'
        || b[16] != b':'
    {
        return None;
    }
    let year = digits(&b[0..4])? as i64;
    let month = digits(&b[5..7])?;
    let day = digits(&b[8..10])?;
    let hour = digits(&b[11..13])?;
    let min = digits(&b[14..16])?;
    let sec = digits(&b[17..19])?;
    if !(1..=12).contains(&month) || day < 1 || day > days_in_month(year, month) {
        return None;
    }
    // 60 is accepted for a leap second and counts as the following second
    if hour > 23 || min > 59 || sec > 60 {
        return None;
    }
    let mut i = 19;
    let mut ms = 0u64;
    if b[i] == b'.' {
        i += 1;
        let start = i;
        while i < b.len() && b[i].is_ascii_digit() {
            if i - start < 3 {
                ms = ms * 10 + (b[i] - b'0') as u64;
            }
            i += 1;
        }
        let n = i - start;
        if n == 0 {
            return None;
        }
        for _ in n..3 {
            ms *= 10;
        }
    }
    let offset_s: i64 = match *b.get(i)? {
        b'Z' | b'z' => {
            if i + 1 != b.len() {
                return None;
            }
            0
        }
        sign @ (b'+' | b'-') => {
            let z = &b[i + 1..];
            if z.len() != 5 || z[2] != b':' {
                return None;
            }
            let oh = digits(&z[0..2])?;
            let om = digits(&z[3..5])?;
            if oh > 23 || om > 59 {
                return None;
            }
            let o = (oh * 3600 + om * 60) as i64;
            if sign == b'+' { o } else { -o }
        }
        _ => return None,
    };
    let secs = days_from_civil(year, month, day) * 86_400 + (hour * 3600 + min * 60 + sec) as i64
        - offset_s;
    if secs < 0 {
        return None;
    }
    Some(secs as u64 * 1000 + ms)
}

/// `Date:` response header (IMF-fixdate, e.g. `Wed, 11 Nov 2026 09:14:03 GMT`) → milliseconds
/// since the Unix epoch.
pub fn parse_http_date_ms(s: &str) -> Option<u64> {
    let t = httpdate::parse_http_date(s.trim()).ok()?;
    Some(t.duration_since(UNIX_EPOCH).ok()?.as_millis() as u64)
}

/// `20261111T091403Z` — UTC, used in local conflict names (§5.1).
pub fn format_utc_compact(ms: u64) -> String {
    let secs = (ms / 1000) as i64;
    let (y, m, d) = civil_from_days(secs.div_euclid(86_400));
    let rem = secs.rem_euclid(86_400);
    format!(
        "{y:04}{m:02}{d:02}T{:02}{:02}{:02}Z",
        rem / 3600,
        rem / 60 % 60,
        rem % 60
    )
}

/// `2026-11-11 10:14` in the local time zone (`ls -l`, `restore --list`). Falls back to UTC if
/// the C library cannot convert the time.
#[cfg(unix)]
pub fn format_local_minute(ms: u64) -> String {
    // The type is `time_t`, taken from `localtime_r`'s signature instead of being named: the
    // libc crate marks the name deprecated on musl targets (its width there is to change on
    // 32-bit systems), and the release binaries for Linux are musl builds.
    let t = (ms / 1000) as _;
    // SAFETY: `tm` is plain data for which all-zero is a valid value; localtime_r only writes
    // into it and reads `t`.
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    let ok = unsafe { !libc::localtime_r(&t, &mut tm).is_null() };
    if ok {
        format!(
            "{:04}-{:02}-{:02} {:02}:{:02}",
            tm.tm_year as i64 + 1900,
            tm.tm_mon + 1,
            tm.tm_mday,
            tm.tm_hour,
            tm.tm_min
        )
    } else {
        let secs = (ms / 1000) as i64;
        let (y, m, d) = civil_from_days(secs.div_euclid(86_400));
        let rem = secs.rem_euclid(86_400);
        format!(
            "{y:04}-{m:02}-{d:02} {:02}:{:02}",
            rem / 3600,
            rem / 60 % 60
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    #[test]
    fn hex_round_trip() {
        assert_eq!(hex(&[]), "");
        assert_eq!(hex(&[0x00, 0x0f, 0xa0, 0xff]), "000fa0ff");
        assert_eq!(unhex("000fa0ff"), Some(vec![0x00, 0x0f, 0xa0, 0xff]));
        assert_eq!(unhex(""), Some(vec![]));
        assert_eq!(unhex("0"), None);
        assert_eq!(unhex("0g"), None);
        assert_eq!(unhex("0F"), None, "upper case is not canonical");
        assert_eq!(unhex(" 0f"), None);
        assert_eq!(unhex("é0"), None);
        let all: Vec<u8> = (0..=255).collect();
        assert_eq!(unhex(&hex(&all)), Some(all));
    }

    #[test]
    fn b64url_round_trip() {
        assert_eq!(b64url(&[]), "");
        assert_eq!(b64url(&[0xfb, 0xff]), "-_8");
        assert_eq!(unb64url("-_8"), Some(vec![0xfb, 0xff]));
        assert_eq!(unb64url("-_8="), None, "padding is rejected");
        assert_eq!(unb64url("+/8"), None, "standard alphabet is rejected");
        assert_eq!(
            unb64url("-_9"),
            None,
            "non-canonical trailing bits are rejected"
        );
        assert_eq!(unb64url("a"), None);
        for n in 0..70usize {
            let v: Vec<u8> = (0..n).map(|i| (i * 37 + 11) as u8).collect();
            let s = b64url(&v);
            assert!(!s.contains('='));
            assert_eq!(unb64url(&s), Some(v));
        }
        // 32 bytes → 43 characters (keys in JSON)
        assert_eq!(b64url(&[7u8; 32]).len(), 43);
    }

    #[test]
    fn crockford() {
        assert_eq!(crockford_encode(&[]), "");
        assert_eq!(crockford_encode(&[0xff; 5]), "ZZZZZZZZ");
        assert_eq!(crockford_encode(&[0; 5]), "00000000");
        let ten: Vec<u8> = (0..10).collect();
        let s = crockford_encode(&ten);
        assert_eq!(s.len(), 16);
        assert_eq!(s, "000G40R40M30E209");
        assert!(s.bytes().all(|c| CROCKFORD.contains(&c)));
        // round trip through a reference decoder
        let mut acc: u128 = 0;
        for c in s.bytes() {
            acc = acc << 5 | CROCKFORD.iter().position(|&x| x == c).unwrap() as u128;
        }
        assert_eq!(&acc.to_be_bytes()[6..], &ten[..]);
        for c in b"ILOU" {
            assert!(!CROCKFORD.contains(c));
        }
    }

    #[test]
    fn ct_eq_cases() {
        assert!(ct_eq(b"", b""));
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"ab"));
        assert!(!ct_eq(b"", b"a"));
        assert!(!ct_eq(&[0u8; 32], &[0x80u8; 32]));
    }

    #[test]
    fn random_is_random() {
        let a: [u8; 32] = random();
        let b: [u8; 32] = random();
        assert_ne!(a, b);
        assert_ne!(a, [0u8; 32]);
        let _empty: [u8; 0] = random();
    }

    #[test]
    fn clocks() {
        let ms = now_ms();
        let ns = now_ns();
        assert!(ms > 1_700_000_000_000);
        assert!((ns / 1_000_000 - ms as i64).abs() < 5_000);
    }

    #[test]
    fn write_atomic_mode_and_replace() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("secrets.json");
        write_atomic(&p, b"one", 0o600).unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"one");
        assert_eq!(std::fs::metadata(&p).unwrap().mode() & 0o777, 0o600);
        let ino1 = std::fs::metadata(&p).unwrap().ino();

        // replacing swaps in a new inode; a reader holding the old file still sees old bytes
        let mut old = std::fs::File::open(&p).unwrap();
        write_atomic(&p, b"two-two", 0o600).unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"two-two");
        assert_ne!(std::fs::metadata(&p).unwrap().ino(), ino1);
        let mut seen = String::new();
        io::Read::read_to_string(&mut old, &mut seen).unwrap();
        assert_eq!(seen, "one");

        // a too-open existing file is replaced by one with the requested mode
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        write_atomic(&p, b"three", 0o600).unwrap();
        assert_eq!(std::fs::metadata(&p).unwrap().mode() & 0o777, 0o600);

        // no temp files are left behind
        let names: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names, vec![std::ffi::OsString::from("secrets.json")]);

        // a missing directory is an error and leaves nothing behind
        assert!(write_atomic(&dir.path().join("nope/x"), b"x", 0o600).is_err());
        // a path without a file name is refused
        assert!(write_atomic(Path::new("/"), b"x", 0o600).is_err());
        // a symlink at the target is replaced, not followed
        let target = dir.path().join("target");
        std::fs::write(&target, b"keep").unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        write_atomic(&link, b"new", 0o600).unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"keep");
        assert!(
            std::fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_file()
        );
    }

    #[test]
    fn remove_atomic_leftovers_takes_only_the_temp_files_of_that_path() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("secrets.json");
        // nothing there, and a directory that does not exist
        assert_eq!(remove_atomic_leftovers(&p).unwrap(), 0);
        assert_eq!(
            remove_atomic_leftovers(&dir.path().join("absent/secrets.json")).unwrap(),
            0
        );

        write_atomic(&p, b"live", 0o600).unwrap();
        // what a killed `write_atomic` leaves: `.<name>.tmp-<16 lowercase hex>`
        let stale = [
            ".secrets.json.tmp-0011223344556677",
            ".secrets.json.tmp-89abcdef89abcdef",
        ];
        let kept = [
            ".token.json.tmp-0011223344556677",    // another file's temp
            ".secrets.json.tmp-001122334455667",   // 15 digits
            ".secrets.json.tmp-00112233445566778", // 17 digits
            ".secrets.json.tmp-0011223344556G77",  // not hex
            ".secrets.json.tmp-0011223344556A77",  // upper case
            "secrets.json.tmp-0011223344556677",   // no leading dot
            ".secrets.json.bak",
            "config.json",
        ];
        for name in stale.iter().chain(&kept) {
            std::fs::write(dir.path().join(name), b"copy").unwrap();
        }
        assert_eq!(remove_atomic_leftovers(&p).unwrap(), 2);
        for name in stale {
            assert!(!dir.path().join(name).exists(), "{name}");
        }
        for name in kept {
            assert!(dir.path().join(name).exists(), "{name}");
        }
        assert_eq!(std::fs::read(&p).unwrap(), b"live", "the file itself stays");
        assert_eq!(remove_atomic_leftovers(&p).unwrap(), 0);
    }

    #[test]
    fn create_dir_private_is_0700_at_every_level() {
        let dir = tempfile::tempdir().unwrap();
        // tempdir itself may be anything; make the umask permissive for this check
        // SAFETY: umask only changes this process's file-mode creation mask.
        let old = unsafe { libc::umask(0o022) };
        let deep = dir.path().join("a/b/c");
        let res = create_dir_private(&deep);
        unsafe { libc::umask(old) };
        res.unwrap();
        for p in [dir.path().join("a"), dir.path().join("a/b"), deep.clone()] {
            let md = std::fs::metadata(&p).unwrap();
            assert!(md.is_dir());
            assert_eq!(md.mode() & 0o777, 0o700, "{}", p.display());
        }
        // idempotent, and an existing directory keeps its mode
        std::fs::set_permissions(&deep, std::fs::Permissions::from_mode(0o755)).unwrap();
        create_dir_private(&deep).unwrap();
        assert_eq!(std::fs::metadata(&deep).unwrap().mode() & 0o777, 0o755);
    }

    #[test]
    fn is_private_modes() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("f");
        std::fs::write(&f, b"x").unwrap();
        let check = |p: &Path, mode: u32| {
            std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode)).unwrap();
            is_private(&std::fs::symlink_metadata(p).unwrap())
        };
        assert!(check(&f, 0o600));
        assert!(check(&f, 0o400));
        assert!(!check(&f, 0o640));
        assert!(!check(&f, 0o604));
        assert!(!check(&f, 0o644));
        assert!(!check(&f, 0o660));
        let d = dir.path().join("d");
        std::fs::create_dir(&d).unwrap();
        assert!(check(&d, 0o700));
        assert!(!check(&d, 0o750));
        assert!(!check(&d, 0o755));
        assert!(!check(&d, 0o701));
    }

    #[test]
    fn human_sizes() {
        assert_eq!(human_size(0), "0 B");
        assert_eq!(human_size(1023), "1023 B");
        assert_eq!(human_size(1024), "1 KiB");
        assert_eq!(human_size(1536), "1.5 KiB");
        assert_eq!(human_size(4_404_019), "4.2 MiB");
        assert_eq!(human_size(310 * 1024 * 1024), "310 MiB");
        assert_eq!(human_size(2_199_023_255_552), "2 TiB");
        assert_eq!(
            human_size(1024 * 1024 - 1),
            "1 MiB",
            "rounding carries into the next unit"
        );
        assert_eq!(human_size(u64::MAX), "16 EiB");
    }

    #[test]
    fn human_ages_and_grouping() {
        assert_eq!(human_age(0), "0 s");
        assert_eq!(human_age(59_999), "59 s");
        assert_eq!(human_age(12 * 60_000), "12 min");
        assert_eq!(human_age(2 * 3_600_000), "2 h");
        assert_eq!(human_age(23 * 3_600_000 + 59 * 60_000), "23 h");
        assert_eq!(human_age(3 * 86_400_000), "3 d");
        assert_eq!(group_thousands(0), "0");
        assert_eq!(group_thousands(999), "999");
        assert_eq!(group_thousands(1_000), "1,000");
        assert_eq!(group_thousands(38_201), "38,201");
        assert_eq!(group_thousands(1_234_567), "1,234,567");
    }

    #[test]
    fn host_identity() {
        let h = hostname();
        assert!(!h.is_empty());
        assert!(!h.contains('.'));
        // stable between calls; may be empty on systems without a machine id
        assert_eq!(host_id(), host_id());
        #[cfg(target_os = "macos")]
        assert_eq!(host_id().len(), 16);
    }

    #[test]
    fn civil_date_round_trip() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(days_from_civil(2000, 3, 1), 11_017);
        assert_eq!(civil_from_days(11_016), (2000, 2, 29));
        assert_eq!(civil_from_days(-1), (1969, 12, 31));
        for z in (-800_000..800_000).step_by(373) {
            let (y, m, d) = civil_from_days(z);
            assert_eq!(days_from_civil(y, m, d), z);
            assert!(d >= 1 && d <= days_in_month(y, m));
        }
    }

    #[test]
    fn rfc3339() {
        let base = 1_794_388_443_000u64; // 2026-11-11T09:14:03Z
        assert_eq!(parse_rfc3339_ms("2026-11-11T09:14:03Z"), Some(base));
        assert_eq!(
            parse_rfc3339_ms("2026-11-11T09:14:03.123Z"),
            Some(base + 123)
        );
        assert_eq!(parse_rfc3339_ms("2026-11-11T09:14:03.1Z"), Some(base + 100));
        assert_eq!(
            parse_rfc3339_ms("2026-11-11T09:14:03.123456789Z"),
            Some(base + 123)
        );
        assert_eq!(parse_rfc3339_ms("2026-11-11T10:14:03+01:00"), Some(base));
        assert_eq!(
            parse_rfc3339_ms("2026-11-11T10:14:03.5+01:00"),
            Some(base + 500)
        );
        assert_eq!(parse_rfc3339_ms("2026-11-11T03:44:03-05:30"), Some(base));
        assert_eq!(parse_rfc3339_ms("2026-11-11t09:14:03z"), Some(base));
        assert_eq!(parse_rfc3339_ms("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(
            parse_rfc3339_ms("2000-02-29T23:59:59Z"),
            Some(951_868_799_000)
        );
        assert_eq!(
            parse_rfc3339_ms("2016-12-31T23:59:60Z"),
            parse_rfc3339_ms("2017-01-01T00:00:00Z")
        );

        for bad in [
            "",
            "garbage",
            "2026-11-11",
            "2026-11-11T09:14:03",
            "2026-11-11 09:14:03Z",
            "2026-11-11T09:14:03.Z",
            "2026-11-11T09:14:03Zx",
            "2026-11-11T09:14:03+0100",
            "2026-11-11T09:14:03+01:00x",
            "2026-11-11T09:14:03+24:00",
            "2026-13-11T09:14:03Z",
            "2026-00-11T09:14:03Z",
            "2026-02-29T09:14:03Z",
            "2026-11-31T09:14:03Z",
            "2026-11-11T24:14:03Z",
            "2026-11-11T09:60:03Z",
            "2026-11-11T09:14:61Z",
            "2026-1-11T09:14:03Z",
            "+026-11-11T09:14:03Z",
            "1969-12-31T23:59:59Z",
            "1970-01-01T00:00:00+01:00",
            "２０２６-11-11T09:14:03Z",
        ] {
            assert_eq!(parse_rfc3339_ms(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn http_date() {
        assert_eq!(
            parse_http_date_ms("Wed, 11 Nov 2026 09:14:03 GMT"),
            Some(1_794_388_443_000)
        );
        assert_eq!(
            parse_http_date_ms(" Wed, 11 Nov 2026 09:14:03 GMT "),
            Some(1_794_388_443_000)
        );
        assert_eq!(parse_http_date_ms("yesterday"), None);
        assert_eq!(parse_http_date_ms(""), None);
    }

    #[test]
    fn utc_compact() {
        assert_eq!(format_utc_compact(1_794_388_443_000), "20261111T091403Z");
        assert_eq!(format_utc_compact(1_794_388_443_999), "20261111T091403Z");
        assert_eq!(format_utc_compact(0), "19700101T000000Z");
        assert_eq!(format_utc_compact(951_868_799_000), "20000229T235959Z");
    }

    /// `TZ` is process-global: both zones are checked inside this one test, and no other test of
    /// this crate formats local time.
    #[test]
    fn local_minute_utc_and_berlin() {
        // POSIX tzset(3); the libc crate does not export it on every target.
        unsafe extern "C" {
            fn tzset();
        }
        fn set_tz(tz: &str) {
            // SAFETY: test-only; see the note on the test about TZ being process-global.
            unsafe {
                std::env::set_var("TZ", tz);
                tzset();
            }
        }
        let winter = 1_794_388_443_000u64; // 2026-11-11T09:14:03Z
        let summer = 1_782_907_200_000u64; // 2026-07-01T12:00:00Z
        let saved = std::env::var_os("TZ");

        set_tz("UTC");
        assert_eq!(format_local_minute(winter), "2026-11-11 09:14");
        assert_eq!(format_local_minute(summer), "2026-07-01 12:00");
        assert_eq!(format_local_minute(0), "1970-01-01 00:00");

        // Use the zone name where the tz database is installed, the equivalent POSIX rule otherwise.
        let tzdir = std::env::var("TZDIR").unwrap_or_else(|_| "/usr/share/zoneinfo".into());
        let berlin = if Path::new(&tzdir).join("Europe/Berlin").exists() {
            "Europe/Berlin"
        } else {
            "CET-1CEST,M3.5.0,M10.5.0/3"
        };
        set_tz(berlin);
        assert_eq!(
            format_local_minute(winter),
            "2026-11-11 10:14",
            "CET = UTC+1"
        );
        assert_eq!(
            format_local_minute(summer),
            "2026-07-01 14:00",
            "CEST = UTC+2"
        );

        // SAFETY: as above.
        unsafe {
            match saved {
                Some(v) => std::env::set_var("TZ", v),
                None => std::env::remove_var("TZ"),
            }
            tzset();
        }
    }

    // -----------------------------------------------------------------------------------------
    // Dependency smoke tests (SPEC §12.1, WP0): the load-bearing features and the 2026 RustCrypto
    // generation resolve, compile and behave.
    // -----------------------------------------------------------------------------------------

    /// rusqlite `fallible_uint`: a `u64` binds and reads back; values above `i64::MAX` fail
    /// instead of wrapping (§8.4).
    #[test]
    fn dep_rusqlite_u64_binds_and_reads_back() {
        let c = rusqlite::Connection::open_in_memory().unwrap();
        c.execute_batch("CREATE TABLE t(k INTEGER PRIMARY KEY, v INTEGER NOT NULL) WITHOUT ROWID;")
            .unwrap();
        let v: u64 = 1 << 62;
        c.execute(
            "INSERT INTO t(k, v) VALUES (?1, ?2)",
            rusqlite::params![1u64, v],
        )
        .unwrap();
        let back: u64 = c
            .query_row("SELECT v FROM t WHERE k = ?1", [1u64], |r| r.get(0))
            .unwrap();
        assert_eq!(back, v);
        assert!(
            c.execute(
                "INSERT INTO t(k, v) VALUES (?1, ?2)",
                rusqlite::params![2u64, u64::MAX]
            )
            .is_err()
        );
        // inode numbers are bit-cast instead (§8.4)
        c.execute(
            "INSERT INTO t(k, v) VALUES (?1, ?2)",
            rusqlite::params![3u64, u64::MAX as i64],
        )
        .unwrap();
        let ino: i64 = c
            .query_row("SELECT v FROM t WHERE k = 3", [], |r| r.get(0))
            .unwrap();
        assert_eq!(ino as u64, u64::MAX);
        let mode: String = c
            .query_row("PRAGMA journal_mode", [], |r| r.get(0))
            .unwrap();
        assert_eq!(mode, "memory");
    }

    /// tokio `io-std`: `tokio::io::stdout()` exists (`cat` writes to it).
    #[test]
    fn dep_tokio_stdout_compiles() {
        fn _stdout() -> tokio::io::Stdout {
            tokio::io::stdout()
        }
        let _: fn() -> tokio::io::Stdout = _stdout;
    }

    #[test]
    fn dep_hkdf_sha256_rfc5869_case_1() {
        let ikm = [0x0bu8; 22];
        let salt: Vec<u8> = (0x00..=0x0c).collect();
        let info: Vec<u8> = (0xf0..=0xf9).collect();
        let (prk, hk) = hkdf::Hkdf::<sha2::Sha256>::extract(Some(&salt), &ikm);
        assert_eq!(
            hex(&prk),
            "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
        );
        let mut okm = [0u8; 42];
        hk.expand(&info, &mut okm).unwrap();
        assert_eq!(
            hex(&okm),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        );
        // from_prk + expand gives the same bytes (stream key derivation of §4.2 uses Extract/Expand)
        let mut okm2 = [0u8; 42];
        hkdf::Hkdf::<sha2::Sha256>::from_prk(&prk)
            .unwrap()
            .expand(&info, &mut okm2)
            .unwrap();
        assert_eq!(okm, okm2);
        // the one-step constructor (Extract + Expand)
        let mut okm3 = [0u8; 42];
        hkdf::Hkdf::<sha2::Sha256>::new(Some(&salt), &ikm)
            .expand(&info, &mut okm3)
            .unwrap();
        assert_eq!(okm, okm3);
    }

    #[test]
    fn dep_chacha20poly1305_rfc8439_vector() {
        use chacha20poly1305::aead::{Aead, Payload};
        use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
        let key: Vec<u8> = (0x80..=0x9f).collect();
        let nonce = unhex("070000004041424344454647").unwrap();
        let aad = unhex("50515253c0c1c2c3c4c5c6c7").unwrap();
        let pt = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let cipher = ChaCha20Poly1305::new_from_slice(&key).unwrap();
        let nonce = Nonce::try_from(&nonce[..]).unwrap();
        let ct = cipher
            .encrypt(&nonce, Payload { msg: pt, aad: &aad })
            .unwrap();
        assert_eq!(ct.len(), pt.len() + 16);
        assert_eq!(hex(&ct[..16]), "d31a8d34648e60db7b86afbc53ef7ec2");
        assert_eq!(hex(&ct[pt.len()..]), "1ae10b594f09e26a7e902ecbd0600691");
        assert_eq!(
            cipher
                .decrypt(
                    &nonce,
                    Payload {
                        msg: &ct,
                        aad: &aad
                    }
                )
                .unwrap(),
            pt
        );
        let mut bad = ct.clone();
        bad[3] ^= 1;
        assert!(
            cipher
                .decrypt(
                    &nonce,
                    Payload {
                        msg: &bad,
                        aad: &aad
                    }
                )
                .is_err()
        );
        // empty AAD, as the stream container uses it (§4.2)
        let ct2 = cipher.encrypt(&nonce, &pt[..]).unwrap();
        assert_eq!(cipher.decrypt(&nonce, &ct2[..]).unwrap(), pt);
    }

    /// argon2 0.6 without default features but with `alloc`: `hash_password_into` exists (§4.3).
    #[test]
    fn dep_argon2id_hash_password_into() {
        use argon2::{Algorithm, Argon2, Params, Version};
        let derive = |m_kib: u32, salt: &[u8]| {
            let params = Params::new(m_kib, 1, 1, Some(32)).unwrap();
            let mut out = [0u8; 32];
            Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
                .hash_password_into(b"passphrase", salt, &mut out)
                .unwrap();
            out
        };
        let a = derive(64, b"0123456789abcdef");
        assert_eq!(a, derive(64, b"0123456789abcdef"));
        assert_ne!(a, derive(64, b"0123456789abcdeg"));
        assert_ne!(a, derive(128, b"0123456789abcdef"));
        assert_ne!(a, [0u8; 32]);
        // out-of-range parameters are refused by the crate as well
        assert!(Params::new(0, 1, 1, Some(32)).is_err());
    }

    #[test]
    fn dep_md5_and_blake3() {
        use md5::{Digest, Md5};
        assert_eq!(
            hex(&Md5::digest(b"The quick brown fox jumps over the lazy dog")),
            "9e107d9d372bb6826bd81d3542a419d6"
        );
        let mut h = Md5::new();
        h.update(b"The quick brown fox ");
        h.update(b"jumps over the lazy dog");
        assert_eq!(hex(&h.finalize()), "9e107d9d372bb6826bd81d3542a419d6");
        assert_eq!(
            blake3::hash(b"").to_hex().as_str(),
            "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
        );
    }

    #[test]
    fn dep_postcard_round_trip_and_trailing_bytes() {
        #[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
        enum Body {
            V1 { a: u64, s: String, v: Vec<[u8; 4]> },
        }
        let b = Body::V1 {
            a: 300,
            s: "x".into(),
            v: vec![[1, 2, 3, 4]],
        };
        let bytes = postcard::to_stdvec(&b).unwrap();
        assert_eq!(postcard::from_bytes::<Body>(&bytes).unwrap(), b);
        // §4.6 rule 3 needs "no trailing bytes": take_from_bytes exposes the rest
        let mut longer = bytes.clone();
        longer.push(0);
        let (back, rest) = postcard::take_from_bytes::<Body>(&longer).unwrap();
        assert_eq!(back, b);
        assert_eq!(rest, [0]);
    }

    // -----------------------------------------------------------------------------------------
    // Self-tests of the seeded test PRNG (`tests/support/prng.rs`, compiled into this unit-test
    // build as `crate::test_prng`).
    // -----------------------------------------------------------------------------------------
    mod prng_selftest {
        use crate::test_prng::*;

        #[test]
        fn deterministic_per_seed() {
            let mut a = Prng::new(42);
            let mut b = Prng::new(42);
            let xs: Vec<u64> = (0..100).map(|_| a.next_u64()).collect();
            let ys: Vec<u64> = (0..100).map(|_| b.next_u64()).collect();
            assert_eq!(xs, ys);
            let mut c = Prng::new(43);
            assert_ne!(xs[0], c.next_u64());
            // seed 0 works and does not get stuck at zero
            let mut z = Prng::new(0);
            let v: Vec<u64> = (0..10).map(|_| z.next_u64()).collect();
            assert!(v.iter().all(|&x| x != 0));
            assert!(v.windows(2).all(|w| w[0] != w[1]));
        }

        #[test]
        fn frozen_stream() {
            // Guards against accidental changes of the generator: seeds recorded in bug reports
            // must keep reproducing the same case.
            let mut r = Prng::new(1);
            let first = [r.next_u64(), r.next_u64(), r.next_u64()];
            let mut again = Prng::new(1);
            assert_eq!(
                first,
                [again.next_u64(), again.next_u64(), again.next_u64()]
            );
            assert_eq!(first, FROZEN_SEED_1);
        }

        const FROZEN_SEED_1: [u64; 3] = [
            0x4b46_a55d_f361_1b9b,
            0xd7e1_f141_0e76_3ef4,
            0x5f14_ec66_975f_9b06,
        ];

        #[test]
        fn below_and_range_stay_in_bounds_and_cover() {
            let mut r = Prng::new(7);
            let mut seen = [false; 10];
            for _ in 0..1000 {
                let v = r.below(10);
                assert!(v < 10);
                seen[v as usize] = true;
                let w = r.range(5, 8);
                assert!((5..8).contains(&w));
            }
            assert!(seen.iter().all(|&s| s));
            assert_eq!(r.below(1), 0);
            assert_eq!(r.range(9, 10), 9);
            // rough uniformity
            let mut counts = [0u32; 4];
            for _ in 0..40_000 {
                counts[r.index(4)] += 1;
            }
            assert!(
                counts.iter().all(|&c| (9_000..11_000).contains(&c)),
                "{counts:?}"
            );
            let heads = (0..10_000).filter(|_| r.bool()).count();
            assert!((4_500..5_500).contains(&heads));
            let hits = (0..10_000).filter(|_| r.chance(1, 4)).count();
            assert!((2_000..3_000).contains(&hits));
        }

        #[test]
        fn fill_shuffle_pick() {
            let mut r = Prng::new(9);
            let b = r.bytes(13);
            assert_eq!(b.len(), 13);
            assert!(b.iter().any(|&x| x != 0));
            assert_ne!(r.array::<32>(), [0u8; 32]);
            assert_eq!(r.bytes(0), Vec::<u8>::new());

            let mut v: Vec<u32> = (0..50).collect();
            r.shuffle(&mut v);
            let mut sorted = v.clone();
            sorted.sort_unstable();
            assert_eq!(sorted, (0..50).collect::<Vec<_>>());
            assert_ne!(
                v, sorted,
                "50 elements stay in order with probability 1/50!"
            );
            assert!(v.contains(r.pick(&v)));

            let n = r.name(12);
            assert_eq!(n.len(), 12);
            assert!(n.bytes().all(|c| c.is_ascii_lowercase()));

            let mut parent = Prng::new(5);
            let mut child = parent.fork();
            assert_ne!(parent.next_u64(), child.next_u64());
        }

        #[test]
        fn seeds() {
            assert_eq!(parse_seed("42"), Some(42));
            assert_eq!(parse_seed(" 0x2a "), Some(42));
            assert_eq!(parse_seed("0XFF"), Some(255));
            assert_eq!(parse_seed("nope"), None);
            assert_eq!(parse_seed(""), None);
            let mut n = 0;
            let mut firsts = Vec::new();
            for_each_seed("seeds", 5, |rng| {
                n += 1;
                firsts.push(rng.next_u64());
            });
            assert_eq!(n, 5);
            firsts.dedup();
            assert_eq!(firsts.len(), 5, "every case gets its own stream");
        }
    }

    // -----------------------------------------------------------------------------------------
    // Skeleton contract (SPEC §9.2 general API rules): the types that cross task and thread
    // boundaries are `Send`/`Sync`, and the futures of the public async entry points are `Send`.
    // Nothing here runs — the functions only have to type-check. If one of them stops compiling,
    // a package made a shared type or future non-`Send` (for example by holding a non-`Send`
    // guard across an `.await`).
    // -----------------------------------------------------------------------------------------
    #[allow(dead_code, unused_variables, clippy::too_many_arguments)]
    mod api_contract {
        use crate::backend::{AnyBackend, Backend, DirBackend, Flaky, Handle, MemBackend, PutBody};
        use crate::index::Vault;
        use crate::transfer::TransferCtx;
        use std::sync::Arc;

        fn send<T: Send>() {}
        fn send_sync<T: Send + Sync>() {}
        fn send_static<T: Send + 'static>() {}
        fn fut<T: Send>(_: T) {}
        fn backend<B: Backend>() {}

        fn shared_types() {
            backend::<MemBackend>();
            backend::<DirBackend>();
            backend::<Flaky<MemBackend>>();
            backend::<AnyBackend>();
            backend::<crate::backend::drive::DriveBackend>();

            send_static::<crate::crypto::MasterKey>();
            send_static::<crate::crypto::PurposeKey>();
            send_static::<crate::crypto::Keyring>();
            send_sync::<crate::crypto::Keyring>();
            send_static::<crate::crypto::Sealer>();
            send_sync::<crate::crypto::Opener>();
            send_static::<crate::crypto::Passphrase>();
            send::<PutBody>();
            send::<crate::backend::ByteStream>();
            send_sync::<crate::state::Db>();
            send::<crate::state::StateLock>();
            send_sync::<Vault<MemBackend>>();
            send_sync::<Vault<AnyBackend>>();
            send_sync::<TransferCtx<MemBackend>>();
            send::<crate::transfer::UploadEvent>();
            send_static::<crate::transfer::PackBuilder>();
            send_sync::<crate::sync::PlanInput<'static>>();
            send_sync::<crate::sync::Filter>();
            send_sync::<crate::auth::TokenProvider>();
            send::<crate::auth::InteractiveOpts>();
            send_sync::<Box<dyn crate::config::SecretStore>>();
            send::<crate::cli::Ctx>();
            send_sync::<crate::ui::Ui>();
            send_static::<crate::ui::Progress>();
        }

        fn backend_futures<B: Backend>(b: &B, h: &Handle, body: PutBody) {
            fut(b.new_ids(1));
            fut(b.create_folder(h, h, "n"));
            fut(b.put(h, h, "n", body));
            fut(b.get(h, None));
            fut(b.stat(h));
            fut(b.list(h));
            fut(b.find_by_name("n"));
            fut(b.trash(h));
            fut(b.untrash(h));
            fut(b.delete(h));
            fut(b.about());
            fut(crate::backend::get_all(b, h, None));
            fut(crate::backend::conformance::run(MemBackend::new()));
        }

        fn vault_futures<B: Backend>(
            v: &Vault<B>,
            backend: Arc<B>,
            db: crate::state::Db,
            keys: crate::crypto::Keyring,
            create: crate::index::CreateParams,
            open: crate::index::OpenParams,
            kf: &crate::format::SealedObject,
        ) {
            fut(Vault::create(
                backend.clone(),
                db.clone(),
                keys.clone(),
                create,
            ));
            fut(Vault::open(backend.clone(), db, keys, open));
            fut(Vault::<B>::discover(&backend));
            fut(Vault::<B>::verify_visible(&backend, v.handles()));
            fut(v.refresh());
            fut(v.commit());
            fut(v.commit_ops(Vec::new()));
            fut(v.resolve_conflicts());
            fut(v.maybe_compact());
            fut(v.write_snapshot());
            fut(v.cleanup_index());
            fut(v.finish_mutation());
            fut(v.repair(false));
            fut(v.keyfiles());
            fut(v.replace_keyfile(kf));
            fut(v.data_folder());
        }

        fn engine_futures<B: Backend>(
            v: &Vault<B>,
            cx: &TransferCtx<B>,
            req: &crate::sync::SyncRequest,
            plan: crate::sync::Plan,
            ui: &crate::ui::Ui,
            cancel: tokio_util::sync::CancellationToken,
            blob: &crate::types::BlobRec,
            head: &crate::types::Head,
            item: &crate::transfer::DownloadItem,
            version: &crate::types::RemovedVersion,
            out: &mut (dyn tokio::io::AsyncWrite + Unpin + Send),
        ) {
            fut(crate::transfer::download_group(cx, blob, Vec::new()));
            fut(crate::transfer::materialize_empty(item));
            fut(crate::transfer::materialize_empties(Vec::new(), &cancel));
            fut(crate::transfer::read_range(
                &*cx.backend,
                &cx.keys,
                blob,
                head,
                0..1,
                out,
            ));
            fut(crate::transfer::verify_remote(
                &*cx.backend,
                &cx.keys,
                blob,
                head,
            ));
            fut(crate::transfer::locate_blob(&*cx.backend, blob));
            let _events: tokio::sync::mpsc::Receiver<crate::transfer::UploadEvent> =
                crate::transfer::upload_batch(cx.clone(), Handle::top(), Vec::new(), 4);

            fut(crate::sync::run(v, req, ui, cancel.clone()));
            fut(crate::sync::execute(v, 1, req, plan, ui, cancel));
            fut(crate::sync::remote_ops::mkdir(v, "p"));
            fut(crate::sync::remote_ops::rm(v, &[], false));
            fut(crate::sync::remote_ops::mv(v, "a", "b", false));
            fut(crate::sync::remote_ops::restore_candidates(v, "p", 0));
            fut(crate::sync::remote_ops::restorable_under(v, "p", 0));
            fut(crate::sync::remote_ops::restore(v, "p", version));
            fut(crate::sync::remote_ops::restore_many(
                v,
                std::slice::from_ref(version),
            ));
            fut(crate::sync::gc(v, true, false, false));
            fut(crate::sync::check_blobs(v));
            fut(crate::sync::check_local(v, std::path::Path::new("."), ""));
            fut(crate::sync::check_download(
                v,
                "",
                crate::ui::Progress::hidden(),
            ));
        }

        fn auth_and_cli_futures(
            http: &reqwest::Client,
            ep: &crate::auth::AuthEndpoints,
            opts: crate::auth::InteractiveOpts,
            tokens: &crate::auth::TokenProvider,
            g: &crate::cli::GlobalOpts,
            o: crate::cli::OpenOpts,
            shared: Arc<crate::auth::TokenProvider>,
        ) {
            fut(crate::auth::login_interactive(http, ep, opts));
            fut(crate::auth::device_start(http, ep));
            fut(crate::auth::refresh(
                http,
                ep,
                "rt",
                crate::auth::AuthClient::Device,
            ));
            fut(crate::auth::revoke(http, ep, "rt"));
            fut(tokens.access_token());
            fut(tokens.force_refresh());
            fut(crate::backend::drive::run_probes(
                shared,
                crate::backend::drive::DriveConfig::default(),
            ));
            fut(crate::cli::open_ctx(g, o));
            fut(crate::cli::run());
        }
    }
}
