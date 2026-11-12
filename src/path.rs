//! Remote path rules (SPEC §5.1): validation, comparison keys, conflict names, CLI arguments.
//!
//! A remote path is a UTF-8 string of `/`-separated components; the empty string is the vault
//! root (never a valid *entry* path, only a prefix).

use unicode_normalization::UnicodeNormalization;

use crate::consts::{PARTIAL_PREFIX, PATH_COMPONENT_MAX, PATH_MAX, PROBE_PREFIX};
use crate::error::PathError;
use crate::types::Stamp;
use crate::util;

/// §5.1: rejects the empty path, a leading or trailing `/`, an empty component, `.` or `..`,
/// NUL, any component > 255 bytes, a total > 4096 bytes. Runs when ops are created, when index
/// objects are accepted, and again before any local write.
pub fn validate(path: &str) -> Result<(), PathError> {
    if path.is_empty() {
        return Err(PathError::Empty);
    }
    if path.len() > PATH_MAX {
        return Err(PathError::TooLong);
    }
    if path.as_bytes().contains(&0) {
        return Err(PathError::Nul);
    }
    if path.starts_with('/') {
        return Err(PathError::Absolute);
    }
    for c in path.split('/') {
        if c.is_empty() {
            return Err(PathError::EmptyComponent);
        }
        if c == "." || c == ".." {
            return Err(PathError::DotComponent);
        }
        if c.len() > PATH_COMPONENT_MAX {
            return Err(PathError::ComponentTooLong);
        }
    }
    Ok(())
}

/// Comparison key (planner only): `NFC(path)`, or — on a case-insensitive sync root —
/// `NFC(casefold(NFD(path)))` with Unicode **full** case folding. The result is always NFC.
/// Never used as a stored name: the index keeps the exact bytes found on disk.
pub fn cmp_key(path: &str, fold_case: bool) -> String {
    if fold_case {
        let nfd: String = path.nfd().collect();
        caseless::default_case_fold_str(&nfd).nfc().collect()
    } else {
        path.nfc().collect()
    }
}

/// Splits a final component into `(stem, ext)` at its last `.` that is not the first byte:
/// `b.tar.gz` → (`b.tar`, `.gz`), `.bashrc` → (`.bashrc`, ``).
fn split_ext(name: &str) -> (&str, &str) {
    match name.rfind('.') {
        Some(i) if i > 0 => name.split_at(i),
        _ => (name, ""),
    }
}

/// The longest prefix of `s` that is at most `max` bytes and ends on a char boundary.
fn clamp(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// `stem ‖ infix ‖ ext`, at most `max` bytes: the stem is truncated first (at a char boundary),
/// then — only if `infix ‖ ext` alone is still too long — the extension.
fn build_name(stem: &str, infix: &str, ext: &str, max: usize) -> String {
    let ext = clamp(ext, max.saturating_sub(infix.len()));
    let stem = clamp(stem, max.saturating_sub(infix.len() + ext.len()));
    let mut out = String::with_capacity(stem.len() + infix.len() + ext.len());
    out.push_str(stem);
    out.push_str(infix);
    out.push_str(ext);
    out
}

/// Deterministic conflict-copy path (§5.1): the final component becomes
/// `stem.conflict-<dev8>-<lamport>ext` with `dev8`/`lamport` taken from the **loser's stamp**.
///
/// The result is always a valid path (`validate`) when `path` is one: the component is clamped
/// to 255 bytes and the whole path to `PATH_MAX` by truncating the stem, then the extension.
/// Where even the bare `.conflict-<dev8>-<lamport>` does not fit beside the parent — a parent
/// within some 40 bytes of `PATH_MAX` — the copy goes into the nearest ancestor directory that
/// has room for it (the vault root always has). A conflict copy that could not be named would
/// make every resolution fail, and with it every mutating command on every device.
pub fn conflict_name(path: &str, loser: &Stamp) -> String {
    let (stem, ext) = split_ext(file_name(path));
    let infix = format!(".conflict-{}-{}", loser.device.short(), loser.lamport);
    let mut dir = parent(path);
    loop {
        let room = match dir {
            Some(p) => PATH_MAX.saturating_sub(p.len() + 1),
            None => PATH_MAX,
        };
        let max = room.min(PATH_COMPONENT_MAX);
        match dir {
            Some(p) if max >= infix.len() => {
                return format!("{p}/{}", build_name(stem, &infix, ext, max));
            }
            Some(p) => dir = parent(p),
            None => return build_name(stem, &infix, ext, max),
        }
    }
}

/// Local conflict name for a file that must be moved aside (§5.1):
/// `stem.conflict-local-<YYYYMMDDTHHMMSSZ>ext`. `attempt` 0 or 1 is the plain name; `attempt`
/// n ≥ 2 appends `-n` to the timestamp (callers count 1, 2, 3, … until the name is free).
pub fn local_conflict_name(file_name: &str, utc_now_ms: u64, attempt: u32) -> String {
    let (stem, ext) = split_ext(file_name);
    let mut infix = format!(".conflict-local-{}", util::format_utc_compact(utc_now_ms));
    if attempt >= 2 {
        infix.push_str(&format!("-{attempt}"));
    }
    build_name(stem, &infix, ext, PATH_COMPONENT_MAX)
}

/// Joins a prefix and a relative path; an empty prefix is the vault root, an empty `rel` is the
/// prefix itself.
pub fn join(prefix: &str, rel: &str) -> String {
    if prefix.is_empty() {
        rel.to_string()
    } else if rel.is_empty() {
        prefix.to_string()
    } else {
        format!("{prefix}/{rel}")
    }
}

/// Component-aware prefix removal: `strip_prefix("a/b/c", "a/b") = Some("c")`,
/// `strip_prefix("a/b", "a/b") = Some("")`, `strip_prefix("a/bc", "a/b") = None`. The empty
/// prefix matches everything.
pub fn strip_prefix<'a>(path: &'a str, prefix: &str) -> Option<&'a str> {
    if prefix.is_empty() {
        return Some(path);
    }
    let rest = path.strip_prefix(prefix)?;
    if rest.is_empty() {
        Some(rest)
    } else {
        rest.strip_prefix('/')
    }
}

/// The path without its final component; `None` for a single component (its parent is the root).
pub fn parent(path: &str) -> Option<&str> {
    path.rfind('/').map(|i| &path[..i])
}

/// The final component.
pub fn file_name(path: &str) -> &str {
    match path.rfind('/') {
        Some(i) => &path[i + 1..],
        None => path,
    }
}

/// Proper ancestors, nearest first: `a/b/c` → `a/b`, `a`. The root (`""`) is not included.
pub fn ancestors(path: &str) -> impl Iterator<Item = &str> {
    std::iter::successors(parent(path), |p| parent(p))
}

/// Names that are always ignored locally — never uploaded, never deleted (§5.1):
/// `.gclone-partial-*` and `.gclone-probe-*`.
pub fn is_ignored_local_name(name: &str) -> bool {
    name.starts_with(PARTIAL_PREFIX) || name.starts_with(PROBE_PREFIX)
}

/// A `copy`/`sync`/… command-line argument.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Arg {
    Local(std::path::PathBuf),
    /// A validated remote path; `""` is the vault root.
    Remote(String),
}

/// A leading `:` makes the argument remote. `:` alone is the vault root (`Remote("")`);
/// trailing slashes are dropped (`:Photos/` = `:Photos`) and the rest must pass [`validate`].
/// Everything else is a local path, taken as is.
pub fn parse_arg(s: &str) -> Result<Arg, PathError> {
    match s.strip_prefix(':') {
        None => Ok(Arg::Local(std::path::PathBuf::from(s))),
        Some(rest) => {
            if rest.is_empty() {
                return Ok(Arg::Remote(String::new()));
            }
            let trimmed = rest.trim_end_matches('/');
            if trimmed.is_empty() {
                // ":/" and friends: a rooted path, not the vault root
                return Err(PathError::Absolute);
            }
            validate(trimmed)?;
            Ok(Arg::Remote(trimmed.to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::DeviceId;
    use unicode_normalization::{UnicodeNormalization, is_nfc};

    #[test]
    fn validate_table() {
        for ok in [
            "a",
            "a/b",
            "a/b/c.txt",
            "...",
            ".hidden",
            "a/..b",
            "a b/c d",
            "é/ß/日本語",
            "a\\b",
            "-rf",
            ":colon",
            "a/.../b",
            " ",
            "a\nb",
        ] {
            assert_eq!(validate(ok), Ok(()), "{ok:?}");
        }
        let long = "x".repeat(255);
        assert_eq!(validate(&long), Ok(()));
        assert_eq!(validate(&format!("a/{long}/b")), Ok(()));
        // 16 components of 255 bytes + 15 slashes = 4095 bytes; "/y" more is 4097
        let sixteen = vec![long.as_str(); 16].join("/");
        assert_eq!(sixteen.len(), 4095);
        assert_eq!(validate(&sixteen), Ok(()));
        // exactly 4096 bytes: 15 × 255 + 127 + 128 bytes of names + 16 slashes
        let exact = format!(
            "{}/{}/{}",
            vec![long.as_str(); 15].join("/"),
            "y".repeat(127),
            "z".repeat(128)
        );
        assert_eq!(exact.len(), 4096);
        assert_eq!(validate(&exact), Ok(()));

        let cases: [(&str, PathError); 16] = [
            ("", PathError::Empty),
            ("/", PathError::Absolute),
            ("/a", PathError::Absolute),
            ("//a", PathError::Absolute),
            ("a/", PathError::EmptyComponent),
            ("a//b", PathError::EmptyComponent),
            ("a/b/", PathError::EmptyComponent),
            (".", PathError::DotComponent),
            ("..", PathError::DotComponent),
            ("../x", PathError::DotComponent),
            ("a/./b", PathError::DotComponent),
            ("a/../b", PathError::DotComponent),
            ("a/..", PathError::DotComponent),
            ("a\0b", PathError::Nul),
            ("\0", PathError::Nul),
            ("a/b\0/c", PathError::Nul),
        ];
        for (bad, err) in cases {
            assert_eq!(validate(bad), Err(err), "{bad:?}");
        }
        assert_eq!(validate(&"x".repeat(256)), Err(PathError::ComponentTooLong));
        assert_eq!(
            validate(&format!("a/{}", "é".repeat(128))),
            Err(PathError::ComponentTooLong),
            "bytes, not chars"
        );
        assert_eq!(validate(&format!("{sixteen}/y")), Err(PathError::TooLong));
        assert_eq!(validate(&format!("{exact}z")), Err(PathError::TooLong));
    }

    #[test]
    fn cmp_key_normalisation() {
        let nfc = "caf\u{e9}/\u{e9}t\u{e9}";
        let nfd = "cafe\u{301}/e\u{301}te\u{301}";
        assert_ne!(nfc, nfd);
        assert_eq!(cmp_key(nfc, false), cmp_key(nfd, false));
        assert_eq!(cmp_key(nfc, true), cmp_key(nfd, true));
        assert_eq!(cmp_key(nfd, false), nfc);

        // fold off: case matters
        assert_ne!(cmp_key("Foo/A", false), cmp_key("foo/a", false));
        assert_eq!(cmp_key("Foo/A", false), "Foo/A");
        // fold on
        assert_eq!(cmp_key("Foo/A", true), cmp_key("foo/a", true));
        assert_eq!(cmp_key("Foo/A", true), "foo/a");
        assert_eq!(
            cmp_key("\u{c9}T\u{c9}", true),
            cmp_key("e\u{301}te\u{301}", true)
        );
    }

    #[test]
    fn cmp_key_full_case_folding() {
        // ß folds to ss (full folding; to_lowercase would keep ß)
        assert_eq!(cmp_key("Straße", true), cmp_key("STRASSE", true));
        assert_eq!(cmp_key("Straße", true), "strasse");
        assert_ne!(cmp_key("Straße", false), cmp_key("STRASSE", false));
        // final sigma: folding is context-free
        let a = cmp_key("ΟΔΟΣ", true);
        assert_eq!(a, cmp_key("οδος", true));
        assert_eq!(a, cmp_key("οδοσ", true));
        assert_ne!(
            "ΟΔΟΣ".to_lowercase(),
            "οδοσ",
            "str::to_lowercase is context-sensitive"
        );
        // İ (U+0130) folds to i + combining dot above; the key must still be NFC
        let k = cmp_key("İstanbul", true);
        assert!(is_nfc(&k));
        assert_eq!(k, "i\u{307}stanbul");
        assert_eq!(k, cmp_key("I\u{307}STANBUL", true));
        // ligature
        assert_eq!(cmp_key("ﬁle", true), cmp_key("FILE", true));
    }

    #[test]
    fn cmp_key_is_always_nfc_and_idempotent() {
        let samples = [
            "plain/ascii.txt",
            "Å/A\u{30a}/\u{212b}",
            "ǅ/ǆ/Ǆ",
            "ΐ/\u{3b9}\u{308}\u{301}",
            "ẞ/ß/SS",
            "q\u{307}\u{323}/q\u{323}\u{307}",
            "ﬃ/FFI",
            "İ/ı/I/i",
            "한글/\u{1112}\u{1161}\u{11ab}",
        ];
        for s in samples {
            for fold in [false, true] {
                let k = cmp_key(s, fold);
                assert!(is_nfc(&k), "{s:?} fold={fold} → {k:?}");
                assert_eq!(cmp_key(&k, fold), k, "idempotent for {s:?} fold={fold}");
                let nfd: String = s.nfd().collect();
                assert_eq!(
                    cmp_key(&nfd, fold),
                    k,
                    "NFD input gives the same key for {s:?}"
                );
            }
        }
        // canonically equivalent combining-mark orders compare equal
        assert_eq!(
            cmp_key("q\u{307}\u{323}", false),
            cmp_key("q\u{323}\u{307}", false)
        );
    }

    fn stamp() -> Stamp {
        Stamp {
            lamport: 412,
            device: DeviceId([0x9f, 0x2c, 0x11, 0xaa, 1, 2, 3, 4]),
            idx: 7,
        }
    }

    #[test]
    fn conflict_names() {
        let s = stamp();
        assert_eq!(
            conflict_name("a/b.tar.gz", &s),
            "a/b.tar.conflict-9f2c11aa-412.gz"
        );
        assert_eq!(
            conflict_name("draft.txt", &s),
            "draft.conflict-9f2c11aa-412.txt"
        );
        assert_eq!(
            conflict_name(".bashrc", &s),
            ".bashrc.conflict-9f2c11aa-412"
        );
        assert_eq!(
            conflict_name("x/.bashrc", &s),
            "x/.bashrc.conflict-9f2c11aa-412"
        );
        assert_eq!(
            conflict_name("x/.config.d", &s),
            "x/.config.conflict-9f2c11aa-412.d"
        );
        assert_eq!(conflict_name("noext", &s), "noext.conflict-9f2c11aa-412");
        assert_eq!(
            conflict_name("a.b/noext", &s),
            "a.b/noext.conflict-9f2c11aa-412"
        );
        assert_eq!(
            conflict_name("trailing.", &s),
            "trailing.conflict-9f2c11aa-412."
        );
        // deterministic and distinct per loser
        assert_eq!(conflict_name("a/b", &s), conflict_name("a/b", &s));
        let other = Stamp { lamport: 413, ..s };
        assert_ne!(conflict_name("a/b", &s), conflict_name("a/b", &other));
        // the result is a valid path
        assert_eq!(validate(&conflict_name("a/b.tar.gz", &s)), Ok(()));
    }

    #[test]
    fn conflict_name_clamps_to_255_bytes() {
        let s = stamp();
        let infix = ".conflict-9f2c11aa-412";
        // long stem, short extension: the stem is cut, the extension survives
        let name = format!("{}.txt", "x".repeat(251));
        assert_eq!(name.len(), 255);
        let c = conflict_name(&format!("dir/{name}"), &s);
        let last = file_name(&c);
        assert_eq!(last.len(), 255);
        assert!(last.ends_with(&format!("{infix}.txt")));
        assert!(last.starts_with("xxx"));
        assert_eq!(parent(&c), Some("dir"));
        assert_eq!(validate(&c), Ok(()));

        // multi-byte stem: cut at a char boundary, never above 255
        let name = format!("{}.jpg", "é".repeat(125));
        let c = conflict_name(&name, &s);
        assert!(c.len() <= 255);
        assert!(c.len() >= 254);
        assert!(c.ends_with(&format!("{infix}.jpg")));
        assert!(c.starts_with("éé"));

        // a short name is untouched
        assert_eq!(conflict_name("a.b", &s).len(), "a.b".len() + infix.len());

        // pathological: the extension alone is too long → it is cut too, the infix always survives
        let name = format!("a.{}", "y".repeat(253));
        let c = conflict_name(&name, &s);
        assert_eq!(c.len(), 255);
        assert!(c.starts_with(infix), "{c}");
        assert_eq!(validate(&c), Ok(()));

        // a huge lamport still fits
        let big = Stamp {
            lamport: u64::MAX,
            ..s
        };
        let c = conflict_name(&"z".repeat(255), &big);
        assert_eq!(c.len(), 255);
        assert!(c.ends_with(&format!(".conflict-9f2c11aa-{}", u64::MAX)));
    }

    /// A valid path of exactly `len` bytes that ends in `/<last>`.
    fn deep_path(len: usize, last: &str) -> String {
        let mut rest = len - last.len() - 1;
        let mut comps = Vec::new();
        while rest > 0 {
            let n = rest.min(255);
            // never leave a remainder of exactly one byte: that would be an empty component
            let n = if rest - n == 1 { n - 1 } else { n };
            comps.push("d".repeat(n));
            rest = rest.saturating_sub(n + 1);
        }
        let path = format!("{}/{last}", comps.join("/"));
        assert_eq!(path.len(), len);
        assert_eq!(validate(&path), Ok(()));
        path
    }

    #[test]
    fn conflict_name_stays_within_the_path_limit() {
        let s = stamp();
        let infix = ".conflict-9f2c11aa-412";
        let big = Stamp {
            lamport: u64::MAX,
            ..s
        };
        // Whatever the length of a valid path: its conflict copy is a valid path too.
        for len in (PATH_MAX - 300)..=PATH_MAX {
            for last in ["abcde", "a.tar.gz", "x", ".hidden"] {
                let path = deep_path(len, last);
                for stamp in [&s, &big] {
                    let c = conflict_name(&path, stamp);
                    assert_eq!(validate(&c), Ok(()), "{len} {last}");
                    assert_ne!(c, path);
                }
            }
        }

        // room for the whole name: nothing is cut
        let path = deep_path(PATH_MAX - infix.len(), "abc.txt");
        let c = conflict_name(&path, &s);
        assert_eq!(c.len(), PATH_MAX);
        assert_eq!(parent(&c), parent(&path));
        assert_eq!(file_name(&c), format!("abc{infix}.txt"));

        // a little less room: the stem is cut, the extension survives
        let path = deep_path(PATH_MAX - infix.len() + 2, "abc.txt");
        let c = conflict_name(&path, &s);
        assert_eq!(c.len(), PATH_MAX);
        assert_eq!(parent(&c), parent(&path));
        assert_eq!(file_name(&c), format!("a{infix}.txt"));

        // no room for stem or extension: the bare infix
        let path = deep_path(PATH_MAX - infix.len() + 7, "abc.txt");
        let c = conflict_name(&path, &s);
        assert_eq!(parent(&c), parent(&path));
        assert_eq!(file_name(&c), infix);

        // no room beside the parent at all: the copy moves up to the nearest ancestor with room
        let path = deep_path(PATH_MAX, "abc.txt");
        let c = conflict_name(&path, &s);
        assert_eq!(validate(&c), Ok(()));
        let up = parent(parent(&path).unwrap()).unwrap();
        assert_eq!(parent(&c), Some(up));
        assert_eq!(file_name(&c), format!("abc{infix}.txt"));
        // deterministic
        assert_eq!(c, conflict_name(&path, &s));
    }

    #[test]
    fn local_conflict_names() {
        let t = 1_794_388_443_000u64;
        assert_eq!(
            local_conflict_name("notes.txt", t, 1),
            "notes.conflict-local-20261111T091403Z.txt"
        );
        assert_eq!(
            local_conflict_name("notes.txt", t, 0),
            "notes.conflict-local-20261111T091403Z.txt"
        );
        assert_eq!(
            local_conflict_name("notes.txt", t, 2),
            "notes.conflict-local-20261111T091403Z-2.txt"
        );
        assert_eq!(
            local_conflict_name("notes.txt", t, 3),
            "notes.conflict-local-20261111T091403Z-3.txt"
        );
        assert_eq!(
            local_conflict_name(".bashrc", t, 1),
            ".bashrc.conflict-local-20261111T091403Z"
        );
        assert_eq!(
            local_conflict_name("a.tar.gz", t, 1),
            "a.tar.conflict-local-20261111T091403Z.gz"
        );
        let long = local_conflict_name(&format!("{}.bin", "w".repeat(251)), t, 12);
        assert_eq!(long.len(), 255);
        assert!(long.ends_with(".conflict-local-20261111T091403Z-12.bin"));
    }

    #[test]
    fn join_strip_parent() {
        assert_eq!(join("", "a/b"), "a/b");
        assert_eq!(join("p", "a/b"), "p/a/b");
        assert_eq!(join("p/q", ""), "p/q");
        assert_eq!(join("", ""), "");

        assert_eq!(strip_prefix("a/b/c", "a/b"), Some("c"));
        assert_eq!(strip_prefix("a/b/c", "a"), Some("b/c"));
        assert_eq!(strip_prefix("a/b", "a/b"), Some(""));
        assert_eq!(strip_prefix("a/bc", "a/b"), None);
        assert_eq!(strip_prefix("a/b", "a/b/c"), None);
        assert_eq!(strip_prefix("a/b", ""), Some("a/b"));
        assert_eq!(strip_prefix("", ""), Some(""));
        assert_eq!(strip_prefix("b/a", "a"), None);
        for (prefix, rel) in [("", "x/y"), ("p", "x/y"), ("p/q", "x")] {
            assert_eq!(strip_prefix(&join(prefix, rel), prefix), Some(rel));
        }

        assert_eq!(parent("a/b/c"), Some("a/b"));
        assert_eq!(parent("a"), None);
        assert_eq!(file_name("a/b/c.txt"), "c.txt");
        assert_eq!(file_name("c.txt"), "c.txt");
        assert_eq!(
            ancestors("a/b/c/d").collect::<Vec<_>>(),
            ["a/b/c", "a/b", "a"]
        );
        assert_eq!(ancestors("a").count(), 0);
    }

    #[test]
    fn ignored_local_names() {
        assert!(is_ignored_local_name(".gclone-partial-0a1b2c3d"));
        assert!(is_ignored_local_name(".gclone-probe-xyz"));
        assert!(is_ignored_local_name(".gclone-partial-"));
        assert!(!is_ignored_local_name(".gcloneignore"));
        assert!(!is_ignored_local_name("gclone-partial-1"));
        assert!(!is_ignored_local_name(".gclone-part"));
        assert!(!is_ignored_local_name("x.gclone-partial-1"));
    }

    #[test]
    fn parse_args() {
        use std::path::PathBuf;
        assert_eq!(parse_arg(":"), Ok(Arg::Remote(String::new())));
        assert_eq!(parse_arg(":Photos"), Ok(Arg::Remote("Photos".into())));
        assert_eq!(
            parse_arg(":Photos/2026"),
            Ok(Arg::Remote("Photos/2026".into()))
        );
        assert_eq!(parse_arg(":Photos/"), Ok(Arg::Remote("Photos".into())));
        assert_eq!(parse_arg("::x"), Ok(Arg::Remote(":x".into())));
        assert_eq!(parse_arg("."), Ok(Arg::Local(PathBuf::from("."))));
        assert_eq!(
            parse_arg("/abs/dir"),
            Ok(Arg::Local(PathBuf::from("/abs/dir")))
        );
        assert_eq!(
            parse_arg("rel/dir"),
            Ok(Arg::Local(PathBuf::from("rel/dir")))
        );
        assert_eq!(parse_arg("./:odd"), Ok(Arg::Local(PathBuf::from("./:odd"))));
        assert_eq!(parse_arg("a:b"), Ok(Arg::Local(PathBuf::from("a:b"))));
        assert_eq!(parse_arg(""), Ok(Arg::Local(PathBuf::from(""))));
        assert_eq!(parse_arg(":/"), Err(PathError::Absolute));
        assert_eq!(parse_arg(":/abs"), Err(PathError::Absolute));
        assert_eq!(parse_arg(":a//b"), Err(PathError::EmptyComponent));
        assert_eq!(parse_arg(":../x"), Err(PathError::DotComponent));
        assert_eq!(parse_arg(":a/./b"), Err(PathError::DotComponent));
        assert_eq!(parse_arg(":a\0"), Err(PathError::Nul));
    }
}
