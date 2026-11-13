//! What every viewer of the vault does the same way (SPEC §7.4): the JSON shapes of the API,
//! the order of a listing, how a search matches names, `Range`, `Content-Disposition`, and the
//! sentences for what is not there.
//!
//! Pure code — no server, no database, no clock. The local viewer (`gclone web`, `super`)
//! feeds it rows of the SQL replica; the hosted viewer's core (`web-core/`, which compiles this
//! file and `mime.rs` a second time, by path) feeds it rows of its in-memory index. One copy,
//! so the two cannot drift apart. This file may use `crate::path`, `crate::types`, `super::mime`
//! and nothing else of the crate.

use std::cmp::Ordering;
use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use super::mime;
use crate::types::{EntryKind, Head};

/// Entries per `list` answer: the default and the most a client may ask for.
pub const LIST_PAGE: usize = 2000;
pub const LIST_PAGE_MAX: usize = 5000;
/// Matches per `search` answer: the default and the most a client may ask for.
pub const SEARCH_HITS: usize = 200;
pub const SEARCH_HITS_MAX: usize = 1000;

// ---------------------------------------------------------------------------------------------
// JSON shapes
// ---------------------------------------------------------------------------------------------

/// The outcome of the last refresh of the replica, as the page shows it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RefreshState {
    pub at_ms: u64,
    /// The replica is as new as the store.
    pub ok: bool,
    /// Index segments the refresh applied.
    pub applied: u64,
    /// Why not, or what else the user should know.
    pub note: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct EntryJson {
    pub name: String,
    /// Search results and `stat` only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// `stat` of a file, local viewer only: what `/file?id=` takes in place of the path.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub dir: bool,
    /// `"folder"`, or how the viewer shows the file (`mime::Kind`).
    pub kind: &'static str,
    /// Files only.
    pub size: Option<u64>,
    pub mtime_ms: Option<i64>,
}

impl EntryJson {
    pub fn new(name: &str, path: Option<String>, is_dir: bool, head: Option<&Head>) -> EntryJson {
        let file = head.filter(|h| !is_dir && h.entry.kind == EntryKind::File);
        EntryJson {
            name: name.to_owned(),
            path,
            id: None,
            dir: is_dir,
            kind: match is_dir {
                true => "folder",
                false => mime::of_name(name).kind.as_str(),
            },
            size: file.map(|h| h.entry.size),
            mtime_ms: file.map(|h| h.entry.mtime_ns.div_euclid(1_000_000)),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct ListJson {
    pub path: String,
    pub sort: &'static str,
    pub order: &'static str,
    /// Entries in the directory; `entries` holds those from `offset` on, a page of them.
    pub total: usize,
    pub offset: usize,
    pub entries: Vec<EntryJson>,
}

#[derive(Debug, Serialize)]
pub struct SearchJson {
    pub q: String,
    pub sort: &'static str,
    pub order: &'static str,
    pub hits: Vec<EntryJson>,
    /// There are more matches than `hits` holds.
    pub more: bool,
}

#[derive(Debug, Serialize)]
pub struct InfoJson {
    pub vault: String,
    pub backend: &'static str,
    pub device: String,
    pub version: &'static str,
    pub read_only: bool,
    pub files: u64,
    pub bytes: u64,
    pub last_change_ms: Option<u64>,
    pub last_change_by: Option<String>,
    pub refresh: RefreshState,
    /// The head fingerprint (`gclone status`): hosted viewer only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub head: Option<String>,
}

// ---------------------------------------------------------------------------------------------
// What is not there, and what was asked for wrongly
// ---------------------------------------------------------------------------------------------

/// `list` of a path that is no directory of the vault.
pub fn no_folder(path: &str) -> String {
    format!("There is no folder {path:?} in the vault.")
}

/// `stat` or a read of a path that is no file (or, for `stat`, no directory) of the vault.
pub fn no_file(path: &str) -> String {
    format!("There is no file {path:?} in the vault.")
}

/// A numeric parameter that is no number, or too large.
pub fn not_a_number(name: &str, max: usize) -> String {
    format!("{name} is a number up to {max}")
}

pub const LIMIT_IS_ZERO: &str = "limit is at least 1";
pub const PATH_IS_MISSING: &str = "path is missing";

/// `path` of a listing: absent or empty for the vault root, else a valid remote path (§5.1).
/// The path is only ever looked up in the index.
pub fn dir_path(path: Option<&str>) -> Result<String, String> {
    match path {
        None | Some("") => Ok(String::new()),
        Some(path) => match crate::path::validate(path) {
            Ok(()) => Ok(path.to_owned()),
            Err(e) => Err(format!("path: {e}")),
        },
    }
}

/// `path` of one entry: required, a valid remote path.
pub fn entry_path(path: Option<&str>) -> Result<String, String> {
    match dir_path(path)? {
        path if path.is_empty() => Err(PATH_IS_MISSING.to_owned()),
        path => Ok(path),
    }
}

// ---------------------------------------------------------------------------------------------
// Listing order
// ---------------------------------------------------------------------------------------------

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SortKey {
    Name,
    Size,
    Mtime,
}

/// `sort` and `order` of a listing or a search, with their names for the answer.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SortOrder {
    pub key: SortKey,
    pub sort: &'static str,
    pub descending: bool,
    pub order: &'static str,
}

impl SortOrder {
    /// Absent means `name` and `asc`; anything else unknown is refused with the sentence.
    pub fn parse(sort: Option<&str>, order: Option<&str>) -> Result<SortOrder, &'static str> {
        let (key, sort) = match sort.unwrap_or("name") {
            "name" => (SortKey::Name, "name"),
            "size" => (SortKey::Size, "size"),
            "mtime" => (SortKey::Mtime, "mtime"),
            _ => return Err("sort is name, size or mtime"),
        };
        let (descending, order) = match order.unwrap_or("asc") {
            "asc" => (false, "asc"),
            "desc" => (true, "desc"),
            _ => return Err("order is asc or desc"),
        };
        Ok(SortOrder {
            key,
            sort,
            descending,
            order,
        })
    }
}

/// What a listing orders and shows: an entry of a directory, or a match of a search.
pub trait RowView {
    fn name(&self) -> &str;
    /// Tells entries with the same name apart (search: the path).
    fn tie(&self) -> &str;
    fn is_dir(&self) -> bool;
    /// The winner at the entry's path; `None` for a directory that exists only through what
    /// is under it (and, in a search, for every directory).
    fn head(&self) -> Option<&Head>;
}

/// The order of a listing — a directory's and a search's alike. Directories come first,
/// always. `sort=name`: by name ([`natural_cmp`]), reversed as a whole under `order=desc`.
/// `sort=size|mtime`: files by that key, reversed under `desc`, equal keys by name ascending;
/// directories, which have neither a size nor a time, by name ascending in both orders.
pub fn sort_rows<T: RowView>(rows: &mut [T], key: SortKey, descending: bool) {
    let value = |row: &T| match key {
        SortKey::Name => 0,
        SortKey::Size => row.head().map_or(0, |h| i128::from(h.entry.size)),
        SortKey::Mtime => row.head().map_or(0, |h| i128::from(h.entry.mtime_ns)),
    };
    let flip = |o: Ordering| if descending { o.reverse() } else { o };
    rows.sort_by(|a, b| {
        let by_name = || natural_cmp(a.name(), b.name()).then_with(|| a.tie().cmp(b.tie()));
        b.is_dir().cmp(&a.is_dir()).then_with(|| match key {
            SortKey::Name => flip(by_name()),
            _ if a.is_dir() => by_name(),
            _ => flip(value(a).cmp(&value(b))).then_with(by_name),
        })
    });
}

/// The answer to `list`: the directory's entries (`rows`, in any order) sorted, and the page
/// of them that starts at `offset`.
pub fn list_json<T: RowView>(
    path: String,
    mut rows: Vec<T>,
    by: SortOrder,
    offset: usize,
    limit: usize,
) -> ListJson {
    sort_rows(&mut rows, by.key, by.descending);
    let entries = rows
        .iter()
        .skip(offset)
        .take(limit)
        .map(|row| EntryJson::new(row.name(), None, row.is_dir(), row.head()))
        .collect();
    ListJson {
        path,
        sort: by.sort,
        order: by.order,
        total: rows.len(),
        offset,
        entries,
    }
}

/// The answer to `search`: the matches the cap let through (`hits`, whose [`RowView::tie`] is
/// the path), in the order a folder would show them.
pub fn search_json<T: RowView>(
    q: String,
    mut hits: Vec<T>,
    more: bool,
    by: SortOrder,
) -> SearchJson {
    sort_rows(&mut hits, by.key, by.descending);
    let hits = hits
        .iter()
        .map(|hit| {
            EntryJson::new(
                hit.name(),
                Some(hit.tie().to_owned()),
                hit.is_dir(),
                hit.head(),
            )
        })
        .collect();
    SearchJson {
        q,
        sort: by.sort,
        order: by.order,
        hits,
        more,
    }
}

/// Names the way a file browser orders them: case-insensitively, with runs of digits compared
/// as numbers (`img2` before `img10`). Total and deterministic: names that are equal under
/// that are ordered by their bytes.
pub fn natural_cmp(a: &str, b: &str) -> Ordering {
    fn run(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) -> String {
        let mut digits = String::new();
        while let Some(c) = chars.peek().filter(|c| c.is_ascii_digit()) {
            digits.push(*c);
            chars.next();
        }
        digits
    }
    let (mut x, mut y) = (a.chars().peekable(), b.chars().peekable());
    loop {
        let ordering = match (x.peek().copied(), y.peek().copied()) {
            (None, None) => return a.cmp(b),
            (None, Some(_)) => Ordering::Less,
            (Some(_), None) => Ordering::Greater,
            (Some(c), Some(d)) if c.is_ascii_digit() && d.is_ascii_digit() => {
                let (m, n) = (run(&mut x), run(&mut y));
                let (m, n) = (m.trim_start_matches('0'), n.trim_start_matches('0'));
                m.len().cmp(&n.len()).then_with(|| m.cmp(n))
            }
            (Some(c), Some(d)) => {
                x.next();
                y.next();
                c.to_lowercase().cmp(d.to_lowercase())
            }
        };
        if ordering != Ordering::Equal {
            return ordering;
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Search
// ---------------------------------------------------------------------------------------------

/// A name as `search` compares it: NFC, lower case.
pub fn fold_name(s: &str) -> String {
    if s.is_ascii() {
        s.to_ascii_lowercase()
    } else {
        use unicode_normalization::UnicodeNormalization as _;
        s.nfc().collect::<String>().to_lowercase()
    }
}

/// Files and directories whose **name** — the last component of the path — contains `needle`,
/// compared without regard to case ([`fold_name`]): `(path, is a directory)` in the order
/// found, at most `limit` of them, and whether there are more.
///
/// `rows` are the winners of the tree as `(path, is a directory)`, **in path order** (byte
/// order). A directory is found whether it has a row of its own or exists only through what is
/// under it: every row's parent directories are looked at once, when the walk enters them. One
/// pass; it stops reading rows at the first match beyond `limit`. An empty needle or a `limit`
/// of 0 finds nothing and reads nothing. The first error of `rows` ends the search.
pub fn search_paths<P: AsRef<str>, E>(
    rows: impl IntoIterator<Item = Result<(P, bool), E>>,
    needle: &str,
    limit: usize,
) -> Result<(Vec<(String, bool)>, bool), E> {
    let needle = fold_name(needle);
    if needle.is_empty() || limit == 0 {
        return Ok((Vec::new(), false));
    }
    let mut found: Vec<(String, bool)> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    // The directory of the previous row: its components have been looked at.
    let mut parent = String::new();
    for row in rows {
        let (path, is_dir) = row?;
        let path = path.as_ref();
        let (dir, name) = match path.rfind('/') {
            Some(i) => (&path[..i], &path[i + 1..]),
            None => ("", path),
        };
        let mut hits: Vec<(&str, bool)> = Vec::new();
        if dir != parent {
            let ends = dir.match_indices('/').map(|(i, _)| i);
            for end in ends.chain([dir.len()]).filter(|end| *end > 0) {
                let above = &dir[..end];
                if fold_name(crate::path::file_name(above)).contains(&needle) {
                    hits.push((above, true));
                }
            }
            parent = dir.to_owned();
        }
        if fold_name(name).contains(&needle) {
            hits.push((path, is_dir));
        }
        for (hit, is_dir) in hits {
            if seen.contains(hit) {
                continue;
            }
            if found.len() == limit {
                return Ok((found, true));
            }
            seen.insert(hit.to_owned());
            found.push((hit.to_owned(), is_dir));
        }
    }
    Ok((found, false))
}

// ---------------------------------------------------------------------------------------------
// Range
// ---------------------------------------------------------------------------------------------

#[derive(Debug, PartialEq, Eq)]
pub enum ByteRange {
    /// No `Range`, one this server does not understand, or several ranges: the whole file
    /// (`200`) — RFC 9110 §14.2 lets a server ignore the header, and a `multipart/byteranges`
    /// answer is not worth having here.
    Whole,
    /// `206` with these bytes (never empty).
    Part(std::ops::Range<u64>),
    /// `416`: a well-formed range that selects nothing of the file.
    Unsatisfiable,
}

/// One `Range` header against a file of `size` bytes: `bytes=a-b`, `bytes=a-`, `bytes=-n`.
pub fn parse_range(header: Option<&str>, size: u64) -> ByteRange {
    let Some(spec) = header.and_then(|h| h.trim().strip_prefix("bytes=")) else {
        return ByteRange::Whole;
    };
    if spec.contains(',') {
        return ByteRange::Whole;
    }
    let Some((first, last)) = spec.trim().split_once('-') else {
        return ByteRange::Whole;
    };
    let number = |s: &str| {
        (!s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
            .then(|| s.parse::<u64>().unwrap_or(u64::MAX))
    };
    let range = match (first.is_empty(), number(first), number(last)) {
        // The last n bytes.
        (true, _, Some(n)) => size.saturating_sub(n)..size,
        (false, Some(a), None) if last.is_empty() => a..size,
        (false, Some(a), Some(b)) if a <= b => a..b.saturating_add(1).min(size),
        _ => return ByteRange::Whole,
    };
    if range.start < range.end {
        ByteRange::Part(range)
    } else {
        ByteRange::Unsatisfiable
    }
}

// ---------------------------------------------------------------------------------------------
// Content-Disposition
// ---------------------------------------------------------------------------------------------

/// A character that changes the direction of the text around it (the Unicode bidirectional
/// controls). In a file name it can make `invoice<U+202E>fdp.exe` read "invoiceexe.pdf".
pub fn is_bidi_control(c: char) -> bool {
    matches!(c, '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
}

/// What an answer says about showing or saving the file.
///
/// A file that is **shown** is a bare `inline`, without its name: a browser takes the file
/// name of an inline answer for the title of a tab that shows the file by itself (Chrome for
/// a PDF, Firefox for images, audio and video), and a title is written to the browser's
/// history — where no name of the vault may end up.
///
/// A **download** is `attachment` with the file's name in both forms of RFC 6266: `filename=`
/// as a quoted string of harmless ASCII for clients that know nothing else, and `filename*=`
/// with the real name in UTF-8, percent-encoded per RFC 5987 — quotes, non-ASCII characters
/// and control characters included, so nothing in a name can end or extend the header.
/// Bidirectional controls are `_` in both forms: the name a browser saves under must not
/// read differently from what it is.
pub fn content_disposition(inline: bool, name: &str) -> String {
    if inline {
        return "inline".to_owned();
    }
    let fallback: String = name
        .chars()
        .map(|c| match c {
            '"' | '\\' | '%' | '/' | ';' => '_',
            c if c.is_ascii_graphic() || c == ' ' => c,
            _ => '_',
        })
        .collect();
    let fallback = match fallback.trim() {
        "" => "download",
        trimmed => trimmed,
    };
    let mut out = format!("attachment; filename=\"{fallback}\"; filename*=UTF-8''");
    let mut utf8 = [0u8; 4];
    for c in name.chars() {
        if is_bidi_control(c) {
            out.push('_');
            continue;
        }
        for &b in c.encode_utf8(&mut utf8).as_bytes() {
            // attr-char of RFC 5987.
            if b.is_ascii_alphanumeric() || b"!#$&+-.^_`|~".contains(&b) {
                out.push(b as char);
            } else {
                out.push_str(&format!("%{b:02X}"));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::index::{ListRow, SearchHit};
    use crate::types::{DeviceId, Entry, Stamp};

    fn row(name: &str, is_dir: bool, size: u64, mtime_ns: i64) -> ListRow {
        let head = Head {
            path: name.to_owned(),
            stamp: Stamp {
                lamport: 1,
                device: DeviceId([1; 8]),
                idx: 0,
            },
            entry: Entry {
                kind: if is_dir {
                    EntryKind::Dir
                } else {
                    EntryKind::File
                },
                size,
                mtime_ns,
                exec: false,
                hash: [0; 32],
                loc: None,
            },
            origin: None,
            winner: true,
        };
        ListRow {
            name: name.to_owned(),
            is_dir,
            // A directory can come with a head (created empty) or without (implied).
            head: (!is_dir || size == 1).then_some(head),
        }
    }

    fn rows() -> Vec<ListRow> {
        vec![
            row("b.txt", false, 30, 100),
            row("zeta", true, 0, 0),
            row("a10.txt", false, 10, 300),
            row("Alpha", true, 1, 999),
            row("a2.txt", false, 30, 200),
            row("c.txt", false, 0, -5),
        ]
    }

    fn sorted(key: SortKey, descending: bool) -> Vec<String> {
        let mut rows = rows();
        sort_rows(&mut rows, key, descending);
        rows.into_iter().map(|r| r.name).collect()
    }

    #[test]
    fn listings_put_directories_first_in_every_order() {
        assert_eq!(
            sorted(SortKey::Name, false),
            ["Alpha", "zeta", "a2.txt", "a10.txt", "b.txt", "c.txt"]
        );
        assert_eq!(
            sorted(SortKey::Name, true),
            ["zeta", "Alpha", "c.txt", "b.txt", "a10.txt", "a2.txt"]
        );
        // Equal sizes by name; directories by name whatever the direction.
        assert_eq!(
            sorted(SortKey::Size, false),
            ["Alpha", "zeta", "c.txt", "a10.txt", "a2.txt", "b.txt"]
        );
        assert_eq!(
            sorted(SortKey::Size, true),
            ["Alpha", "zeta", "a2.txt", "b.txt", "a10.txt", "c.txt"]
        );
        assert_eq!(
            sorted(SortKey::Mtime, false),
            ["Alpha", "zeta", "c.txt", "b.txt", "a2.txt", "a10.txt"]
        );
        assert_eq!(
            sorted(SortKey::Mtime, true),
            ["Alpha", "zeta", "a10.txt", "a2.txt", "b.txt", "c.txt"]
        );
    }

    #[test]
    fn entries_of_directories_carry_no_size_or_time() {
        let dir = row("Alpha", true, 1, 999);
        let entry = EntryJson::new(&dir.name, None, true, dir.head.as_ref());
        assert_eq!(
            serde_json::to_string(&entry).unwrap(),
            r#"{"name":"Alpha","dir":true,"kind":"folder","size":null,"mtime_ms":null}"#
        );
        let file = row("old.PDF", false, 7, -1_500_000);
        let entry = EntryJson::new(
            &file.name,
            Some("x/old.PDF".into()),
            false,
            file.head.as_ref(),
        );
        assert_eq!(
            serde_json::to_string(&entry).unwrap(),
            r#"{"name":"old.PDF","path":"x/old.PDF","dir":false,"kind":"pdf","size":7,"mtime_ms":-2}"#
        );
    }

    fn hit(path: &str, is_dir: bool, size: u64) -> SearchHit {
        SearchHit {
            path: path.to_owned(),
            is_dir,
            head: (!is_dir).then(|| row(path, false, size, 0).head).flatten(),
        }
    }

    fn hits() -> Vec<SearchHit> {
        vec![
            hit("z/a10.txt", false, 5),
            hit("b/a2.txt", false, 5),
            hit("a/a2.txt", false, 9),
            hit("m/Docs", true, 0),
            hit("a2.txt", false, 1),
            hit("b/docs", true, 0),
        ]
    }

    #[test]
    fn search_matches_are_ordered_like_a_listing() {
        let sorted = |key: SortKey, descending: bool| {
            let mut hits = hits();
            sort_rows(&mut hits, key, descending);
            hits.into_iter().map(|h| h.path).collect::<Vec<_>>()
        };
        // By the name — the last component — and, where names are equal, by the path.
        assert_eq!(
            sorted(SortKey::Name, false),
            [
                "m/Docs",
                "b/docs",
                "a/a2.txt",
                "a2.txt",
                "b/a2.txt",
                "z/a10.txt"
            ]
        );
        assert_eq!(
            sorted(SortKey::Name, true),
            [
                "b/docs",
                "m/Docs",
                "z/a10.txt",
                "b/a2.txt",
                "a2.txt",
                "a/a2.txt"
            ]
        );
        assert_eq!(
            sorted(SortKey::Size, true),
            [
                "m/Docs",
                "b/docs",
                "a/a2.txt",
                "b/a2.txt",
                "z/a10.txt",
                "a2.txt"
            ]
        );
    }

    #[test]
    fn sort_and_order_have_defaults_and_are_closed_sets() {
        let by = SortOrder::parse(None, None).unwrap();
        assert_eq!(
            (by.key, by.sort, by.descending, by.order),
            (SortKey::Name, "name", false, "asc")
        );
        let by = SortOrder::parse(Some("size"), Some("desc")).unwrap();
        assert_eq!(
            (by.key, by.sort, by.descending, by.order),
            (SortKey::Size, "size", true, "desc")
        );
        assert_eq!(
            SortOrder::parse(Some("mtime"), Some("asc")).unwrap().key,
            SortKey::Mtime
        );
        for sort in ["", "Name", "date", "name "] {
            assert_eq!(
                SortOrder::parse(Some(sort), None),
                Err("sort is name, size or mtime"),
                "{sort:?}"
            );
        }
        for order in ["", "ASC", "down"] {
            assert_eq!(
                SortOrder::parse(None, Some(order)),
                Err("order is asc or desc"),
                "{order:?}"
            );
        }
    }

    #[test]
    fn a_listing_is_sorted_then_paged() {
        let by = SortOrder::parse(Some("size"), Some("desc")).unwrap();
        let page = list_json("docs".into(), rows(), by, 1, 3);
        assert_eq!(
            serde_json::to_string(&page).unwrap(),
            concat!(
                r#"{"path":"docs","sort":"size","order":"desc","total":6,"offset":1,"entries":["#,
                r#"{"name":"zeta","dir":true,"kind":"folder","size":null,"mtime_ms":null},"#,
                r#"{"name":"a2.txt","dir":false,"kind":"text","size":30,"mtime_ms":0},"#,
                r#"{"name":"b.txt","dir":false,"kind":"text","size":30,"mtime_ms":0}]}"#
            )
        );
        // Past the end: the total, and nothing else.
        let by = SortOrder::parse(None, None).unwrap();
        let page = list_json(String::new(), rows(), by, 6, LIST_PAGE);
        assert_eq!((page.total, page.offset, page.entries.len()), (6, 6, 0));
        let found = search_json("a2".into(), hits(), true, by);
        assert_eq!(
            serde_json::to_string(&found).unwrap(),
            concat!(
                r#"{"q":"a2","sort":"name","order":"asc","hits":["#,
                r#"{"name":"Docs","path":"m/Docs","dir":true,"kind":"folder","size":null,"mtime_ms":null},"#,
                r#"{"name":"docs","path":"b/docs","dir":true,"kind":"folder","size":null,"mtime_ms":null},"#,
                r#"{"name":"a2.txt","path":"a/a2.txt","dir":false,"kind":"text","size":9,"mtime_ms":0},"#,
                r#"{"name":"a2.txt","path":"a2.txt","dir":false,"kind":"text","size":1,"mtime_ms":0},"#,
                r#"{"name":"a2.txt","path":"b/a2.txt","dir":false,"kind":"text","size":5,"mtime_ms":0},"#,
                r#"{"name":"a10.txt","path":"z/a10.txt","dir":false,"kind":"text","size":5,"mtime_ms":0}],"#,
                r#""more":true}"#
            )
        );
    }

    #[test]
    fn the_info_answer_names_the_head_only_where_there_is_one() {
        let info = |head: Option<&str>| InfoJson {
            vault: "v".into(),
            backend: "dir",
            device: "d".into(),
            version: "1",
            read_only: true,
            files: 2,
            bytes: 3,
            last_change_ms: None,
            last_change_by: Some("laptop".into()),
            refresh: RefreshState {
                at_ms: 4,
                ok: true,
                applied: 0,
                note: None,
            },
            head: head.map(str::to_owned),
        };
        let local = concat!(
            r#"{"vault":"v","backend":"dir","device":"d","version":"1","read_only":true,"#,
            r#""files":2,"bytes":3,"last_change_ms":null,"last_change_by":"laptop","#,
            r#""refresh":{"at_ms":4,"ok":true,"applied":0,"note":null}"#
        );
        assert_eq!(
            serde_json::to_string(&info(None)).unwrap(),
            format!("{local}}}")
        );
        assert_eq!(
            serde_json::to_string(&info(Some("ABCD-EFGH"))).unwrap(),
            format!(r#"{local},"head":"ABCD-EFGH"}}"#)
        );
        let state: RefreshState =
            serde_json::from_str(r#"{"at_ms":4,"ok":false,"applied":2,"note":"offline"}"#).unwrap();
        assert_eq!(
            (state.at_ms, state.ok, state.applied, state.note.as_deref()),
            (4, false, 2, Some("offline"))
        );
    }

    #[test]
    fn paths_of_requests() {
        assert_eq!(dir_path(None), Ok(String::new()));
        assert_eq!(dir_path(Some("")), Ok(String::new()));
        assert_eq!(dir_path(Some("a/b")), Ok("a/b".to_owned()));
        assert_eq!(entry_path(Some("a/b")), Ok("a/b".to_owned()));
        assert_eq!(entry_path(None), Err("path is missing".to_owned()));
        assert_eq!(entry_path(Some("")), Err("path is missing".to_owned()));
        for bad in ["/a", "a//b", "a/../b", ".", "a\0b"] {
            let refused = dir_path(Some(bad)).unwrap_err();
            assert!(refused.starts_with("path: "), "{bad:?}: {refused}");
            assert_eq!(entry_path(Some(bad)), Err(refused));
        }
        assert_eq!(
            no_folder("a\"b"),
            r#"There is no folder "a\"b" in the vault."#
        );
        assert_eq!(
            no_file("x/y.txt"),
            r#"There is no file "x/y.txt" in the vault."#
        );
        assert_eq!(not_a_number("limit", 5000), "limit is a number up to 5000");
    }

    /// The search as both viewers run it: over `(path, is a directory)` in path order.
    fn search(rows: &[(&str, bool)], needle: &str, limit: usize) -> (Vec<(String, bool)>, bool) {
        let rows = rows
            .iter()
            .map(|(path, is_dir)| Ok::<_, std::convert::Infallible>((*path, *is_dir)));
        search_paths(rows, needle, limit).unwrap()
    }

    #[test]
    fn search_finds_names_not_paths() {
        // Path order is byte order: '-' and '.' sort before '/'.
        let tree = [
            ("docs-other", false),
            ("docs.txt", false),
            ("docs/a.txt", false),
            ("docs/sub/b.txt", false),
            ("empty-dir", true),
            ("top", false),
        ];
        let hit = |path: &str, is_dir: bool| (path.to_owned(), is_dir);
        // A directory without a row of its own is found through what is under it, once, when
        // the walk enters it.
        assert_eq!(
            search(&tree, "docs", 10),
            (
                vec![
                    hit("docs-other", false),
                    hit("docs.txt", false),
                    hit("docs", true)
                ],
                false
            )
        );
        assert_eq!(
            search(&tree, "TXT", 10).0,
            vec![
                hit("docs.txt", false),
                hit("docs/a.txt", false),
                hit("docs/sub/b.txt", false)
            ]
        );
        assert_eq!(
            search(&tree, "Sub", 10),
            (vec![hit("docs/sub", true)], false)
        );
        assert_eq!(
            search(&tree, "empty", 10),
            (vec![hit("empty-dir", true)], false)
        );
        // The cap: `more` only when a match was left out.
        assert_eq!(
            search(&tree, "o", 1),
            (vec![hit("docs-other", false)], true)
        );
        assert_eq!(search(&tree, "o", 4).0.len(), 4);
        assert!(!search(&tree, "o", 4).1);
        for nothing in ["", "zzz", "docs/a", "/"] {
            assert_eq!(
                search(&tree, nothing, 10),
                (Vec::new(), false),
                "{nothing:?}"
            );
        }
        assert_eq!(search(&tree, "docs", 0), (Vec::new(), false));
        // A file and a directory of one name (an unresolved conflict): one hit, the row's.
        let clash = [("a", false), ("a/b", false)];
        assert_eq!(search(&clash, "a", 10), (vec![hit("a", false)], false));
    }

    #[test]
    fn search_folds_case_and_normalization() {
        // "é" precomposed in the tree, decomposed in the needle, and the other way round.
        let tree = [
            ("Fotos \u{e9}t\u{e9}/IMG.JPG", false),
            ("cafe\u{301}.txt", false),
        ];
        let paths = |needle: &str| -> Vec<String> {
            search(&tree, needle, 10)
                .0
                .into_iter()
                .map(|h| h.0)
                .collect()
        };
        assert_eq!(paths("E\u{301}T"), ["Fotos \u{e9}t\u{e9}"]);
        assert_eq!(paths("caf\u{e9}"), ["cafe\u{301}.txt"]);
        assert_eq!(paths("img.jpg"), ["Fotos \u{e9}t\u{e9}/IMG.JPG"]);
        assert_eq!(fold_name("STRASSE.Txt"), "strasse.txt");
        assert_eq!(fold_name("\u{c4}"), "\u{e4}");
    }

    #[test]
    fn search_stops_at_the_first_error_and_reads_no_further_than_it_must() {
        let rows = vec![Ok(("a.txt", false)), Err("broken"), Ok(("b.txt", false))];
        assert_eq!(search_paths(rows, "txt", 10), Err("broken"));
        // Nothing is read for an empty needle, and nothing after the match beyond the cap.
        let read = std::cell::Cell::new(0);
        let counted = || {
            ["a.txt", "b.txt", "c.txt", "d.txt"]
                .into_iter()
                .map(|path| {
                    read.set(read.get() + 1);
                    Ok::<_, &str>((path, false))
                })
        };
        let found = search_paths(counted(), "", 10);
        assert_eq!((found, read.get()), (Ok((Vec::new(), false)), 0));
        let found = search_paths(counted(), "txt", 2).unwrap();
        assert_eq!((found.0.len(), found.1, read.get()), (2, true, 3));
    }

    #[test]
    fn ranges() {
        use ByteRange::*;
        for (header, size, expected) in [
            (None, 100, Whole),
            (Some("bytes=0-0"), 100, Part(0..1)),
            (Some("bytes=0-"), 100, Part(0..100)),
            (Some("bytes=10-19"), 100, Part(10..20)),
            (Some("bytes=99-"), 100, Part(99..100)),
            (Some("bytes=90-1000"), 100, Part(90..100)),
            (Some("bytes=-10"), 100, Part(90..100)),
            (Some("bytes=-1000"), 100, Part(0..100)),
            (Some(" bytes=5-5 "), 100, Part(5..6)),
            (Some("bytes=0-18446744073709551615"), 100, Part(0..100)),
            // Selects nothing.
            (Some("bytes=100-"), 100, Unsatisfiable),
            (Some("bytes=100-200"), 100, Unsatisfiable),
            (Some("bytes=-0"), 100, Unsatisfiable),
            (Some("bytes=0-"), 0, Unsatisfiable),
            (Some("bytes=-5"), 0, Unsatisfiable),
            (Some("bytes=99999999999999999999-"), 100, Unsatisfiable),
            // Not understood, or more than one range: the whole file.
            (Some("bytes=0-1,5-6"), 100, Whole),
            (Some("bytes=5-1"), 100, Whole),
            (Some("bytes=a-b"), 100, Whole),
            (Some("bytes=-"), 100, Whole),
            (Some("bytes=+1-2"), 100, Whole),
            (Some("bytes=1"), 100, Whole),
            (Some("items=0-1"), 100, Whole),
            (Some(""), 100, Whole),
        ] {
            assert_eq!(parse_range(header, size), expected, "{header:?} of {size}");
        }
    }

    #[test]
    fn content_disposition_survives_any_name() {
        assert_eq!(
            content_disposition(false, "report.pdf"),
            "attachment; filename=\"report.pdf\"; filename*=UTF-8''report.pdf"
        );
        assert_eq!(
            content_disposition(false, "my file (1).txt"),
            "attachment; filename=\"my file (1).txt\"; filename*=UTF-8''my%20file%20%281%29.txt"
        );
        // A file that is shown carries no name at all: a browser would make it a tab's title,
        // and with that an entry of its history.
        for name in [
            "my file (1).txt",
            "Steuererklärung 2025.pdf",
            "\"; filename=\"x",
            "",
        ] {
            assert_eq!(content_disposition(true, name), "inline", "{name:?}");
        }
        // Characters that turn the text around are not handed to the browser's "save as":
        // `invoice<RLO>fdp.exe` would be drawn as "invoiceexe.pdf".
        assert_eq!(
            content_disposition(false, "invoice\u{202e}fdp.exe"),
            "attachment; filename=\"invoice_fdp.exe\"; filename*=UTF-8''invoice_fdp.exe"
        );
        for c in [
            '\u{061c}', '\u{200e}', '\u{200f}', '\u{202a}', '\u{202b}', '\u{202c}', '\u{202d}',
            '\u{202e}', '\u{2066}', '\u{2067}', '\u{2068}', '\u{2069}',
        ] {
            assert!(is_bidi_control(c), "{c:?}");
            assert_eq!(
                content_disposition(false, &format!("a{c}b.txt")),
                "attachment; filename=\"a_b.txt\"; filename*=UTF-8''a_b.txt",
                "{c:?}"
            );
        }
        // Their neighbours in the tables are ordinary characters of a name.
        assert_eq!(
            content_disposition(false, "a\u{200d}b\u{2065}.txt"),
            "attachment; filename=\"a_b_.txt\"; filename*=UTF-8''a%E2%80%8Db%E2%81%A5.txt"
        );
        assert_eq!(
            content_disposition(false, "a\"b\\c;d.txt"),
            "attachment; filename=\"a_b_c_d.txt\"; filename*=UTF-8''a%22b%5Cc%3Bd.txt"
        );
        assert_eq!(
            content_disposition(false, "größe 🎉.txt"),
            "attachment; filename=\"gr__e _.txt\"; filename*=UTF-8''gr%C3%B6%C3%9Fe%20%F0%9F%8E%89.txt"
        );
        assert_eq!(
            content_disposition(false, "line\r\nbreak\t\u{7f}.txt"),
            "attachment; filename=\"line__break__.txt\"; filename*=UTF-8''line%0D%0Abreak%09%7F.txt"
        );
        assert_eq!(
            content_disposition(false, "100%.txt"),
            "attachment; filename=\"100_.txt\"; filename*=UTF-8''100%25.txt"
        );
        assert_eq!(
            content_disposition(false, "\n"),
            "attachment; filename=\"_\"; filename*=UTF-8''%0A"
        );
        assert_eq!(
            content_disposition(false, " "),
            "attachment; filename=\"download\"; filename*=UTF-8''%20"
        );
        // Whatever the name: one line of visible ASCII, and the quoted string stays closed.
        for name in [
            "\u{0}\u{1}\u{1f}",
            "\"; filename=\"evil.exe",
            "ä\u{202e}gpj.exe",
            "a/b",
        ] {
            let value = content_disposition(false, name);
            assert!(
                value.bytes().all(|b| b.is_ascii_graphic() || b == b' '),
                "{value:?}"
            );
            assert_eq!(value.matches('"').count(), 2, "{value:?}");
            assert!(hyper::header::HeaderValue::from_str(&value).is_ok());
        }
    }

    #[test]
    fn names_are_ordered_like_a_file_browser() {
        let mut names = vec![
            "img10.png",
            "Img2.png",
            "img1.png",
            "b",
            "A",
            "a",
            "img02.png",
            "Zebra",
            "ähnlich",
            "10",
            "9",
            "",
        ];
        names.sort_by(|a, b| natural_cmp(a, b));
        assert_eq!(
            names,
            [
                "",
                "9",
                "10",
                "A",
                "a",
                "b",
                "img1.png",
                "Img2.png",
                "img02.png",
                "img10.png",
                "Zebra",
                "ähnlich"
            ]
        );
        assert_eq!(natural_cmp("a", "a"), Ordering::Equal);
        assert_eq!(natural_cmp("a1", "a01"), "a1".cmp("a01"));
        assert_eq!(natural_cmp("file", "file2"), Ordering::Less);
        // Digit runs longer than any integer type.
        assert_eq!(
            natural_cmp(&"9".repeat(40), &format!("1{}", "0".repeat(40))),
            Ordering::Less
        );
    }
}
