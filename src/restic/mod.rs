//! `gclone serve restic` (SPEC §7.6): restic's REST backend protocol in front of Google Drive.
//!
//! restic keeps a repository — its own encrypted, content-addressed files — and gclone
//! contributes the sign-in and the Drive client. The vault is not involved: the files live in
//! their own tree (`gclone-restic/<repo>/…`, §3.4), need no passphrase of gclone, and no local
//! state. `proto` is the wire grammar, `layout` finds and creates the folder tree, `store` is
//! the repository (the ID cache, listings, uploads, deletes and what makes them consistent),
//! `http` turns hyper requests into store calls, `stdio` is the transport restic starts itself.

use std::collections::HashMap;
use std::io::Write as _;
use std::sync::Mutex;
use std::time::Duration;

use crate::consts;
use crate::error::{BackendError, QuotaKind};
use crate::util;

pub mod http;
pub mod layout;
pub mod proto;
pub mod stdio;
pub mod store;

pub use http::App;
pub use store::{Opened, Repo};

/// The top-level Drive folder that holds every restic repository of the account.
pub const ROOT_NAME: &str = "gclone-restic";
/// Folders `00` … `ff` under `data/`, all created by `restic init`.
pub const SHARDS: usize = 256;
/// Bodies up to this are buffered and sent to Drive in one replayable request.
pub const SMALL_MAX: u64 = consts::MULTIPART_MAX;
/// How long an acknowledgement waits for the listing that confirms it.
pub const LIST_CONFIRM_WAIT: Duration = Duration::from_secs(30);
/// Pause between confirming listings: this, doubling, capped at [`LIST_CONFIRM_POLL_MAX`]. The
/// first listing is immediate.
pub const LIST_CONFIRM_POLL: Duration = Duration::from_millis(250);
pub const LIST_CONFIRM_POLL_MAX: Duration = Duration::from_secs(2);
/// How long a listing that omits this process's own upload is taken for list lag.
pub const OWN_GRACE: Duration = consts::GAP_GRACE;
/// How long after this process trashed a file a listing that still shows it is taken for list
/// lag without a question. After that Drive is asked whether the file is in the trash: someone
/// may have restored it.
pub const HIDDEN_RECHECK: Duration = LIST_CONFIRM_WAIT;
/// How long a refused `POST config` is remembered for the `DELETE config` restic sends next.
pub const CONFIG_REFUSAL: Duration = Duration::from_secs(60);
/// Shard listings in flight for one `GET data/` or one pack confirmation.
pub const LIST_FANOUT: usize = 8;
/// Folder creations in flight during `init`.
pub const CREATE_FANOUT: usize = 8;
/// Advertised `SETTINGS_MAX_CONCURRENT_STREAMS`: restic has one connection and cannot open a
/// second, which is what Go's client does when it runs out of streams.
pub const H2_MAX_STREAMS: u32 = 1024;
/// HTTP/2 receive windows. The connection's is far larger than a stream's: an upload that
/// waits for Drive holds its stream's window, and must not hold up every other stream.
pub const H2_STREAM_WINDOW: u32 = 1024 * 1024;
pub const H2_CONN_WINDOW: u32 = 64 * 1024 * 1024;
/// Open connections in `--port` mode.
pub const LISTENER_CONNECTIONS: usize = 64;
/// How long the process stays, after its connection ended, for uploads nobody waits for any
/// more to take back what they stored.
pub const EXIT_GRACE: Duration = Duration::from_secs(10);
/// An identical stderr line is not repeated within this time.
pub const NOTE_REPEAT: Duration = Duration::from_secs(60);

/// The name of a repository: one path segment, `^[a-z0-9][a-z0-9._-]{0,62}$`. Lowercase only,
/// so that two repositories cannot differ by case alone (Drive compares names without it).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RepoName(String);

pub const REPO_NAME_RULE: &str = "a repository name is 1 to 63 characters of a-z, 0-9, '.', '_' \
    and '-', starting with a letter or digit (restic: -r rclone:NAME)";

impl RepoName {
    pub fn parse(s: &str) -> Result<RepoName, String> {
        let b = s.as_bytes();
        let plain = |c: &u8| c.is_ascii_lowercase() || c.is_ascii_digit();
        let ok = (1..=63).contains(&b.len())
            && plain(&b[0])
            && b.iter()
                .all(|c| plain(c) || matches!(c, b'.' | b'_' | b'-'));
        match ok {
            true => Ok(RepoName(s.to_string())),
            false => Err(REPO_NAME_RULE.to_string()),
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::str::FromStr for RepoName {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        RepoName::parse(s)
    }
}

impl std::fmt::Display for RepoName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// restic's five kinds of content-addressed files.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum FileType {
    Data,
    Keys,
    Locks,
    Snapshots,
    Index,
}

impl FileType {
    pub const ALL: [FileType; 5] = [
        FileType::Data,
        FileType::Keys,
        FileType::Locks,
        FileType::Snapshots,
        FileType::Index,
    ];

    /// The folder's name, on Drive and in the URL.
    pub fn dir(self) -> &'static str {
        match self {
            FileType::Data => "data",
            FileType::Keys => "keys",
            FileType::Locks => "locks",
            FileType::Snapshots => "snapshots",
            FileType::Index => "index",
        }
    }

    pub fn parse(s: &str) -> Option<FileType> {
        FileType::ALL.into_iter().find(|t| t.dir() == s)
    }
}

/// A file name: the SHA-256 of the file's bytes, 64 lowercase hex digits on the wire.
#[derive(Copy, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Name(pub [u8; 32]);

impl Name {
    pub fn parse(s: &str) -> Option<Name> {
        let raw = (s.len() == 64).then(|| util::unhex(s)).flatten()?;
        Some(Name(raw.try_into().ok()?))
    }

    pub fn hex(&self) -> String {
        util::hex(&self.0)
    }

    /// The folder under `data/` a pack of this name lives in.
    pub fn shard(&self) -> u8 {
        self.0[0]
    }
}

impl std::fmt::Debug for Name {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.hex())
    }
}

/// One file of a repository.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum Target {
    /// restic's `config`: the only file that is not named by its content.
    Config,
    File(FileType, Name),
}

impl Target {
    /// The file's name on Drive.
    pub fn file_name(&self) -> String {
        match self {
            Target::Config => "config".to_string(),
            Target::File(_, name) => name.hex(),
        }
    }

    /// `locks/<hex>`, `config`: for messages.
    pub fn shown(&self) -> String {
        match self {
            Target::Config => "config".to_string(),
            Target::File(ty, name) => format!("{}/{}", ty.dir(), name.hex()),
        }
    }
}

#[derive(Copy, Clone, Debug, Default)]
pub struct Options {
    /// Refuse every delete except `locks/<name>` (a guard against mistakes, not a security
    /// boundary: the device's login can trash the same files directly).
    pub append_only: bool,
    /// `--port`: the process serves one restic run after another, and what it remembers about
    /// the packs of a run ends with the run (`store`: `forget_ended_runs`). Set by `App::listener`.
    pub listener: bool,
}

/// Why a request cannot be answered with what it asked for (`proto::status` has the statuses).
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// No repository of that name on Drive. `404` — except for a listing, where it is `403`:
    /// restic reads a `404` there as "empty".
    #[error("there is no repository of that name on Drive (run restic init)")]
    NoRepo,
    #[error("no such file")]
    NotFound,
    /// A file of that name with other content is there already.
    #[error("the file exists already")]
    Exists,
    #[error("--append-only: nothing but locks can be deleted")]
    Forbidden,
    /// `DELETE config` right after a `POST config` that was refused: the config is another
    /// client's.
    #[error("the config was written by another restic init and is kept")]
    ConfigKept,
    /// The body is not what the request says it is.
    #[error("bad upload: {0}")]
    BadUpload(&'static str),
    #[error("a Content-Length is required")]
    LengthRequired,
    /// The folder tree is incomplete, ambiguous or in the trash: nothing a retry can clear.
    #[error("{0}")]
    Layout(String),
    /// A listing that would confirm the request did not arrive in time.
    #[error("{0}")]
    Unconfirmed(String),
    /// Drive stored something other than what was sent (the object is trashed again).
    #[error("{0}")]
    Integrity(String),
    #[error(transparent)]
    Backend(#[from] BackendError),
}

/// What a request asked for, as far as the stderr line of its failure depends on it.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Asked {
    /// `GET <type>/`: "no such repository" is an error there, not restic's question.
    Listing,
    /// `POST locks/<name>`: the first upload of nearly every restic command.
    Lock,
    Other,
}

impl Error {
    /// The line for stderr, or `None` for an answer that needs none (`2xx`, `400`, `404`,
    /// `416`, and the refusals that are the client's own doing).
    pub fn note(&self, what: &str, asked: Asked) -> Option<String> {
        match self {
            Error::NoRepo if asked != Asked::Listing => None,
            Error::NotFound
            | Error::Exists
            | Error::Forbidden
            | Error::ConfigKept
            | Error::BadUpload(_)
            | Error::LengthRequired => None,
            Error::Backend(BackendError::QuotaExceeded(QuotaKind::DailyUpload)) => Some(
                "Google's daily upload limit is reached; uploads work again within 24 hours. \
                 Read-only restic commands work now with --no-lock"
                    .to_string(),
            ),
            // At the daily upload limit this is the first line restic shows, minutes before
            // the write breaker names the limit: restic keeps trying for a quarter of an hour.
            Error::Backend(BackendError::RateLimited) if asked == Asked::Lock => Some(format!(
                "{what}: {self}. If this goes on, Google's daily upload limit may be reached \
                 (uploads work again within 24 hours); read-only restic commands work now with \
                 --no-lock"
            )),
            _ => Some(format!("{what}: {self}")),
        }
    }
}

/// One line for the user on stderr (restic shows it prefixed `rclone: `). Write errors are
/// ignored — stderr closes when restic exits first — and an identical line is not repeated
/// within [`NOTE_REPEAT`].
pub fn note(line: &str) {
    static SEEN: Mutex<Option<HashMap<String, std::time::Instant>>> = Mutex::new(None);
    {
        let mut seen = SEEN.lock().unwrap_or_else(|e| e.into_inner());
        let seen = seen.get_or_insert_with(HashMap::new);
        let now = std::time::Instant::now();
        seen.retain(|_, at| now.duration_since(*at) < NOTE_REPEAT);
        if seen.insert(line.to_string(), now).is_some() {
            return;
        }
    }
    let _ = writeln!(std::io::stderr().lock(), "gclone: {line}");
}

#[cfg(test)]
mod tests {
    use super::*;

    /// U5.
    #[test]
    fn repository_names() {
        let longest = "a".repeat(63);
        for ok in [
            "a",
            "0",
            "main",
            "my-laptop.2026",
            "a_b",
            "9lives",
            &longest,
        ] {
            assert_eq!(RepoName::parse(ok).unwrap().as_str(), ok);
        }
        let too_long = "a".repeat(64);
        for bad in [
            "", ".", "..", ".a", "-a", "_a", "Main", "a/b", "a:b", "a b", "ä", "a\n", "a%2e",
            &too_long,
        ] {
            assert_eq!(RepoName::parse(bad).unwrap_err(), REPO_NAME_RULE, "{bad:?}");
        }
    }

    #[test]
    fn names_and_types() {
        let hex = "0f".repeat(32);
        let name = Name::parse(&hex).unwrap();
        assert_eq!(name.hex(), hex);
        assert_eq!(name.shard(), 0x0f);
        for bad in [
            "",
            &hex[1..],
            &format!("{hex}0"),
            &hex.to_uppercase(),
            &"g".repeat(64),
        ] {
            assert!(Name::parse(bad).is_none(), "{bad:?}");
        }
        for ty in FileType::ALL {
            assert_eq!(FileType::parse(ty.dir()), Some(ty));
        }
        assert_eq!(FileType::parse("Data"), None);
        assert_eq!(FileType::parse("config"), None);
        assert_eq!(Target::Config.shown(), "config");
        assert_eq!(
            Target::File(FileType::Locks, name).shown(),
            format!("locks/{hex}")
        );
    }

    #[test]
    fn which_errors_get_a_line_on_stderr() {
        for quiet in [
            Error::NotFound,
            Error::Exists,
            Error::Forbidden,
            Error::ConfigKept,
            Error::BadUpload("x"),
            Error::LengthRequired,
        ] {
            assert!(quiet.note("GET locks", Asked::Other).is_none(), "{quiet:?}");
        }
        let line = Error::Layout("two folders named locks".into())
            .note("GET locks", Asked::Listing)
            .unwrap();
        assert_eq!(line, "GET locks: two folders named locks");
        // `HEAD config` on a name that is not there is how `restic init` begins: no line.
        assert!(Error::NoRepo.note("HEAD config", Asked::Other).is_none());
        assert!(Error::NoRepo.note("POST locks", Asked::Lock).is_none());
        assert!(Error::NoRepo.note("GET keys/", Asked::Listing).is_some());
        let daily = Error::Backend(BackendError::QuotaExceeded(QuotaKind::DailyUpload))
            .note("POST locks", Asked::Lock)
            .unwrap();
        assert!(daily.starts_with("Google's daily upload limit is reached"));
        assert!(daily.ends_with("--no-lock"));

        // At the daily limit the lock upload is throttled for minutes before the breaker
        // names the limit: the first line a user sees already says what to do.
        let throttled = || Error::Backend(BackendError::RateLimited);
        let first = throttled().note("POST laptop:locks", Asked::Lock).unwrap();
        assert!(first.starts_with("POST laptop:locks: "), "{first}");
        assert!(
            first.contains("daily upload limit may be reached") && first.ends_with("--no-lock"),
            "{first}"
        );
        for asked in [Asked::Other, Asked::Listing] {
            let plain = throttled().note("POST laptop:data", asked).unwrap();
            assert!(!plain.contains("--no-lock"), "{plain}");
        }
    }
}
