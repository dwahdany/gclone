//! What a vault file is served as (SPEC §7.4). The type comes from the file name's extension
//! through the table below and from nothing else: content is never sniffed, and the answer
//! carries `X-Content-Type-Options: nosniff` so that the browser does not sniff either.
//!
//! Files in the vault are untrusted content. Nothing that a browser would run as a document
//! with script — HTML, XHTML, XML, JavaScript — is ever served under its real type: all of it
//! is `text/plain`. SVG keeps `image/svg+xml` (an `<img>` needs it, and scripts do not run
//! there); opened directly it is held by the `sandbox` policy of [`Served::csp`].

/// How the viewer shows a file; also picks its icon.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Kind {
    Image,
    Pdf,
    Audio,
    Video,
    Text,
    /// Icon only: no preview.
    Archive,
    /// No preview.
    Other,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Image => "image",
            Kind::Pdf => "pdf",
            Kind::Audio => "audio",
            Kind::Video => "video",
            Kind::Text => "text",
            Kind::Archive => "archive",
            Kind::Other => "file",
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Served {
    pub kind: Kind,
    /// The `Content-Type` value.
    pub mime: &'static str,
}

const TEXT: &str = "text/plain; charset=utf-8";
const BINARY: &str = "application/octet-stream";

/// Extension (lower case, without the dot) → type. Text formats are listed without a type:
/// they are all served as `text/plain`.
const TYPES: &[(Kind, &str, &[&str])] = &[
    (Kind::Image, "image/png", &["png"]),
    (Kind::Image, "image/jpeg", &["jpg", "jpeg", "jpe", "jfif"]),
    (Kind::Image, "image/gif", &["gif"]),
    (Kind::Image, "image/webp", &["webp"]),
    (Kind::Image, "image/avif", &["avif"]),
    (Kind::Image, "image/bmp", &["bmp"]),
    (Kind::Image, "image/x-icon", &["ico"]),
    (Kind::Image, "image/svg+xml", &["svg"]),
    (Kind::Image, "image/heic", &["heic"]),
    (Kind::Image, "image/heif", &["heif"]),
    (Kind::Image, "image/tiff", &["tif", "tiff"]),
    (Kind::Pdf, "application/pdf", &["pdf"]),
    (Kind::Audio, "audio/mpeg", &["mp3"]),
    (Kind::Audio, "audio/mp4", &["m4a", "m4b"]),
    (Kind::Audio, "audio/aac", &["aac"]),
    (Kind::Audio, "audio/wav", &["wav"]),
    (Kind::Audio, "audio/flac", &["flac"]),
    (Kind::Audio, "audio/ogg", &["ogg", "oga", "opus"]),
    (Kind::Audio, "audio/webm", &["weba"]),
    (Kind::Video, "video/mp4", &["mp4", "m4v"]),
    (Kind::Video, "video/quicktime", &["mov"]),
    (Kind::Video, "video/webm", &["webm"]),
    (Kind::Video, "video/x-matroska", &["mkv"]),
    (Kind::Video, "video/ogg", &["ogv"]),
    (Kind::Video, "video/x-msvideo", &["avi"]),
    (Kind::Video, "video/mp2t", &["mts", "m2ts"]),
    (
        Kind::Text,
        TEXT,
        &[
            "txt",
            "text",
            "md",
            "markdown",
            "rst",
            "adoc",
            "org",
            "log",
            "csv",
            "tsv",
            "json",
            "jsonl",
            "ndjson",
            "geojson",
            "yaml",
            "yml",
            "toml",
            "ini",
            "cfg",
            "conf",
            "env",
            "properties",
            "xml",
            "xsl",
            "xsd",
            "plist",
            "html",
            "htm",
            "xhtml",
            "xht",
            "shtml",
            "css",
            "scss",
            "less",
            "js",
            "mjs",
            "cjs",
            "jsx",
            "ts",
            "tsx",
            "vue",
            "svelte",
            "rs",
            "py",
            "pyi",
            "go",
            "c",
            "h",
            "cc",
            "cpp",
            "cxx",
            "hpp",
            "hh",
            "m",
            "mm",
            "java",
            "kt",
            "kts",
            "scala",
            "swift",
            "rb",
            "php",
            "pl",
            "pm",
            "lua",
            "r",
            "jl",
            "hs",
            "ml",
            "ex",
            "exs",
            "erl",
            "clj",
            "dart",
            "cs",
            "fs",
            "vb",
            "sh",
            "bash",
            "zsh",
            "fish",
            "ps1",
            "bat",
            "cmd",
            "sql",
            "graphql",
            "proto",
            "nix",
            "tf",
            "cmake",
            "mk",
            "gradle",
            "tex",
            "bib",
            "sty",
            "srt",
            "vtt",
            "ass",
            "diff",
            "patch",
            "lock",
            "gitignore",
            "gitattributes",
            "editorconfig",
            "dockerfile",
            "asc",
            "pem",
            "crt",
            "pub",
            "ics",
            "vcf",
            "eml",
        ],
    ),
    (
        Kind::Archive,
        BINARY,
        &[
            "zip", "tar", "gz", "tgz", "bz2", "tbz", "xz", "txz", "zst", "7z", "rar", "lz", "lz4",
            "cab", "dmg", "iso", "img", "jar", "war", "apk", "deb", "rpm", "pkg",
        ],
    ),
];

/// Files without an extension that are text by convention (compared in lower case).
const TEXT_NAMES: &[&str] = &[
    "readme",
    "license",
    "licence",
    "copying",
    "authors",
    "changelog",
    "changes",
    "news",
    "notice",
    "todo",
    "makefile",
    "dockerfile",
    "gemfile",
    "rakefile",
    "procfile",
    "justfile",
    "vagrantfile",
];

/// The type a file of this name is served as.
pub fn of_name(name: &str) -> Served {
    let lower = name.to_ascii_lowercase();
    // `.bashrc` has no extension; `b.tar.gz` has `gz`.
    let ext = match lower.rfind('.') {
        Some(i) if i > 0 => &lower[i + 1..],
        Some(_) => lower.trim_start_matches('.'),
        None if TEXT_NAMES.contains(&lower.as_str()) => "txt",
        None => "",
    };
    TYPES
        .iter()
        .find(|(_, _, exts)| exts.contains(&ext))
        .map(|&(kind, mime, _)| Served { kind, mime })
        .unwrap_or(Served {
            kind: Kind::Other,
            mime: BINARY,
        })
}

impl Served {
    /// The small allowlist of what may be shown in the browser instead of being downloaded:
    /// images, PDF, audio, video and `text/plain`. Everything else is an attachment.
    pub fn inline(self) -> bool {
        !matches!(self.kind, Kind::Archive | Kind::Other)
    }

    /// The `Content-Security-Policy` of a response that carries vault bytes. Every type gets
    /// `default-src 'none'`, so a document made from the bytes can load nothing and run
    /// nothing; and `sandbox`, which puts such a document into an opaque origin without
    /// script — except PDF, which browsers refuse to show in a sandboxed frame (their viewer
    /// is a plugin). A PDF is not a document of the viewer's origin either way: its type is
    /// fixed and never sniffed. What is allowed back in is what the browser's own image, media
    /// and text documents need to show the one resource they were made for.
    pub fn csp(self) -> &'static str {
        match self.kind {
            Kind::Pdf => "default-src 'none'; frame-ancestors 'self'",
            Kind::Image => {
                "sandbox; default-src 'none'; img-src 'self'; style-src 'unsafe-inline'; \
                 frame-ancestors 'none'"
            }
            Kind::Audio | Kind::Video => {
                "sandbox; default-src 'none'; media-src 'self'; style-src 'unsafe-inline'; \
                 frame-ancestors 'none'"
            }
            Kind::Text => {
                "sandbox; default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'"
            }
            Kind::Archive | Kind::Other => "sandbox; default-src 'none'; frame-ancestors 'none'",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn types_come_from_the_extension() {
        for (name, kind, mime) in [
            ("a.png", Kind::Image, "image/png"),
            ("A.JPG", Kind::Image, "image/jpeg"),
            ("logo.svg", Kind::Image, "image/svg+xml"),
            ("paper.pdf", Kind::Pdf, "application/pdf"),
            ("song.mp3", Kind::Audio, "audio/mpeg"),
            ("clip.MP4", Kind::Video, "video/mp4"),
            ("clip.mov", Kind::Video, "video/quicktime"),
            ("notes.txt", Kind::Text, TEXT),
            ("README.md", Kind::Text, TEXT),
            ("data.json", Kind::Text, TEXT),
            ("table.csv", Kind::Text, TEXT),
            ("main.rs", Kind::Text, TEXT),
            ("Makefile", Kind::Text, TEXT),
            ("LICENSE", Kind::Text, TEXT),
            (".gitignore", Kind::Text, TEXT),
            ("b.tar.gz", Kind::Archive, BINARY),
            ("setup.exe", Kind::Other, BINARY),
            ("noext", Kind::Other, BINARY),
            ("trailing.", Kind::Other, BINARY),
            (".", Kind::Other, BINARY),
            ("", Kind::Other, BINARY),
            ("weird.png.exe", Kind::Other, BINARY),
            ("ünï.pdf", Kind::Pdf, "application/pdf"),
        ] {
            assert_eq!(of_name(name), Served { kind, mime }, "{name}");
        }
    }

    /// Nothing a browser runs as a document of the viewer's origin has its real type.
    #[test]
    fn active_content_is_plain_text() {
        for name in [
            "page.html",
            "page.HTM",
            "page.xhtml",
            "page.shtml",
            "feed.xml",
            "sheet.xsl",
            "app.js",
            "mod.mjs",
            "style.css",
            "comp.vue",
        ] {
            let served = of_name(name);
            assert_eq!(served.mime, TEXT, "{name}");
            assert!(served.csp().starts_with("sandbox;"), "{name}");
        }
        // No entry of the table is an HTML, XML or script type — SVG is the one XML format
        // with its own type, and it is sandboxed.
        for (kind, mime, _) in TYPES {
            for active in ["html", "xml", "javascript", "ecmascript"] {
                assert!(
                    !mime.contains(active) || *mime == "image/svg+xml",
                    "{mime} is served as itself"
                );
            }
            let served = Served { kind: *kind, mime };
            assert!(served.csp().contains("default-src 'none'"));
            assert_eq!(
                served.csp().starts_with("sandbox;"),
                *kind != Kind::Pdf,
                "{mime}"
            );
        }
        assert!(of_name("x.svg").csp().starts_with("sandbox;"));
    }

    #[test]
    fn only_the_allowlist_is_shown_inline() {
        for (name, inline) in [
            ("a.png", true),
            ("a.svg", true),
            ("a.pdf", true),
            ("a.mp3", true),
            ("a.mp4", true),
            ("a.txt", true),
            ("a.html", true), // as text/plain
            ("a.zip", false),
            ("a.exe", false),
            ("a.docx", false),
            ("a", false),
        ] {
            assert_eq!(of_name(name).inline(), inline, "{name}");
        }
    }

    #[test]
    fn no_extension_is_listed_twice() {
        let mut seen = std::collections::BTreeSet::new();
        for (_, _, exts) in TYPES {
            for ext in *exts {
                assert!(seen.insert(*ext), "{ext} is listed twice");
                assert_eq!(*ext, ext.to_ascii_lowercase());
            }
        }
    }
}
