//! Terminal output (SPEC §9.3): result lines, warnings, NDJSON events, prompts and transfer
//! progress. Implemented completely by WP0 so that the transfer and sync packages can be
//! tested before the CLI exists.
//!
//! Streams: human **results** (`out`, plan/skip lines) and NDJSON events go to stdout;
//! everything else (info, warnings, errors, prompts, progress bars, logs) goes to stderr.
//!
//! The prompt methods (`confirm`, `choose`, `prompt_line`, `prompt_secret`) block on the
//! terminal: call them from `spawn_blocking` (or before the transfer phase), never from a task
//! that other work is waiting on.

use indicatif::{MultiProgress, ProgressBar, ProgressDrawTarget, ProgressStyle};
use std::io::{self, BufRead as _, IsTerminal as _, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use crate::util;

#[derive(Clone, Debug, Default)]
pub struct UiOpts {
    pub json: bool,
    pub quiet: bool,
    pub verbose: u8,
}

/// One `--json` event (one JSON object per line on stdout, §7.3).
#[derive(Clone, Debug, serde::Serialize)]
#[serde(tag = "event", rename_all = "lowercase")]
pub enum Event {
    Plan {
        action: String,
        path: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        size: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        note: Option<String>,
    },
    Done {
        action: String,
        path: String,
        bytes: u64,
    },
    Skip {
        path: String,
        reason: String,
    },
    Warn {
        message: String,
    },
    Summary {
        uploaded: u64,
        downloaded: u64,
        reused: u64,
        deleted: u64,
        skipped: u64,
        failed: u64,
        conflicts: u64,
        bytes_up: u64,
        bytes_down: u64,
        exit: i32,
    },
}

type Sink = Mutex<Box<dyn Write + Send>>;

/// The user interface of one command. `Send + Sync`; share it by reference.
pub struct Ui {
    opts: UiOpts,
    /// `silent()`: no output at all, no prompts.
    silent: bool,
    /// stdin and stderr are terminals (prompts are possible).
    tty: bool,
    mp: MultiProgress,
    out: Sink,
    err: Sink,
}

impl Ui {
    /// The real thing: stdout / stderr, progress bars on stderr when it is a terminal and
    /// neither `--json` nor `--quiet` is set.
    pub fn new(opts: UiOpts) -> Self {
        let tty = io::stdin().is_terminal() && io::stderr().is_terminal();
        let draw = if opts.json || opts.quiet {
            ProgressDrawTarget::hidden()
        } else {
            ProgressDrawTarget::stderr()
        };
        Ui {
            opts,
            silent: false,
            tty,
            mp: MultiProgress::with_draw_target(draw),
            out: Mutex::new(Box::new(io::stdout())),
            err: Mutex::new(Box::new(io::stderr())),
        }
    }

    /// No output, `confirm()` = false, `choose()` = None, prompts fail — for tests and library
    /// callers.
    pub fn silent() -> Self {
        Ui {
            opts: UiOpts {
                json: false,
                quiet: true,
                verbose: 0,
            },
            silent: true,
            tty: false,
            mp: MultiProgress::with_draw_target(ProgressDrawTarget::hidden()),
            out: Mutex::new(Box::new(io::sink())),
            err: Mutex::new(Box::new(io::sink())),
        }
    }

    /// Like [`Ui::new`] but writing "stdout" and "stderr" into the given sinks; never a TTY and
    /// never drawing progress bars. For tests that assert on output.
    #[doc(hidden)]
    pub fn with_writers(
        opts: UiOpts,
        out: Box<dyn Write + Send>,
        err: Box<dyn Write + Send>,
    ) -> Self {
        Ui {
            opts,
            silent: false,
            tty: false,
            mp: MultiProgress::with_draw_target(ProgressDrawTarget::hidden()),
            out: Mutex::new(out),
            err: Mutex::new(err),
        }
    }

    /// Prompts are possible (stdin and stderr are terminals).
    pub fn is_tty(&self) -> bool {
        self.tty
    }

    pub fn json(&self) -> bool {
        self.opts.json
    }

    pub fn quiet(&self) -> bool {
        self.opts.quiet
    }

    pub fn verbose(&self) -> u8 {
        self.opts.verbose
    }

    fn write(&self, sink: &Sink, line: &str) {
        self.mp.suspend(|| {
            let mut w = sink.lock().unwrap_or_else(|e| e.into_inner());
            // A closed pipe (`gclone ls | head`) must not turn into a panic or an error.
            let _ = writeln!(w, "{line}");
            let _ = w.flush();
        });
    }

    /// Human result line → stdout (suppressed in `--json`).
    pub fn out(&self, line: &str) {
        if self.silent || self.opts.json {
            return;
        }
        self.write(&self.out, line);
    }

    /// Progress note → stderr unless `-q`.
    pub fn info(&self, line: &str) {
        if self.silent || self.opts.quiet {
            return;
        }
        self.write(&self.err, line);
    }

    /// `warning: …` on stderr; in `--json` mode a `warn` event on stdout instead.
    pub fn warn(&self, line: &str) {
        if self.silent {
            return;
        }
        if self.opts.json {
            self.emit_json(&Event::Warn {
                message: line.to_string(),
            });
        } else {
            self.write(&self.err, &format!("warning: {line}"));
        }
    }

    /// `error: …` on stderr (in every mode: stdout stays clean NDJSON under `--json`).
    pub fn error(&self, line: &str) {
        if self.silent {
            return;
        }
        self.write(&self.err, &format!("error: {line}"));
    }

    fn emit_json(&self, e: &Event) {
        if let Ok(line) = serde_json::to_string(e) {
            self.write(&self.out, &line);
        }
    }

    /// `--json`: one NDJSON object on stdout. Otherwise rendered like the examples of §7.3:
    /// `Plan` and `Skip` as aligned lines on stdout (not with `-q`), `Done` on stderr with `-v`,
    /// `Warn` like [`Ui::warn`]. `Summary` has no human rendering — the command prints its own
    /// result line with [`Ui::out`].
    pub fn event(&self, e: &Event) {
        if self.silent {
            return;
        }
        if self.opts.json {
            self.emit_json(e);
            return;
        }
        match e {
            Event::Plan {
                action,
                path,
                size,
                note,
            } => {
                if self.opts.quiet {
                    return;
                }
                let detail = match (size, note) {
                    (Some(s), Some(n)) => format!("{}  {n}", util::human_size(*s)),
                    (Some(s), None) => util::human_size(*s),
                    (None, Some(n)) => n.clone(),
                    (None, None) => String::new(),
                };
                self.write(&self.out, &plan_line(sigil(action), action, path, &detail));
            }
            Event::Skip { path, reason } => {
                if self.opts.quiet {
                    return;
                }
                self.write(&self.out, &plan_line('!', "skip", path, reason));
            }
            Event::Done {
                action,
                path,
                bytes,
            } => {
                if self.opts.quiet || self.opts.verbose == 0 {
                    return;
                }
                let detail = if *bytes > 0 {
                    util::human_size(*bytes)
                } else {
                    String::new()
                };
                self.write(&self.err, &plan_line(sigil(action), action, path, &detail));
            }
            Event::Warn { message } => self.warn(message),
            Event::Summary { .. } => {}
        }
    }

    fn read_stdin_line(&self) -> io::Result<String> {
        let mut line = String::new();
        let n = io::stdin().lock().read_line(&mut line)?;
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "end of input"));
        }
        while line.ends_with('\n') || line.ends_with('\r') {
            line.pop();
        }
        Ok(line)
    }

    fn show_prompt(&self, text: &str) {
        let mut w = self.err.lock().unwrap_or_else(|e| e.into_inner());
        let _ = write!(w, "{text}");
        let _ = w.flush();
    }

    /// `question [y/N]` on the terminal; false when not a TTY (callers then require `--yes`).
    pub fn confirm(&self, question: &str) -> bool {
        if self.silent || !self.tty {
            return false;
        }
        self.mp.suspend(|| {
            self.show_prompt(&format!("{question} [y/N] "));
            match self.read_stdin_line() {
                Ok(a) => matches!(a.trim().to_ascii_lowercase().as_str(), "y" | "yes"),
                Err(_) => false,
            }
        })
    }

    /// A numbered menu on the terminal; `None` when not a TTY, on end of input, or when the
    /// answer is not one of the numbers (root-identity guard, vault choice).
    pub fn choose(&self, question: &str, options: &[&str]) -> Option<usize> {
        if self.silent || !self.tty || options.is_empty() {
            return None;
        }
        self.mp.suspend(|| {
            let mut text = format!("{question}\n");
            for (i, o) in options.iter().enumerate() {
                text.push_str(&format!("  {}) {o}\n", i + 1));
            }
            text.push_str(&format!("Choice [1-{}]: ", options.len()));
            self.show_prompt(&text);
            let n: usize = self.read_stdin_line().ok()?.trim().parse().ok()?;
            if (1..=options.len()).contains(&n) {
                Some(n - 1)
            } else {
                None
            }
        })
    }

    /// Shows `question` on stderr and reads one line from stdin — the terminal, or a pipe when
    /// stdin is not a terminal (the headless login reads its code this way). The trailing line
    /// break is removed. End of input → `UnexpectedEof`.
    pub fn prompt_line(&self, question: &str) -> io::Result<String> {
        if self.silent {
            return Err(io::Error::other("no terminal"));
        }
        self.mp.suspend(|| {
            if !question.is_empty() {
                self.show_prompt(&format!("{question} "));
            }
            self.read_stdin_line()
        })
    }

    /// No-echo prompt on `/dev/tty` (rpassword); fails when there is no terminal. A secret is
    /// never read from stdin, argv or the environment.
    pub fn prompt_secret(&self, question: &str) -> io::Result<String> {
        if self.silent {
            return Err(io::Error::other("no terminal"));
        }
        self.mp
            .suspend(|| rpassword::prompt_password(format!("{question} ")))
    }

    /// A byte progress bar on stderr: `Uploading  [====>   ] 3.1 GiB/4.9 GiB  41 MiB/s  eta 44s
    /// (1,204/4,700 files, 12 blobs)`. Hidden with `--json`, `-q`, or when stderr is no terminal.
    pub fn transfer_progress(&self, label: &str, total_bytes: u64, total_files: u64) -> Progress {
        if self.silent {
            return Progress::hidden();
        }
        let bar = self.mp.add(ProgressBar::new(total_bytes));
        if let Ok(style) = ProgressStyle::with_template(
            "{prefix:<10} [{bar:16}] {binary_bytes}/{binary_total_bytes}  {binary_bytes_per_sec}  eta {eta}  {msg}",
        ) {
            bar.set_style(style.progress_chars("=> "));
        }
        bar.set_prefix(label.to_string());
        let p = Progress {
            bar,
            state: Arc::new(ProgressState {
                total_files,
                ..ProgressState::default()
            }),
        };
        p.refresh_message();
        p
    }
}

/// `+ upload   2026/IMG_0412.jpg            4.2 MiB`
fn plan_line(sigil: char, action: &str, path: &str, detail: &str) -> String {
    if detail.is_empty() {
        format!("{sigil} {action:<8} {path}")
    } else {
        format!("{sigil} {action:<8} {path:<28} {detail}")
    }
}

fn sigil(action: &str) -> char {
    match action {
        "upload" | "download" | "mkdir" | "restore" => '+',
        "reuse" => '=',
        "delete" | "rmdir" => '-',
        "skip" | "keep" | "conflict" => '!',
        _ => '~',
    }
}

#[derive(Default)]
struct ProgressState {
    total_files: u64,
    bytes: AtomicU64,
    files: AtomicU64,
    blobs: AtomicU64,
}

/// Cloneable handle on one transfer's progress; `Send + Sync + 'static`. All clones count into
/// the same totals.
#[derive(Clone)]
pub struct Progress {
    bar: ProgressBar,
    state: Arc<ProgressState>,
}

impl Progress {
    /// Draws nothing (it still counts) — for tests and library callers.
    pub fn hidden() -> Self {
        Progress {
            bar: ProgressBar::hidden(),
            state: Arc::new(ProgressState::default()),
        }
    }

    fn refresh_message(&self) {
        if self.bar.is_hidden() {
            return;
        }
        let files = util::group_thousands(self.state.files.load(Ordering::Relaxed));
        let blobs = util::group_thousands(self.state.blobs.load(Ordering::Relaxed));
        let msg = if self.state.total_files > 0 {
            format!(
                "({files}/{} files, {blobs} blobs)",
                util::group_thousands(self.state.total_files)
            )
        } else {
            format!("({files} files, {blobs} blobs)")
        };
        self.bar.set_message(msg);
    }

    /// `n` more bytes were transferred.
    pub fn add_bytes(&self, n: u64) {
        self.state.bytes.fetch_add(n, Ordering::Relaxed);
        self.bar.inc(n);
    }

    /// One more file is completely transferred.
    pub fn file_done(&self) {
        self.state.files.fetch_add(1, Ordering::Relaxed);
        self.refresh_message();
    }

    /// One more blob is completely transferred.
    pub fn blob_done(&self) {
        self.state.blobs.fetch_add(1, Ordering::Relaxed);
        self.refresh_message();
    }

    /// Removes the bar from the screen. The counters stay readable.
    pub fn finish(&self) {
        self.bar.finish_and_clear();
    }

    /// Bytes counted so far (all clones).
    pub fn bytes(&self) -> u64 {
        self.state.bytes.load(Ordering::Relaxed)
    }

    /// Files counted so far (all clones).
    pub fn files(&self) -> u64 {
        self.state.files.load(Ordering::Relaxed)
    }

    /// Blobs counted so far (all clones).
    pub fn blobs(&self) -> u64 {
        self.state.blobs.load(Ordering::Relaxed)
    }
}

/// tracing-subscriber to stderr. `GCLONE_LOG` (an `EnvFilter` directive string such as
/// `debug` or `gclone::index=trace`) wins; otherwise `-v` = info, `-vv` = debug for gclone,
/// `-vvv` = trace for everything, default = warnings only. Calling it twice is harmless.
pub fn init_logging(verbose: u8) {
    use tracing_subscriber::EnvFilter;
    let default = match verbose {
        0 => "warn",
        1 => "warn,gclone=info",
        2 => "warn,gclone=debug",
        _ => "trace",
    };
    let filter = std::env::var("GCLONE_LOG")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .and_then(|s| EnvFilter::try_new(s).ok())
        .unwrap_or_else(|| EnvFilter::new(default));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(io::stderr)
        // A log line that cannot be written is dropped. The default reports the failure with
        // `eprintln!`, which panics on a closed stderr — and under `serve restic --stdio`
        // stderr closes whenever restic exits first.
        .log_internal_errors(false)
        // Colour only for a terminal: a log line in a file or a pipe carries no escape codes.
        .with_ansi(io::stderr().is_terminal() && std::env::var_os("NO_COLOR").is_none())
        .with_target(verbose >= 2)
        .without_time()
        .try_init();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Default)]
    struct Buf(Arc<Mutex<Vec<u8>>>);
    impl Write for Buf {
        fn write(&mut self, b: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    impl Buf {
        fn text(&self) -> String {
            String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
        }
    }

    fn ui(json: bool, quiet: bool, verbose: u8) -> (Ui, Buf, Buf) {
        let (out, err) = (Buf::default(), Buf::default());
        let ui = Ui::with_writers(
            UiOpts {
                json,
                quiet,
                verbose,
            },
            Box::new(out.clone()),
            Box::new(err.clone()),
        );
        (ui, out, err)
    }

    fn all_events() -> Vec<Event> {
        vec![
            Event::Plan {
                action: "upload".into(),
                path: "2026/IMG_0412.jpg".into(),
                size: Some(4_404_019),
                note: None,
            },
            Event::Plan {
                action: "reuse".into(),
                path: "a \"quoted\"\nname".into(),
                size: None,
                note: Some("(same content as b)".into()),
            },
            Event::Done {
                action: "upload".into(),
                path: "2026/IMG_0412.jpg".into(),
                bytes: 4_404_019,
            },
            Event::Skip {
                path: "notes.txt".into(),
                reason: "remote is newer".into(),
            },
            Event::Warn {
                message: "something odd".into(),
            },
            Event::Summary {
                uploaded: 1,
                downloaded: 2,
                reused: 3,
                deleted: 4,
                skipped: 5,
                failed: 6,
                conflicts: 7,
                bytes_up: 8,
                bytes_down: 9,
                exit: 6,
            },
        ]
    }

    #[test]
    fn json_mode_emits_one_valid_object_per_event() {
        let (ui, out, err) = ui(true, false, 0);
        assert!(ui.json());
        let events = all_events();
        for e in &events {
            ui.event(e);
        }
        let text = out.text();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), events.len(), "one line per event: {text}");
        assert!(text.ends_with('\n'));
        let tags = ["plan", "plan", "done", "skip", "warn", "summary"];
        for (line, tag) in lines.iter().zip(tags) {
            let v: serde_json::Value = serde_json::from_str(line).unwrap();
            assert!(v.is_object(), "{line}");
            assert_eq!(v["event"], tag);
        }
        let plan: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(
            plan,
            serde_json::json!({"event": "plan", "action": "upload", "path": "2026/IMG_0412.jpg", "size": 4_404_019})
        );
        let reuse: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(reuse["path"], "a \"quoted\"\nname");
        assert_eq!(reuse["note"], "(same content as b)");
        assert!(reuse.get("size").is_none());
        let summary: serde_json::Value = serde_json::from_str(lines[5]).unwrap();
        assert_eq!(
            summary,
            serde_json::json!({"event": "summary", "uploaded": 1, "downloaded": 2, "reused": 3, "deleted": 4, "skipped": 5,
                               "failed": 6, "conflicts": 7, "bytes_up": 8, "bytes_down": 9, "exit": 6})
        );
        assert_eq!(
            err.text(),
            "",
            "nothing on stderr for events in --json mode"
        );

        // out() is suppressed, warn() becomes an event, error() stays on stderr
        ui.out("human line");
        ui.warn("careful");
        ui.error("bad");
        let text = out.text();
        let last = text.lines().last().unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(last).unwrap(),
            serde_json::json!({"event": "warn", "message": "careful"})
        );
        assert_eq!(text.lines().count(), events.len() + 1);
        assert!(!text.contains("human line"));
        assert_eq!(err.text(), "error: bad\n");
    }

    #[test]
    fn human_mode_renders_like_the_spec_examples() {
        let (ui, out, err) = ui(false, false, 0);
        ui.event(&Event::Plan {
            action: "upload".into(),
            path: "2026/IMG_0412.jpg".into(),
            size: Some(4_404_019),
            note: None,
        });
        ui.event(&Event::Plan {
            action: "reuse".into(),
            path: "2026/trip/IMG_0001.jpg".into(),
            size: None,
            note: Some("(same content as 2026/IMG_0001.jpg)".into()),
        });
        ui.event(&Event::Plan {
            action: "delete".into(),
            path: "2025/blurry.jpg".into(),
            size: None,
            note: None,
        });
        ui.event(&Event::Skip {
            path: "notes.txt".into(),
            reason: "remote is newer (changed on \"nas\"); --force to overwrite".into(),
        });
        ui.event(&Event::Plan {
            action: "keep".into(),
            path: "draft.txt".into(),
            size: None,
            note: Some(
                "both changed; remote version will be kept as draft.conflict-9f2c11aa-412.txt"
                    .into(),
            ),
        });
        ui.event(&Event::Done {
            action: "upload".into(),
            path: "x".into(),
            bytes: 1,
        });
        ui.event(&Event::Summary {
            uploaded: 0,
            downloaded: 0,
            reused: 0,
            deleted: 0,
            skipped: 0,
            failed: 0,
            conflicts: 0,
            bytes_up: 0,
            bytes_down: 0,
            exit: 0,
        });
        ui.out("Would upload 1 (4.2 MiB), reuse 1, delete 1, skip 1, conflict 1. Nothing changed (dry run).");
        assert_eq!(
            out.text(),
            "\
+ upload   2026/IMG_0412.jpg            4.2 MiB
= reuse    2026/trip/IMG_0001.jpg       (same content as 2026/IMG_0001.jpg)
- delete   2025/blurry.jpg
! skip     notes.txt                    remote is newer (changed on \"nas\"); --force to overwrite
! keep     draft.txt                    both changed; remote version will be kept as draft.conflict-9f2c11aa-412.txt
Would upload 1 (4.2 MiB), reuse 1, delete 1, skip 1, conflict 1. Nothing changed (dry run).
"
        );
        assert_eq!(err.text(), "", "Done lines need -v");

        ui.info("Creating vault...");
        ui.warn("careful");
        ui.error("bad");
        ui.event(&Event::Warn {
            message: "odd".into(),
        });
        assert_eq!(
            err.text(),
            "Creating vault...\nwarning: careful\nerror: bad\nwarning: odd\n"
        );
    }

    #[test]
    fn verbose_and_quiet() {
        let (ui, out, err) = ui(false, false, 1);
        assert_eq!(ui.verbose(), 1);
        ui.event(&Event::Done {
            action: "download".into(),
            path: "a/b".into(),
            bytes: 2048,
        });
        assert_eq!(out.text(), "");
        assert_eq!(err.text(), format!("+ download {:<28} 2 KiB\n", "a/b"));

        let (ui, out, err) = self::ui(false, true, 3);
        assert!(ui.quiet());
        ui.info("hidden");
        ui.event(&Event::Plan {
            action: "upload".into(),
            path: "p".into(),
            size: None,
            note: None,
        });
        ui.event(&Event::Skip {
            path: "p".into(),
            reason: "r".into(),
        });
        ui.event(&Event::Done {
            action: "upload".into(),
            path: "p".into(),
            bytes: 1,
        });
        ui.out("result");
        ui.warn("still shown");
        ui.error("still shown");
        assert_eq!(out.text(), "result\n");
        assert_eq!(err.text(), "warning: still shown\nerror: still shown\n");
    }

    #[test]
    fn silent_ui_and_hidden_progress_work_without_a_tty() {
        let ui = Ui::silent();
        assert!(!ui.is_tty());
        assert!(!ui.json());
        ui.out("x");
        ui.info("x");
        ui.warn("x");
        ui.error("x");
        for e in all_events() {
            ui.event(&e);
        }
        assert!(!ui.confirm("Delete everything?"));
        assert_eq!(ui.choose("Which?", &["a", "b"]), None);
        assert!(ui.prompt_line("Code:").is_err());
        assert!(ui.prompt_secret("Passphrase:").is_err());

        let p = ui.transfer_progress("Uploading", 1000, 3);
        p.add_bytes(10);
        p.file_done();
        p.blob_done();
        p.finish();

        let p = Progress::hidden();
        let q = p.clone();
        p.add_bytes(100);
        q.add_bytes(23);
        q.file_done();
        p.file_done();
        p.blob_done();
        assert_eq!((p.bytes(), p.files(), p.blobs()), (123, 2, 1));
        assert_eq!((q.bytes(), q.files(), q.blobs()), (123, 2, 1));
        p.finish();
        q.add_bytes(1);
        assert_eq!(p.bytes(), 124);
    }

    #[test]
    fn non_tty_ui_never_prompts() {
        let (ui, out, err) = ui(false, false, 0);
        assert!(!ui.is_tty());
        assert!(!ui.confirm("Delete 5 of 10 files?"));
        assert_eq!(ui.choose("Which vault?", &["one", "two"]), None);
        assert_eq!(out.text(), "");
        assert_eq!(
            err.text(),
            "",
            "no question is shown when nobody can answer"
        );

        // progress handles from a non-terminal Ui count but draw nothing
        let p = ui.transfer_progress("Downloading", 4096, 2);
        p.add_bytes(4096);
        p.file_done();
        p.file_done();
        p.blob_done();
        p.finish();
        assert_eq!((p.bytes(), p.files(), p.blobs()), (4096, 2, 1));
        assert_eq!(err.text(), "");
    }

    #[test]
    fn handles_are_send_sync_static() {
        fn ok<T: Send + Sync + 'static>() {}
        ok::<Ui>();
        ok::<Progress>();
        ok::<Event>();
        // a Progress can be moved into a task and used from several threads
        let p = Progress::hidden();
        let handles: Vec<_> = (0..4)
            .map(|_| {
                let p = p.clone();
                std::thread::spawn(move || {
                    for _ in 0..100 {
                        p.add_bytes(1);
                    }
                    p.file_done();
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!((p.bytes(), p.files()), (400, 4));
    }

    #[test]
    fn init_logging_twice_is_harmless() {
        init_logging(0);
        init_logging(2);
        tracing::warn!("logging initialised");
    }
}
