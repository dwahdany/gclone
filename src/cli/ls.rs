//! `gclone ls` / `gclone tree` (SPEC §7.1, §10) — owned by WP7.

use std::collections::BTreeMap;

use super::{Ctx, GlobalOpts, OpenOpts, open_ctx, remote_arg, shown};
use crate::path;
use crate::types::{EntryKind, Head};
use crate::util::{format_local_minute, group_thousands, human_size};

#[derive(clap::Args, Clone, Debug)]
pub struct LsArgs {
    /// Long format: size and modification time.
    #[arg(short = 'l', long)]
    pub long: bool,
    /// Recursive.
    #[arg(short = 'R', long)]
    pub recursive: bool,
    /// Remote path (`:PATH`; default: the vault root).
    pub path: Option<String>,
}

#[derive(clap::Args, Clone, Debug)]
pub struct TreeArgs {
    /// Remote path (`:PATH`; default: the vault root).
    pub path: Option<String>,
}

fn not_found(path: &str) -> anyhow::Error {
    std::io::Error::new(
        std::io::ErrorKind::NotFound,
        format!("{}: no such file or directory in the vault", shown(path)),
    )
    .into()
}

/// `    4.2 MiB  2026-11-02 18:31  IMG_0412.jpg` / `          -                    trip/`
fn long_line(head: Option<&Head>, name: &str, is_dir: bool) -> String {
    let (size, time) = match head {
        Some(h) if h.entry.kind == EntryKind::File => (
            human_size(h.entry.size),
            format_local_minute(u64::try_from(h.entry.mtime_ns / 1_000_000).unwrap_or(0)),
        ),
        // A directory has no size and no time of its own.
        _ => ("-".to_string(), String::new()),
    };
    let slash = if is_dir { "/" } else { "" };
    format!("{size:>11}  {time:<16}  {name}{slash}")
}

fn short_line(name: &str, is_dir: bool) -> String {
    if is_dir {
        format!("{name}/")
    } else {
        name.to_string()
    }
}

/// The path of the command, checked: `Some(head)` when it names a file.
fn target(ctx: &Ctx, arg: Option<&str>) -> anyhow::Result<(String, Option<Head>)> {
    let prefix = match arg {
        Some(arg) => remote_arg(arg)?,
        None => String::new(),
    };
    if ctx.vault.exists_dir(&prefix)? {
        return Ok((prefix, None));
    }
    match ctx.vault.head(&prefix)? {
        Some(head) => Ok((prefix, Some(head))),
        None => Err(not_found(&prefix)),
    }
}

pub async fn run(g: &GlobalOpts, args: LsArgs) -> anyhow::Result<i32> {
    let ctx = open_ctx(g, OpenOpts::read_only()).await?;
    ctx.report_refresh();
    let (prefix, file) = target(&ctx, args.path.as_deref())?;
    let print = |head: Option<&Head>, name: &str, is_dir: bool| {
        ctx.ui.out(&if args.long {
            long_line(head, name, is_dir)
        } else {
            short_line(name, is_dir)
        });
    };
    if let Some(head) = &file {
        print(Some(head), path::file_name(&prefix), false);
    } else if args.recursive {
        for head in ctx.vault.walk(&prefix)? {
            let Some(rel) = path::strip_prefix(&head.path, &prefix).filter(|r| !r.is_empty())
            else {
                continue;
            };
            print(Some(&head), rel, head.entry.kind == EntryKind::Dir);
        }
    } else {
        for row in ctx.vault.list(&prefix)? {
            print(row.head.as_ref(), &row.name, row.is_dir);
        }
    }
    Ok(0)
}

#[derive(Default)]
struct Node {
    is_dir: bool,
    children: BTreeMap<String, Node>,
}

fn draw(node: &Node, indent: &str, out: &mut Vec<String>, counts: &mut (u64, u64)) {
    let last = node.children.len().saturating_sub(1);
    for (i, (name, child)) in node.children.iter().enumerate() {
        let (branch, next) = if i == last {
            ("└── ", "    ")
        } else {
            ("├── ", "│   ")
        };
        out.push(format!("{indent}{branch}{name}"));
        if child.is_dir || !child.children.is_empty() {
            counts.0 += 1;
            draw(child, &format!("{indent}{next}"), out, counts);
        } else {
            counts.1 += 1;
        }
    }
}

/// The lines of `tree` for the winners under `prefix` (paths relative to it), plus the counts
/// `(directories, files)`.
fn tree_lines(rels: impl Iterator<Item = (String, bool)>) -> (Vec<String>, (u64, u64)) {
    let mut root = Node::default();
    for (rel, is_dir) in rels {
        let mut node = &mut root;
        for part in rel.split('/') {
            node = node.children.entry(part.to_string()).or_default();
        }
        node.is_dir |= is_dir;
    }
    let (mut lines, mut counts) = (Vec::new(), (0, 0));
    draw(&root, "", &mut lines, &mut counts);
    (lines, counts)
}

/// `gclone tree`.
pub async fn run_tree(g: &GlobalOpts, args: TreeArgs) -> anyhow::Result<i32> {
    let ctx = open_ctx(g, OpenOpts::read_only()).await?;
    ctx.report_refresh();
    let (prefix, file) = target(&ctx, args.path.as_deref())?;
    ctx.ui.out(&shown(&prefix));
    if file.is_some() {
        return Ok(0);
    }
    let heads = ctx.vault.walk(&prefix)?;
    let rels = heads.iter().filter_map(|h| {
        path::strip_prefix(&h.path, &prefix)
            .filter(|r| !r.is_empty())
            .map(|r| (r.to_string(), h.entry.kind == EntryKind::Dir))
    });
    let (lines, (dirs, files)) = tree_lines(rels);
    for line in &lines {
        ctx.ui.out(line);
    }
    let plural = |n: u64, one: &str, many: &str| {
        format!("{} {}", group_thousands(n), if n == 1 { one } else { many })
    };
    ctx.ui.out("");
    ctx.ui.out(&format!(
        "{}, {}",
        plural(dirs, "directory", "directories"),
        plural(files, "file", "files")
    ));
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tree_is_drawn_with_implied_directories() {
        let rels = [
            ("2026/IMG_0412.jpg", false),
            ("2026/trip/IMG_0001.jpg", false),
            ("empty", true),
            ("notes.txt", false),
        ]
        .into_iter()
        .map(|(p, d)| (p.to_string(), d));
        let (lines, counts) = tree_lines(rels);
        assert_eq!(
            lines,
            [
                "├── 2026",
                "│   ├── IMG_0412.jpg",
                "│   └── trip",
                "│       └── IMG_0001.jpg",
                "├── empty",
                "└── notes.txt",
            ]
        );
        assert_eq!(counts, (3, 3));
    }

    #[test]
    fn listing_lines() {
        assert_eq!(short_line("trip", true), "trip/");
        assert_eq!(short_line("a.jpg", false), "a.jpg");
        assert_eq!(
            long_line(None, "trip", true),
            format!("{:>11}  {:<16}  trip/", "-", "")
        );
    }
}
