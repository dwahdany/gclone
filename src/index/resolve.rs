//! Deterministic conflict resolution (SPEC §5.2.3) — owned by WP4. Private to `index`.

use std::collections::{BTreeSet, HashSet};

use rusqlite::Connection;
use rusqlite::types::Value;

use super::Vault;
use crate::backend::Backend;
use crate::error::{IndexError, StateError};
use crate::path::{self, conflict_name};
use crate::state::tables::{self, heads_query};
use crate::types::{EntryKind, Head, OpDraft};

/// Resolutions that would put two `Put`s for one path into a segment wait for the next round
/// (only fork twins can cause that); this bounds the rounds of one call.
const MAX_ROUNDS: usize = 8;

struct Round {
    drafts: Vec<OpDraft>,
    resolutions: u64,
    /// Something was left for the next round.
    deferred: bool,
}

fn heads_at(c: &Connection, path: &str) -> Result<Vec<Head>, StateError> {
    heads_query(c, "path = ?", &[Value::Text(path.to_owned())])
}

/// The conflict losers, in the order rule 1 handles them. Served by the partial index
/// `heads_losers`: O(losers), not a scan of every head.
pub(crate) const LOSERS: &str = "winner = 0 ORDER BY path, st_l, st_d, st_i, hash";

/// Rule 2 for one path: its winner is a file while other paths need a directory there.
const BLOCKING_FILE_AT: &str = "path = ?1 AND winner = 1 AND kind = 0 AND EXISTS (SELECT 1 \
     FROM heads c WHERE c.path > ?1 || '/' AND c.path < ?1 || '0')";

/// Rule 2 over the whole replica.
const BLOCKING_FILES_ALL: &str = "winner = 1 AND kind = 0 AND EXISTS (SELECT 1 FROM heads c \
     WHERE c.path > heads.path || '/' AND c.path < heads.path || '0') ORDER BY path";

/// The winning files that sit where other paths need a directory (rule 2), sorted by path.
///
/// Such a clash appears only when the heads of a path change — the file's own, or those of a
/// path below it — so only the paths touched since the last complete resolution and their
/// ancestors are looked at (`touched`, §8.4); the whole table is scanned only after the
/// replica's content was replaced (`resolve_all`).
fn blocking_files(c: &Connection) -> Result<Vec<Head>, StateError> {
    let Some(touched) = tables::touched_paths(c)? else {
        return heads_query(c, BLOCKING_FILES_ALL, &[]);
    };
    let mut suspects: BTreeSet<&str> = BTreeSet::new();
    for path in &touched {
        suspects.insert(path);
        suspects.extend(path::ancestors(path));
    }
    let mut files = Vec::new();
    for path in suspects {
        files.extend(heads_query(
            c,
            BLOCKING_FILE_AT,
            &[Value::Text(path.to_owned())],
        )?);
    }
    debug_assert_eq!(
        files.iter().map(|h| &h.path).collect::<Vec<_>>(),
        heads_query(c, BLOCKING_FILES_ALL, &[])?
            .iter()
            .map(|h| &h.path)
            .collect::<Vec<_>>(),
        "the touched paths must name every file-vs-directory clash (§5.2.3 rule 2)"
    );
    Ok(files)
}

fn del(head: &Head) -> OpDraft {
    OpDraft::Del {
        path: head.path.clone(),
        base: head.stamp,
        effect: None,
    }
}

/// The ops that resolve the replica's current conflicts — a pure function of its state, so
/// several devices emit the same ops (§5.2.3).
fn plan(c: &Connection) -> Result<Round, StateError> {
    let mut round = Round {
        drafts: Vec::new(),
        resolutions: 0,
        deferred: false,
    };
    // Paths that get a `Put` in this round: a segment never holds two for one path.
    let mut put_paths: HashSet<String> = HashSet::new();

    // `Put{conflict_name(..), entry, origin}` — unless that copy exists already (another device
    // resolved the same conflict). `false`: the target is taken in this round.
    let copy_aside = |round: &mut Round, put_paths: &mut HashSet<String>, v: &Head| {
        let target = conflict_name(&v.path, &v.stamp);
        if heads_at(c, &target)?
            .iter()
            .any(|h| h.entry.same_content(&v.entry))
        {
            return Ok::<bool, StateError>(true);
        }
        if !put_paths.insert(target.clone()) {
            return Ok(false);
        }
        round.drafts.push(OpDraft::Put {
            path: target,
            entry: v.entry.clone(),
            base: None,
            origin: Some(v.stamp),
            effect: None,
        });
        Ok(true)
    };

    // Rule 1: several heads at a path.
    let losers = heads_query(c, LOSERS, &[])?;
    for loser in &losers {
        let Some(winner) = heads_at(c, &loser.path)?.into_iter().find(|h| h.winner) else {
            continue;
        };
        let keep_copy =
            loser.entry.kind != EntryKind::Dir && !loser.entry.same_content(&winner.entry);
        if loser.stamp == winner.stamp {
            // Fork twins: a `Del` on the shared stamp would remove the winner as well. A
            // successor that carries the winner's entry replaces every head with that stamp.
            if put_paths.contains(&loser.path)
                || (keep_copy && !copy_aside(&mut round, &mut put_paths, loser)?)
            {
                round.deferred = true;
                continue;
            }
            put_paths.insert(loser.path.clone());
            round.drafts.push(OpDraft::Put {
                path: winner.path.clone(),
                entry: winner.entry.clone(),
                base: Some(winner.stamp),
                origin: Some(winner.stamp),
                effect: None,
            });
        } else {
            if keep_copy && !copy_aside(&mut round, &mut put_paths, loser)? {
                round.deferred = true;
                continue;
            }
            round.drafts.push(del(loser));
        }
        round.resolutions += 1;
    }

    // Rule 2: a file where other paths need a directory — the file moves.
    let files = blocking_files(c)?;
    for file in &files {
        if put_paths.contains(&file.path) || !copy_aside(&mut round, &mut put_paths, file)? {
            round.deferred = true;
            continue;
        }
        round.drafts.push(del(file));
        round.resolutions += 1;
    }
    Ok(round)
}

impl<B: Backend> Vault<B> {
    /// §5.2.3; stages, then ALWAYS `commit()`; returns the number of resolutions.
    pub async fn resolve_conflicts(&self) -> Result<u64, IndexError> {
        let _journal = self.journal.lock().await;
        self.resolve_locked().await
    }

    pub(super) async fn resolve_locked(&self) -> Result<u64, IndexError> {
        // Leftover staged ops first: nothing staged outlives this call, and the resolutions are
        // planned on a replica that contains them.
        self.commit_locked().await?;
        let mut total = 0;
        for _ in 0..MAX_ROUNDS {
            let round = self.db.read(plan)?;
            if round.drafts.is_empty() {
                // Everything touched so far was looked at and is settled.
                if !round.deferred && self.db.read(tables::touched_any)? {
                    self.db.txn(tables::touched_clear)?;
                }
                break;
            }
            self.stage(round.drafts)?;
            self.commit_locked().await?;
            total += round.resolutions;
            if !round.deferred {
                break;
            }
        }
        Ok(total)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::ciphertext_len;
    use crate::format::{Op, SegmentV1, SnapshotV1};
    use crate::index::query::CONFLICT_COUNT;
    use crate::index::testing;
    use crate::state::Db;
    use crate::types::{BlobId, DeviceId, Entry, EntryKind, Loc};

    fn file(tag: u8) -> Entry {
        let size = 1000 + u64::from(tag);
        Entry {
            kind: EntryKind::File,
            size,
            mtime_ns: 0,
            exec: false,
            hash: [tag; 32],
            loc: Some(Loc {
                blob: BlobId([tag; 16]),
                off: 0,
                clen: ciphertext_len(size, 16),
                salt: [tag; 16],
                chunk_log2: 16,
                epoch: 1,
                suite: 1,
                flags: 0,
            }),
        }
    }

    fn put(path: &str, tag: u8) -> Op {
        Op::Put {
            path: path.into(),
            entry: file(tag),
            base: None,
            origin: None,
        }
    }

    /// Applies one segment of device `d` with the given ops.
    fn apply(db: &Db, d: u8, seq: u64, ops: Vec<Op>) {
        let seg = SegmentV1 {
            vault_id: [0x11; 16],
            device: DeviceId([d; 8]),
            seq,
            lamport: seq,
            prev: None,
            seen: Vec::new(),
            created_ms: 0,
            host: "test".into(),
            ops,
        };
        testing::apply(db, &seg, 1).unwrap();
    }

    fn touched(db: &Db) -> Option<Vec<String>> {
        db.read(tables::touched_paths).unwrap()
    }

    /// The paths a round would move out of the way of a directory (rule 2).
    fn moved(db: &Db) -> Vec<String> {
        db.read(plan)
            .unwrap()
            .drafts
            .iter()
            .filter_map(|d| match d {
                OpDraft::Del { path, .. } => Some(path.clone()),
                _ => None,
            })
            .collect()
    }

    fn query_plan(db: &Db, sql: &str) -> String {
        db.read(|c| {
            let mut stmt = c.prepare(&format!("EXPLAIN QUERY PLAN {sql}"))?;
            let rows = stmt.query_map([], |r| r.get::<_, String>(3))?;
            Ok::<_, StateError>(rows.collect::<Result<Vec<_>, _>>()?.join("\n"))
        })
        .unwrap()
    }

    /// Regression (cost): "are there conflicts?" and rule 1 scanned every head — several times
    /// per command — because no index covered the losers; rule 2 scanned every head and probed
    /// below each file.
    #[test]
    fn conflict_queries_do_not_scan_the_heads() {
        let db = Db::open_in_memory().unwrap();
        for sql in [
            CONFLICT_COUNT.to_owned(),
            format!("SELECT path FROM heads WHERE {LOSERS}"),
        ] {
            let plan = query_plan(&db, &sql);
            assert!(plan.contains("heads_losers"), "{sql}\n{plan}");
            assert!(!plan.contains("SCAN heads\n") && !plan.ends_with("SCAN heads"));
            assert!(!plan.contains("TEMP B-TREE"), "no sort either:\n{plan}");
        }
        // Rule 2 for one touched path: two primary-key searches, no scan.
        let plan = query_plan(
            &db,
            &format!(
                "SELECT path FROM heads WHERE {}",
                BLOCKING_FILE_AT.replace("?1", "'p'")
            ),
        );
        assert!(!plan.contains("SCAN"), "{plan}");
        assert!(
            plan.contains("SEARCH heads USING PRIMARY KEY (path=?)"),
            "{plan}"
        );
    }

    #[test]
    fn rule_2_looks_at_the_touched_paths_and_their_ancestors() {
        let db = Db::open_in_memory().unwrap();
        assert_eq!(touched(&db), Some(vec![]));
        apply(&db, 1, 1, vec![put("a", 1), put("x/y", 2), put("z", 3)]);
        assert_eq!(
            touched(&db),
            Some(vec!["a".to_owned(), "x/y".into(), "z".into()])
        );
        assert!(moved(&db).is_empty());
        db.txn(tables::touched_clear).unwrap();

        // A path appears below a file that was settled long ago: found through its ancestor.
        apply(&db, 2, 1, vec![put("a/b/c", 4)]);
        assert_eq!(touched(&db), Some(vec!["a/b/c".to_owned()]));
        assert_eq!(moved(&db), vec!["a".to_owned()]);
        // Unresolved, it is found again: nothing is forgotten before a round is clean.
        assert_eq!(moved(&db), vec!["a".to_owned()]);

        // A file appears where settled paths need a directory: found through itself.
        let db = Db::open_in_memory().unwrap();
        apply(&db, 1, 1, vec![put("x/y", 2)]);
        db.txn(tables::touched_clear).unwrap();
        apply(&db, 2, 1, vec![put("x", 5), put("unrelated", 6)]);
        assert_eq!(moved(&db), vec!["x".to_owned()]);

        // A deletion makes another head of the path its winner: the path counts as touched.
        let db = Db::open_in_memory().unwrap();
        let dir = Op::Put {
            path: "d".into(),
            entry: Entry::dir(),
            base: None,
            origin: None,
        };
        apply(&db, 1, 1, vec![put("d", 7)]);
        apply(&db, 2, 1, vec![dir, put("d/in", 8)]);
        // (the file loses to the directory entry: rule 1's business, not rule 2's)
        let winner = db
            .read(|c| heads_at(c, "d"))
            .unwrap()
            .into_iter()
            .find(|h| h.winner)
            .unwrap();
        assert_eq!(winner.entry.kind, EntryKind::Dir);
        db.txn(tables::touched_clear).unwrap();
        apply(
            &db,
            3,
            2,
            vec![Op::Del {
                path: "d".into(),
                base: winner.stamp,
            }],
        );
        assert_eq!(touched(&db), Some(vec!["d".to_owned()]));
        assert_eq!(moved(&db), vec!["d".to_owned()]);
    }

    #[test]
    fn rule_2_scans_everything_after_a_rebuild_or_a_flood() {
        // More touched paths than are worth tracking: one scan instead.
        let db = Db::open_in_memory().unwrap();
        let ops: Vec<Op> = (0..tables::TOUCHED_MAX + 1)
            .map(|i| put(&format!("f{i}"), 1))
            .collect();
        apply(&db, 1, 1, ops);
        db.txn(tables::touched_bound).unwrap();
        assert_eq!(touched(&db), None);
        apply(&db, 2, 1, vec![put("f7/below", 2)]);
        assert_eq!(
            touched(&db),
            None,
            "nothing is tracked while the scan is due"
        );
        assert_eq!(moved(&db), vec!["f7".to_owned()]);
        db.txn(tables::touched_clear).unwrap();
        assert_eq!(touched(&db), Some(vec![]));

        // A replica replaced by a snapshot: whatever clash the snapshot carries is found.
        let db = Db::open_in_memory().unwrap();
        apply(&db, 1, 1, vec![put("p", 1)]);
        apply(&db, 2, 1, vec![put("p/q", 2)]);
        let state = testing::dump(&db).unwrap();
        let snap: SnapshotV1 =
            state.to_snapshot([0x11; 16], DeviceId([1; 8]), 9, Vec::new(), Vec::new(), 0);
        let fresh = Db::open_in_memory().unwrap();
        testing::load_snapshot(&fresh, &snap).unwrap();
        assert_eq!(touched(&fresh), None);
        assert_eq!(moved(&fresh), vec!["p".to_owned()]);
    }
}
