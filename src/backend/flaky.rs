//! Fault-injecting wrapper around any backend (SPEC §9.5) — owned by WP2.
//!
//! Every injector is one-shot unless it takes a `times`; `times == u32::MAX` means "always".
//! An injected failure happens *instead of* the call (nothing reaches the inner backend), and
//! the call still counts in [`Flaky::calls`]. Planned failures are checked before the put/get
//! injectors, which stay armed for the next call that gets through. [`Flaky::hang`] is the one
//! fault that is not an answer: the call never returns, as on a network that went away.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};

use bytes::Bytes;
use futures_util::StreamExt;
use tokio::sync::mpsc;

use super::{Backend, ByteStream, Handle, ObjMeta, PutBody, Quota};
use crate::error::BackendError;

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum OpKind {
    NewIds,
    CreateFolder,
    Put,
    Get,
    Stat,
    List,
    FindByName,
    Trash,
    Untrash,
    Delete,
    About,
}

type MakeError = fn() -> BackendError;
type Hook = Box<dyn FnOnce() + Send>;

#[derive(Default)]
struct Plan {
    calls: HashMap<OpKind, u64>,
    fail_next: HashMap<OpKind, (u32, MakeError)>,
    /// (op, ordinal of the call that fails).
    fail_nth: Vec<(OpKind, u64, MakeError)>,
    fail_put_named: Vec<(String, u32, MakeError)>,
    hang: Vec<OpKind>,
    lose_ack: bool,
    cut_stream_put: Option<u64>,
    put_progress: Option<(u64, Hook)>,
    corrupt_md5: bool,
    cut_get: Option<u64>,
    list_lag_ms: u64,
}

/// True while `times` allows another failure; counts down unless it is `u32::MAX`.
fn take(times: &mut u32) -> bool {
    match *times {
        0 => false,
        u32::MAX => true,
        _ => {
            *times -= 1;
            true
        }
    }
}

/// What the next put has to do besides reaching the inner backend.
struct PutFaults {
    lose_ack: bool,
    corrupt_md5: bool,
    cut: Option<u64>,
    progress: Option<(u64, Hook)>,
}

/// The caller's part channel, with the byte count and the progress hook.
struct Tap {
    parts: mpsc::Receiver<std::io::Result<Bytes>>,
    consumed: u64,
    progress: Option<(u64, Hook)>,
}

impl Tap {
    fn fire(&mut self) {
        if let Some((_, hook)) = self.progress.take_if(|(after, _)| self.consumed >= *after) {
            hook();
        }
    }

    async fn next(&mut self) -> Option<std::io::Result<Bytes>> {
        self.fire();
        let item = self.parts.recv().await?;
        if let Ok(part) = &item {
            self.consumed += part.len() as u64;
        }
        self.fire();
        Some(item)
    }
}

/// inner + `Arc<Mutex<fault plan>>`. Clones (for a `Clone` inner) share the plan.
pub struct Flaky<B: Backend> {
    inner: B,
    plan: Arc<Mutex<Plan>>,
}

impl<B: Backend + Clone> Clone for Flaky<B> {
    fn clone(&self) -> Self {
        Flaky {
            inner: self.inner.clone(),
            plan: self.plan.clone(),
        }
    }
}

impl<B: Backend> Flaky<B> {
    pub fn new(inner: B) -> Self {
        Flaky {
            inner,
            plan: Arc::default(),
        }
    }

    pub fn inner(&self) -> &B {
        &self.inner
    }

    fn plan(&self) -> MutexGuard<'_, Plan> {
        self.plan.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The next `times` calls of `op` fail.
    pub fn fail_next(&self, op: OpKind, times: u32, make: fn() -> BackendError) {
        self.plan().fail_next.insert(op, (times, make));
    }

    /// nth call of that kind from now (1-based).
    pub fn fail_nth(&self, op: OpKind, nth: u64, make: fn() -> BackendError) {
        let mut plan = self.plan();
        let at = plan.calls.get(&op).copied().unwrap_or(0) + nth;
        plan.fail_nth.push((op, at, make));
    }

    /// e.g. `("s-", u32::MAX, quota)` = every segment put fails.
    pub fn fail_put_named(&self, name_prefix: &str, times: u32, make: fn() -> BackendError) {
        self.plan()
            .fail_put_named
            .push((name_prefix.to_string(), times, make));
    }

    /// Every call of `op` from now on never returns (nothing reaches the inner backend): a
    /// network that went away, which only a cancellation or a deadline of the caller ends.
    /// Stays until [`clear`](Self::clear)ed; calls already hanging keep hanging.
    pub fn hang(&self, op: OpKind) {
        self.plan().hang.push(op);
    }

    /// The object IS stored, the caller gets `Transient` → retry must take the idempotent path.
    pub fn lose_ack_next_put(&self) {
        self.plan().lose_ack = true;
    }

    /// Consumes that much, stores nothing, returns `SessionLost`. Waits for the next `Stream`
    /// put; `Small` puts pass untouched.
    pub fn cut_next_stream_put(&self, after_bytes: u64) {
        self.plan().cut_stream_put = Some(after_bytes);
    }

    /// Runs `f` once when the next Stream put has consumed ≥ `after_bytes` (e.g. rewrite the
    /// source file mid-upload). "Consumed" counts the bytes taken from the caller's channel:
    /// `f` runs right after the part that crosses the offset was received (with `0`: before the
    /// first part is requested).
    pub fn on_put_progress(&self, after_bytes: u64, f: Box<dyn FnOnce() + Send>) {
        self.plan().put_progress = Some((after_bytes, f));
    }

    /// Returned `ObjMeta.md5` is wrong once → caller must trash + retry.
    pub fn corrupt_md5_next_put(&self) {
        self.plan().corrupt_md5 = true;
    }

    /// Stream yields that much then `Err(Transient)` — also when the object (or range) ends
    /// before `after_bytes`.
    pub fn cut_next_get(&self, after_bytes: u64) {
        self.plan().cut_get = Some(after_bytes);
    }

    /// `list`/`find_by_name` hide objects younger than `ms` (by `inner.now_ms`). Stays until
    /// set to 0 or [`clear`](Self::clear)ed.
    pub fn set_list_lag_ms(&self, ms: u64) {
        self.plan().list_lag_ms = ms;
    }

    /// Calls of `op` since `new`, injected failures included.
    pub fn calls(&self, op: OpKind) -> u64 {
        self.plan().calls.get(&op).copied().unwrap_or(0)
    }

    /// Drops every planned fault and the list lag. The call counts stay.
    pub fn clear(&self) {
        let mut plan = self.plan();
        let calls = std::mem::take(&mut plan.calls);
        *plan = Plan {
            calls,
            ..Plan::default()
        };
    }

    /// Counts the call and answers the failure planned for it, if any; never returns for an
    /// `op` that hangs.
    async fn enter(&self, op: OpKind) -> Result<(), BackendError> {
        let (hangs, planned) = self.planned(op);
        if hangs {
            std::future::pending::<()>().await;
        }
        planned
    }

    fn planned(&self, op: OpKind) -> (bool, Result<(), BackendError>) {
        let mut plan = self.plan();
        if plan.hang.contains(&op) {
            *plan.calls.entry(op).or_insert(0) += 1;
            return (true, Ok(()));
        }
        let ordinal = {
            let n = plan.calls.entry(op).or_insert(0);
            *n += 1;
            *n
        };
        let nth = plan
            .fail_nth
            .iter()
            .position(|(o, at, _)| *o == op && *at == ordinal)
            .map(|i| plan.fail_nth.swap_remove(i).2);
        // A call consumes one failure even when two plans name it.
        let failure = nth.or_else(|| {
            let (times, make) = plan.fail_next.get_mut(&op)?;
            take(times).then_some(*make)
        });
        (false, failure.map_or(Ok(()), |make| Err(make())))
    }

    async fn enter_put(&self, name: &str, is_stream: bool) -> Result<PutFaults, BackendError> {
        self.enter(OpKind::Put).await?;
        let mut plan = self.plan();
        for (prefix, times, make) in plan.fail_put_named.iter_mut() {
            if name.starts_with(prefix.as_str()) && take(times) {
                return Err(make());
            }
        }
        let lose_ack = std::mem::take(&mut plan.lose_ack);
        Ok(PutFaults {
            lose_ack,
            // A lost acknowledgement hides the meta; the lie waits for a put that returns one.
            corrupt_md5: !lose_ack && std::mem::take(&mut plan.corrupt_md5),
            cut: plan.cut_stream_put.take_if(|_| is_stream),
            progress: plan.put_progress.take_if(|_| is_stream),
        })
    }

    fn lagging(&self, mut found: Vec<ObjMeta>) -> Vec<ObjMeta> {
        let lag = self.plan().list_lag_ms;
        if lag > 0 {
            let now = self.inner.now_ms();
            found.retain(|m| now.saturating_sub(m.created_ms) >= lag);
        }
        found
    }
}

impl<B: Backend> Backend for Flaky<B> {
    async fn new_ids(&self, n: usize) -> Result<Vec<Handle>, BackendError> {
        self.enter(OpKind::NewIds).await?;
        self.inner.new_ids(n).await
    }

    async fn create_folder(
        &self,
        id: &Handle,
        parent: &Handle,
        name: &str,
    ) -> Result<(), BackendError> {
        self.enter(OpKind::CreateFolder).await?;
        self.inner.create_folder(id, parent, name).await
    }

    async fn put(
        &self,
        id: &Handle,
        parent: &Handle,
        name: &str,
        body: PutBody,
    ) -> Result<ObjMeta, BackendError> {
        let is_stream = matches!(body, PutBody::Stream { .. });
        let faults = self.enter_put(name, is_stream).await?;
        let result = match body {
            PutBody::Stream { total, parts } => {
                let mut tap = Tap {
                    parts,
                    consumed: 0,
                    progress: faults.progress,
                };
                if let Some(after) = faults.cut {
                    while tap.consumed < after && tap.next().await.is_some() {}
                    return Err(BackendError::SessionLost);
                }
                // Parts are relayed one at a time, so the hook fires at the same point of the
                // caller's stream whatever the inner backend buffers.
                let (tx, relayed) = mpsc::channel(1);
                let relay = async {
                    while let Some(item) = tap.next().await {
                        if tx.send(item).await.is_err() {
                            break;
                        }
                    }
                    drop(tx);
                };
                let body = PutBody::Stream {
                    total,
                    parts: relayed,
                };
                let put = self.inner.put(id, parent, name, body);
                tokio::pin!(put, relay);
                tokio::select! {
                    biased;
                    result = &mut put => result,
                    () = &mut relay => put.await,
                }
            }
            small => self.inner.put(id, parent, name, small).await,
        };
        let mut meta = result?;
        if faults.lose_ack {
            return Err(BackendError::Transient(
                "injected: the acknowledgement of the put was lost".into(),
            ));
        }
        if faults.corrupt_md5 {
            let mut md5 = meta.md5.unwrap_or_default();
            md5[0] ^= 0x01;
            meta.md5 = Some(md5);
        }
        Ok(meta)
    }

    async fn get(
        &self,
        h: &Handle,
        range: Option<std::ops::Range<u64>>,
    ) -> Result<ByteStream, BackendError> {
        self.enter(OpKind::Get).await?;
        let cut = self.plan().cut_get.take();
        let stream = self.inner.get(h, range).await?;
        let Some(after) = cut else {
            return Ok(stream);
        };
        let cut_error = || BackendError::Transient("injected: the download stream was cut".into());
        // `left` = bytes still to hand out; `None` once the error has been yielded.
        let cut_stream = futures_util::stream::unfold(
            (stream, Some(after)),
            move |(mut stream, left)| async move {
                let left = left?;
                if left == 0 {
                    return Some((Err(cut_error()), (stream, None)));
                }
                match stream.next().await {
                    Some(Ok(mut chunk)) => {
                        chunk.truncate(left.min(chunk.len() as u64) as usize);
                        let left = left - chunk.len() as u64;
                        Some((Ok(chunk), (stream, Some(left))))
                    }
                    Some(Err(e)) => Some((Err(e), (stream, None))),
                    None => Some((Err(cut_error()), (stream, None))),
                }
            },
        );
        Ok(Box::pin(cut_stream))
    }

    async fn stat(&self, h: &Handle) -> Result<Option<ObjMeta>, BackendError> {
        self.enter(OpKind::Stat).await?;
        self.inner.stat(h).await
    }

    async fn list(&self, parent: &Handle) -> Result<Vec<ObjMeta>, BackendError> {
        self.enter(OpKind::List).await?;
        Ok(self.lagging(self.inner.list(parent).await?))
    }

    async fn list_strict(&self, parent: &Handle) -> Result<Vec<ObjMeta>, BackendError> {
        self.enter(OpKind::List).await?;
        Ok(self.lagging(self.inner.list_strict(parent).await?))
    }

    async fn list_trashed(&self, parent: &Handle) -> Result<Vec<ObjMeta>, BackendError> {
        self.enter(OpKind::List).await?;
        self.inner.list_trashed(parent).await
    }

    async fn find_by_name(&self, name: &str) -> Result<Vec<ObjMeta>, BackendError> {
        self.enter(OpKind::FindByName).await?;
        Ok(self.lagging(self.inner.find_by_name(name).await?))
    }

    async fn trash(&self, h: &Handle) -> Result<(), BackendError> {
        self.enter(OpKind::Trash).await?;
        self.inner.trash(h).await
    }

    async fn untrash(&self, h: &Handle) -> Result<(), BackendError> {
        self.enter(OpKind::Untrash).await?;
        self.inner.untrash(h).await
    }

    async fn delete(&self, h: &Handle) -> Result<(), BackendError> {
        self.enter(OpKind::Delete).await?;
        self.inner.delete(h).await
    }

    async fn about(&self) -> Result<Quota, BackendError> {
        self.enter(OpKind::About).await?;
        self.inner.about().await
    }

    fn now_ms(&self) -> u64 {
        self.inner.now_ms()
    }

    fn clock_offset_ms(&self) -> i64 {
        self.inner.clock_offset_ms()
    }
}
