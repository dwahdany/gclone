//! In-memory backend with adversary hooks (SPEC §9.5) — owned by WP2.
//!
//! Behaves like one Drive account: several objects may share a name, a trashed folder hides
//! everything below it (its descendants report `trashed = true`), deleting a folder deletes its
//! content, and `stat(Handle::top())` answers a folder. `list` of an unknown parent is empty.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard};

use bytes::Bytes;

use super::{
    Backend, ByteStream, Handle, ObjMeta, PartReader, PutBody, Quota, bad_request, check_small,
    md5_of, not_downloadable,
};
use crate::error::BackendError;

/// `get` streams are cut into pieces of this size, so readers see chunk boundaries.
const GET_CHUNK: usize = 256 * 1024;

/// Clones share one store ("one Drive, many devices").
#[derive(Clone)]
pub struct MemBackend {
    inner: Arc<Mutex<Store>>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Counters {
    pub new_ids: u64,
    pub create_folder: u64,
    /// `put` calls, including those answered from an existing id.
    pub put: u64,
    /// Bytes of the objects that `put` stored.
    pub put_bytes: u64,
    pub get: u64,
    /// Bytes that `get` streams actually handed out.
    pub get_bytes: u64,
    pub stat: u64,
    pub list: u64,
    pub find_by_name: u64,
    pub trash: u64,
    pub untrash: u64,
    pub delete: u64,
    pub about: u64,
}

/// Opaque full copy of the stored objects (not of the clock, the counters or the id sequence:
/// a rollback attack rewinds content, not time).
pub struct MemCheckpoint(BTreeMap<String, Obj>);

#[derive(Clone)]
struct Obj {
    name: String,
    parent: Handle,
    data: Bytes,
    md5: Option<[u8; 16]>,
    created_ms: u64,
    is_folder: bool,
    trashed: bool,
    /// Adversary hook: the size that `stat` and the listings report instead of the real one.
    claimed_size: Option<u64>,
}

struct Store {
    objects: BTreeMap<String, Obj>,
    now_ms: u64,
    next_id: u64,
    counters: Counters,
}

impl Store {
    /// Trashed itself or below a trashed folder.
    fn is_trashed(&self, obj: &Obj) -> bool {
        let mut cur = obj;
        loop {
            if cur.trashed {
                return true;
            }
            match self.objects.get(&cur.parent.0) {
                Some(parent) => cur = parent,
                None => return false,
            }
        }
    }

    fn meta(&self, id: &str, obj: &Obj) -> ObjMeta {
        ObjMeta {
            handle: Handle(id.to_string()),
            name: obj.name.clone(),
            parent: obj.parent.clone(),
            size: obj.claimed_size.unwrap_or(obj.data.len() as u64),
            md5: obj.md5,
            created_ms: obj.created_ms,
            is_folder: obj.is_folder,
            trashed: self.is_trashed(obj),
        }
    }

    fn meta_of(&self, h: &Handle) -> Option<ObjMeta> {
        self.objects.get(&h.0).map(|o| self.meta(&h.0, o))
    }

    fn visible(&self, keep: impl Fn(&Obj) -> bool) -> Vec<ObjMeta> {
        let mut out: Vec<ObjMeta> = self
            .objects
            .iter()
            .filter(|(_, o)| keep(o) && !self.is_trashed(o))
            .map(|(id, o)| self.meta(id, o))
            .collect();
        out.sort_by(|a, b| a.name.cmp(&b.name));
        out
    }

    /// A new object needs a real id and a parent that is the top level or an existing folder.
    fn check_new(&self, id: &Handle, parent: &Handle) -> Result<(), BackendError> {
        if id.is_top() {
            return Err(bad_request(
                "the top-level handle cannot be used as an object id",
            ));
        }
        if parent.is_top() || self.objects.get(&parent.0).is_some_and(|p| p.is_folder) {
            return Ok(());
        }
        Err(BackendError::Fatal {
            status: 404,
            reason: "notFound".into(),
            message: format!("parent folder {} does not exist", parent.0),
        })
    }

    fn set_trashed(&mut self, h: &Handle, trashed: bool) -> Result<(), BackendError> {
        if h.is_top() {
            return Err(bad_request("the top level cannot be trashed"));
        }
        let obj = self.objects.get_mut(&h.0).ok_or(BackendError::NotFound)?;
        obj.trashed = trashed;
        Ok(())
    }

    /// Removes the object and, for a folder, everything below it.
    fn remove(&mut self, h: &Handle) -> bool {
        if h.is_top() || self.objects.remove(&h.0).is_none() {
            return false;
        }
        let mut gone = vec![h.0.clone()];
        while let Some(parent) = gone.pop() {
            let children: Vec<String> = self
                .objects
                .iter()
                .filter(|(_, o)| o.parent.0 == parent)
                .map(|(id, _)| id.clone())
                .collect();
            for id in children {
                self.objects.remove(&id);
                gone.push(id);
            }
        }
        true
    }
}

impl Default for MemBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl MemBackend {
    /// An empty store whose clock stands at the current wall-clock time.
    pub fn new() -> Self {
        MemBackend {
            inner: Arc::new(Mutex::new(Store {
                objects: BTreeMap::new(),
                now_ms: crate::util::now_ms(),
                next_id: 0,
                counters: Counters::default(),
            })),
        }
    }

    fn store(&self) -> MutexGuard<'_, Store> {
        // A panicking test hook must not take every later assertion down with it.
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Logical clock; `created_ms` comes from it. It moves only through these two calls.
    pub fn set_now_ms(&self, ms: u64) {
        self.store().now_ms = ms;
    }

    pub fn advance_ms(&self, ms: u64) {
        let mut s = self.store();
        s.now_ms = s.now_ms.saturating_add(ms);
    }

    pub fn counters(&self) -> Counters {
        self.store().counters.clone()
    }

    pub fn reset_counters(&self) {
        self.store().counters = Counters::default();
    }

    /// Every object, trashed ones included, in id order.
    pub fn all_objects(&self) -> Vec<ObjMeta> {
        let s = self.store();
        s.objects.iter().map(|(id, o)| s.meta(id, o)).collect()
    }

    /// The stored bytes; `None` for folders and unknown ids.
    pub fn read(&self, h: &Handle) -> Option<Bytes> {
        let s = self.store();
        s.objects
            .get(&h.0)
            .filter(|o| !o.is_folder)
            .map(|o| o.data.clone())
    }

    // --- adversary hooks

    /// md5 is recomputed (server-consistent lie). Panics if `h` is not a stored file: a
    /// tampering test that tampers with nothing would pass for the wrong reason.
    pub fn tamper(&self, h: &Handle, f: impl FnOnce(&mut Vec<u8>)) {
        let mut s = self.store();
        let Some(obj) = s.objects.get_mut(&h.0).filter(|o| !o.is_folder) else {
            panic!("MemBackend::tamper: no file with id {:?}", h.0);
        };
        let mut data = obj.data.to_vec();
        f(&mut data);
        obj.md5 = Some(md5_of(&data));
        obj.data = data.into();
    }

    /// A store that lies about a size: `stat` and the listings report `size` for `h` while
    /// `get` keeps serving the real bytes. A listed size is a claim, never a bound on what a
    /// download delivers. Panics if `h` is not a stored file.
    pub fn claim_size(&self, h: &Handle, size: u64) {
        let mut s = self.store();
        let Some(obj) = s.objects.get_mut(&h.0).filter(|o| !o.is_folder) else {
            panic!("MemBackend::claim_size: no file with id {:?}", h.0);
        };
        obj.claimed_size = Some(size);
    }

    /// Removes the object (a folder with its content) without a trace.
    pub fn hard_delete(&self, h: &Handle) -> bool {
        self.store().remove(h)
    }

    pub fn rename(&self, h: &Handle, new_name: &str) -> bool {
        match self.store().objects.get_mut(&h.0) {
            Some(obj) => {
                obj.name = new_name.to_string();
                true
            }
            None => false,
        }
    }

    /// Swap attack: `h` keeps its id, name and place but serves the bytes (and md5) of `with`.
    pub fn replace_content(&self, h: &Handle, with: &Handle) -> bool {
        let mut s = self.store();
        let Some((data, md5)) = s
            .objects
            .get(&with.0)
            .filter(|o| !o.is_folder)
            .map(|o| (o.data.clone(), o.md5))
        else {
            return false;
        };
        match s.objects.get_mut(&h.0).filter(|o| !o.is_folder) {
            Some(obj) => {
                obj.data = data;
                obj.md5 = md5;
                true
            }
            None => false,
        }
    }

    pub fn checkpoint(&self) -> MemCheckpoint {
        MemCheckpoint(self.store().objects.clone())
    }

    /// Rollback attack.
    pub fn restore(&self, c: &MemCheckpoint) {
        self.store().objects = c.0.clone();
    }
}

impl Backend for MemBackend {
    async fn new_ids(&self, n: usize) -> Result<Vec<Handle>, BackendError> {
        let mut s = self.store();
        s.counters.new_ids += 1;
        Ok((0..n)
            .map(|_| {
                s.next_id += 1;
                Handle(format!("m{:011}", s.next_id))
            })
            .collect())
    }

    async fn create_folder(
        &self,
        id: &Handle,
        parent: &Handle,
        name: &str,
    ) -> Result<(), BackendError> {
        let mut s = self.store();
        s.counters.create_folder += 1;
        if let Some(existing) = s.objects.get(&id.0) {
            return if existing.is_folder {
                Ok(())
            } else {
                Err(BackendError::AlreadyExists)
            };
        }
        s.check_new(id, parent)?;
        let folder = Obj {
            name: name.to_string(),
            parent: parent.clone(),
            data: Bytes::new(),
            md5: None,
            created_ms: s.now_ms,
            is_folder: true,
            trashed: false,
            claimed_size: None,
        };
        s.objects.insert(id.0.clone(), folder);
        Ok(())
    }

    async fn put(
        &self,
        id: &Handle,
        parent: &Handle,
        name: &str,
        body: PutBody,
    ) -> Result<ObjMeta, BackendError> {
        {
            let mut s = self.store();
            s.counters.put += 1;
            if let Some(existing) = s.meta_of(id) {
                return Ok(existing);
            }
            s.check_new(id, parent)?;
        }
        let data = match body {
            PutBody::Small(data) => {
                check_small(data.len())?;
                data
            }
            PutBody::Stream { total, parts } => {
                let mut reader = PartReader::new(total, parts);
                let mut buf = Vec::new();
                while let Some(part) = reader.next().await? {
                    buf.extend_from_slice(&part);
                }
                buf.into()
            }
        };
        // The store was unlocked while the body arrived: the id or the parent may have changed.
        let mut s = self.store();
        if let Some(existing) = s.meta_of(id) {
            return Ok(existing);
        }
        s.check_new(id, parent)?;
        s.counters.put_bytes += data.len() as u64;
        let obj = Obj {
            name: name.to_string(),
            parent: parent.clone(),
            md5: Some(md5_of(&data)),
            data,
            created_ms: s.now_ms,
            is_folder: false,
            trashed: false,
            claimed_size: None,
        };
        let meta = s.meta(&id.0, &obj);
        s.objects.insert(id.0.clone(), obj);
        Ok(meta)
    }

    async fn get(
        &self,
        h: &Handle,
        range: Option<std::ops::Range<u64>>,
    ) -> Result<ByteStream, BackendError> {
        let data = {
            let mut s = self.store();
            s.counters.get += 1;
            if h.is_top() {
                return Err(not_downloadable());
            }
            let obj = s.objects.get(&h.0).ok_or(BackendError::NotFound)?;
            if obj.is_folder {
                return Err(not_downloadable());
            }
            obj.data.clone()
        };
        let len = data.len() as u64;
        let (start, end) = match range {
            Some(r) => (r.start.min(len), r.end.min(len)),
            None => (0, len),
        };
        let data = data.slice(start as usize..end.max(start) as usize);
        let store = self.inner.clone();
        let chunks = (0..data.len()).step_by(GET_CHUNK).map(move |at| {
            let chunk = data.slice(at..data.len().min(at + GET_CHUNK));
            let mut s = store.lock().unwrap_or_else(|e| e.into_inner());
            s.counters.get_bytes += chunk.len() as u64;
            Ok(chunk)
        });
        Ok(Box::pin(futures_util::stream::iter(chunks)))
    }

    async fn stat(&self, h: &Handle) -> Result<Option<ObjMeta>, BackendError> {
        let mut s = self.store();
        s.counters.stat += 1;
        if h.is_top() {
            return Ok(Some(ObjMeta::top(0)));
        }
        Ok(s.meta_of(h))
    }

    async fn list(&self, parent: &Handle) -> Result<Vec<ObjMeta>, BackendError> {
        let mut s = self.store();
        s.counters.list += 1;
        Ok(s.visible(|o| o.parent == *parent))
    }

    async fn find_by_name(&self, name: &str) -> Result<Vec<ObjMeta>, BackendError> {
        let mut s = self.store();
        s.counters.find_by_name += 1;
        Ok(s.visible(|o| o.name == name))
    }

    async fn trash(&self, h: &Handle) -> Result<(), BackendError> {
        let mut s = self.store();
        s.counters.trash += 1;
        s.set_trashed(h, true)
    }

    async fn untrash(&self, h: &Handle) -> Result<(), BackendError> {
        let mut s = self.store();
        s.counters.untrash += 1;
        s.set_trashed(h, false)
    }

    async fn delete(&self, h: &Handle) -> Result<(), BackendError> {
        let mut s = self.store();
        s.counters.delete += 1;
        if h.is_top() {
            return Err(bad_request("the top level cannot be deleted"));
        }
        if s.remove(h) {
            Ok(())
        } else {
            Err(BackendError::NotFound)
        }
    }

    async fn about(&self) -> Result<Quota, BackendError> {
        let mut s = self.store();
        s.counters.about += 1;
        let size = |o: &Obj| o.data.len() as u64;
        Ok(Quota {
            limit: None,
            usage: s.objects.values().map(size).sum(),
            usage_in_trash: s
                .objects
                .values()
                .filter(|o| s.is_trashed(o))
                .map(size)
                .sum(),
            account: None,
        })
    }

    fn now_ms(&self) -> u64 {
        self.store().now_ms
    }
}
