//! The backend the binary uses (SPEC §9.5) — owned by WP2. Pure delegation.

use super::dir::DirBackend;
use super::mem::MemBackend;
use super::{Backend, ByteStream, Handle, ObjMeta, PutBody, Quota};
use crate::error::BackendError;

pub enum AnyBackend {
    Drive(crate::backend::drive::DriveBackend),
    Dir(DirBackend),
    Mem(MemBackend),
}

macro_rules! delegate {
    ($self:ident, $b:ident => $call:expr) => {
        match $self {
            AnyBackend::Drive($b) => $call,
            AnyBackend::Dir($b) => $call,
            AnyBackend::Mem($b) => $call,
        }
    };
}

impl Backend for AnyBackend {
    async fn new_ids(&self, n: usize) -> Result<Vec<Handle>, BackendError> {
        delegate!(self, b => b.new_ids(n).await)
    }

    async fn create_folder(
        &self,
        id: &Handle,
        parent: &Handle,
        name: &str,
    ) -> Result<(), BackendError> {
        delegate!(self, b => b.create_folder(id, parent, name).await)
    }

    async fn put(
        &self,
        id: &Handle,
        parent: &Handle,
        name: &str,
        body: PutBody,
    ) -> Result<ObjMeta, BackendError> {
        delegate!(self, b => b.put(id, parent, name, body).await)
    }

    async fn get(
        &self,
        h: &Handle,
        range: Option<std::ops::Range<u64>>,
    ) -> Result<ByteStream, BackendError> {
        delegate!(self, b => b.get(h, range).await)
    }

    async fn stat(&self, h: &Handle) -> Result<Option<ObjMeta>, BackendError> {
        delegate!(self, b => b.stat(h).await)
    }

    async fn list(&self, parent: &Handle) -> Result<Vec<ObjMeta>, BackendError> {
        delegate!(self, b => b.list(parent).await)
    }

    async fn list_strict(&self, parent: &Handle) -> Result<Vec<ObjMeta>, BackendError> {
        delegate!(self, b => b.list_strict(parent).await)
    }

    async fn find_by_name(&self, name: &str) -> Result<Vec<ObjMeta>, BackendError> {
        delegate!(self, b => b.find_by_name(name).await)
    }

    async fn trash(&self, h: &Handle) -> Result<(), BackendError> {
        delegate!(self, b => b.trash(h).await)
    }

    async fn untrash(&self, h: &Handle) -> Result<(), BackendError> {
        delegate!(self, b => b.untrash(h).await)
    }

    async fn delete(&self, h: &Handle) -> Result<(), BackendError> {
        delegate!(self, b => b.delete(h).await)
    }

    async fn about(&self) -> Result<Quota, BackendError> {
        delegate!(self, b => b.about().await)
    }

    fn now_ms(&self) -> u64 {
        delegate!(self, b => b.now_ms())
    }
}
