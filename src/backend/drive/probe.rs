//! The automatable day-0 probes of SPEC §2.9 (rows 6, 8, 9, 10, 12, 13) — owned by WP3.
//!
//! Each probe sends single, unretried requests and reports what Drive answered; nothing here
//! is on the path of a normal command.

use std::time::{Duration, Instant};

use bytes::Bytes;
use reqwest::header::{CONTENT_RANGE, CONTENT_TYPE, HeaderMap, LOCATION, RANGE};

use super::api::{BLOB_MIME, File, Outgoing, decode, header_text, metadata};
use super::errors::parse_range_header;
use super::pacer::CallKind;
use super::upload::multipart_body;
use super::{DriveBackend, DriveConfig, FIELDS, Inner};
use crate::auth::TokenProvider;
use crate::auth::login::describe;
use crate::backend::{Backend, Handle, PutBody};
use crate::consts::{
    ID_POOL_BATCH, ID_POOL_BATCH_FALLBACK, MIB, MULTIPART_MAX, PROBE_PREFIX, UPLOAD_GRANULE,
};
use crate::error::BackendError;
use crate::util;

#[derive(Clone, Debug)]
pub enum ProbeOutcome {
    Pass(String),
    Fail(String),
    Info(String),
    Skipped(String),
}

#[derive(Clone, Debug)]
pub struct ProbeLine {
    pub id: u8,
    pub question: &'static str,
    pub outcome: ProbeOutcome,
}

const ROWS: [(u8, &str); 6] = [
    (
        6,
        "409 for a pre-generated ID that exists: multipart? resumable initiation or completion? stat right after?",
    ),
    (
        8,
        "files.list lag after a write; files.get read-after-write",
    ),
    (
        9,
        "size, md5Checksum, createdTime in the completion body when fields= was sent at initiation",
    ),
    (10, "generateIds max count"),
    (12, "exact multipart size boundary"),
    (
        13,
        "is a resumable upload invisible to files.list until finalised?",
    ),
];

/// How long probe 8 waits for a new object to show up in a listing.
const LIST_LAG_MAX: Duration = Duration::from_secs(30);
const LIST_LAG_POLL: Duration = Duration::from_millis(250);

struct Raw {
    status: u16,
    headers: HeaderMap,
    body: Bytes,
}

struct Probe<'a> {
    backend: &'a DriveBackend,
    folder: Handle,
}

impl Probe<'_> {
    fn inner(&self) -> &Inner {
        &self.backend.inner
    }

    async fn id(&self) -> Result<Handle, BackendError> {
        Ok(self.backend.new_ids(1).await?.remove(0))
    }

    /// One request, as is: no retry, no classification.
    async fn send(
        &self,
        kind: CallKind,
        request: impl Into<Outgoing>,
    ) -> Result<Raw, BackendError> {
        let inner = self.inner();
        inner.pacer.acquire(kind).await;
        let token = inner.token().await?;
        let response = request
            .into()
            .send(&token)
            .await
            .map_err(BackendError::Transient)?;
        Ok(Raw {
            status: response.status().as_u16(),
            headers: response.headers().clone(),
            body: response
                .bytes()
                .await
                .map_err(|e| BackendError::Transient(describe(&e.without_url())))?,
        })
    }

    async fn multipart(&self, id: &Handle, name: &str, data: &[u8]) -> Result<Raw, BackendError> {
        let inner = self.inner();
        let body = multipart_body(
            "gclone-probe",
            &metadata(id, &self.folder, name, BLOB_MIME),
            data,
        );
        let request = inner
            .upload
            .post(inner.upload_url())
            .query(&[("uploadType", "multipart"), ("fields", FIELDS)])
            .header(CONTENT_TYPE, "multipart/related; boundary=gclone-probe");
        self.send(CallKind::Create, inner.upload_request(request, vec![body]))
            .await
    }

    async fn initiate(&self, id: &Handle, name: &str, total: u64) -> Result<Raw, BackendError> {
        let inner = self.inner();
        let request = inner
            .upload
            .post(inner.upload_url())
            .query(&[("uploadType", "resumable"), ("fields", FIELDS)])
            .header("X-Upload-Content-Type", BLOB_MIME)
            .header("X-Upload-Content-Length", total)
            .header(CONTENT_TYPE, "application/json; charset=UTF-8")
            .body(metadata(id, &self.folder, name, BLOB_MIME).to_string());
        self.send(CallKind::Create, request).await
    }

    async fn session_put(
        &self,
        session: &str,
        start: u64,
        data: Bytes,
        total: u64,
    ) -> Result<Raw, BackendError> {
        let end = start + data.len() as u64 - 1;
        let inner = self.inner();
        let request = inner
            .upload
            .put(session)
            .header(CONTENT_RANGE, format!("bytes {start}-{end}/{total}"));
        self.send(
            CallKind::UploadPart,
            inner.upload_request(request, vec![data]),
        )
        .await
    }

    fn session_uri(raw: &Raw) -> Result<String, BackendError> {
        header_text(&raw.headers, &LOCATION)
            .map(str::to_owned)
            .ok_or_else(|| {
                BackendError::Transient("no session URI in the initiation answer".into())
            })
    }

    async fn listed(&self, id: &Handle) -> Result<bool, BackendError> {
        Ok(self
            .backend
            .list(&self.folder)
            .await?
            .iter()
            .any(|m| m.handle == *id))
    }

    /// Row 6.
    async fn conflict(&self) -> Result<ProbeOutcome, BackendError> {
        let id = self.id().await?;
        let data = Bytes::from_static(b"gclone probe 6");
        self.backend
            .put(&id, &self.folder, "probe-6", PutBody::Small(data.clone()))
            .await?;

        let again = self.multipart(&id, "probe-6", &data).await?;
        if (200..300).contains(&again.status) {
            return Ok(ProbeOutcome::Fail(
                "a second multipart create with the same ID was accepted".into(),
            ));
        }
        let seen = self.backend.stat(&id).await?.is_some();

        let total = data.len() as u64;
        let init = self.initiate(&id, "probe-6", total).await?;
        let resumable = if init.status == 409 {
            "409 at initiation".to_string()
        } else if init.status == 200 {
            let done = self
                .session_put(&Self::session_uri(&init)?, 0, data, total)
                .await?;
            match done.status {
                409 => "409 at completion".to_string(),
                200 | 201 => {
                    return Ok(ProbeOutcome::Fail(
                        "a second resumable create with the same ID was accepted".into(),
                    ));
                }
                other => format!("{other} at completion"),
            }
        } else {
            format!("{} at initiation", init.status)
        };
        Ok(ProbeOutcome::Info(format!(
            "multipart: {}; resumable: {resumable}; stat right after the 409: {}",
            again.status,
            if seen { "found" } else { "not found" }
        )))
    }

    /// Row 8.
    async fn list_lag(&self) -> Result<ProbeOutcome, BackendError> {
        let id = self.id().await?;
        let body = PutBody::Small(Bytes::from_static(b"gclone probe 8"));
        self.backend.put(&id, &self.folder, "probe-8", body).await?;
        let created = Instant::now();
        let stat = if self.backend.stat(&id).await?.is_some() {
            "found"
        } else {
            "NOT found"
        };
        loop {
            if self.listed(&id).await? {
                return Ok(ProbeOutcome::Info(format!(
                    "files.get right after the create: {stat}; files.list shows the object after {} ms",
                    created.elapsed().as_millis()
                )));
            }
            if created.elapsed() >= LIST_LAG_MAX {
                return Ok(ProbeOutcome::Fail(format!(
                    "files.get right after the create: {stat}; files.list does not show the object after {} s",
                    LIST_LAG_MAX.as_secs()
                )));
            }
            tokio::time::sleep(LIST_LAG_POLL).await;
        }
    }

    /// Row 9.
    async fn completion_fields(&self) -> Result<ProbeOutcome, BackendError> {
        let id = self.id().await?;
        let data = Bytes::from(vec![9u8; UPLOAD_GRANULE as usize + 1]);
        let total = data.len() as u64;
        let init = self.initiate(&id, "probe-9", total).await?;
        if init.status != 200 {
            return Ok(ProbeOutcome::Fail(format!(
                "initiation answered {}",
                init.status
            )));
        }
        let done = self
            .session_put(&Self::session_uri(&init)?, 0, data, total)
            .await?;
        if !matches!(done.status, 200 | 201) {
            return Ok(ProbeOutcome::Fail(format!(
                "completion answered {}",
                done.status
            )));
        }
        Ok(match decode::<File>(&done.body) {
            Ok(file) if file.is_complete_blob() => ProbeOutcome::Pass(format!(
                "completion ({}) carries size, md5Checksum and createdTime",
                done.status
            )),
            _ => ProbeOutcome::Fail(
                "the completion body lacks size, md5Checksum or createdTime; every upload costs a follow-up files.get".into(),
            ),
        })
    }

    /// Row 10.
    async fn generate_ids(&self) -> Result<ProbeOutcome, BackendError> {
        let inner = self.inner();
        let url = format!("{}/generateIds", inner.files_url());
        let mut refused = Vec::new();
        for count in [1000, ID_POOL_BATCH, ID_POOL_BATCH_FALLBACK] {
            let request = inner.api.get(&url).query(&[
                ("count", count.to_string().as_str()),
                ("space", "drive"),
                ("type", "files"),
            ]);
            let raw = self.send(CallKind::GenerateIds, request).await?;
            if raw.status == 200 {
                let note = format!("count={count} accepted (refused: {refused:?})");
                return Ok(if count >= ID_POOL_BATCH {
                    ProbeOutcome::Pass(note)
                } else {
                    ProbeOutcome::Info(format!("{note}; the id pool uses batches of {count}"))
                });
            }
            refused.push(format!("{count} → {}", raw.status));
        }
        Ok(ProbeOutcome::Fail(format!(
            "every count was refused: {refused:?}"
        )))
    }

    /// Row 12.
    async fn multipart_boundary(&self) -> Result<ProbeOutcome, BackendError> {
        let sizes = [MULTIPART_MAX, 5_000_000, 5 * MIB, 5 * MIB + 1];
        let data = Bytes::from(vec![12u8; (5 * MIB + 1) as usize]);
        let mut seen = Vec::new();
        for size in sizes {
            let id = self.id().await?;
            let raw = self
                .multipart(&id, &format!("probe-12-{size}"), &data[..size as usize])
                .await?;
            if size == MULTIPART_MAX && !(200..300).contains(&raw.status) {
                return Ok(ProbeOutcome::Fail(format!(
                    "a multipart upload of MULTIPART_MAX ({size} bytes) answered {}",
                    raw.status
                )));
            }
            seen.push(format!("{size} bytes → {}", raw.status));
        }
        Ok(ProbeOutcome::Pass(seen.join("; ")))
    }

    /// Row 13.
    async fn unfinished_visibility(&self) -> Result<ProbeOutcome, BackendError> {
        let id = self.id().await?;
        let granule = UPLOAD_GRANULE as usize;
        let data = Bytes::from(vec![13u8; 2 * granule]);
        let total = data.len() as u64;
        let init = self.initiate(&id, "probe-13", total).await?;
        if init.status != 200 {
            return Ok(ProbeOutcome::Fail(format!(
                "initiation answered {}",
                init.status
            )));
        }
        let session = Self::session_uri(&init)?;
        let first = self
            .session_put(&session, 0, data.slice(..granule), total)
            .await?;
        if first.status != 308 {
            return Ok(ProbeOutcome::Fail(format!(
                "the first part answered {}",
                first.status
            )));
        }
        let held = parse_range_header(header_text(&first.headers, &RANGE));
        if held == 0 || held > granule as u64 {
            return Ok(ProbeOutcome::Fail(format!(
                "after a part of {granule} bytes the session reports {held} bytes"
            )));
        }
        let listed = self.listed(&id).await?;
        let by_id = self.backend.stat(&id).await?.is_some();
        let rest = self
            .session_put(&session, held, data.slice(held as usize..), total)
            .await?;
        if !matches!(rest.status, 200 | 201) {
            return Ok(ProbeOutcome::Fail(format!(
                "the last part answered {}",
                rest.status
            )));
        }
        let note = format!(
            "while unfinished: files.list {}, files.get {}",
            if listed {
                "SHOWS it"
            } else {
                "does not show it"
            },
            if by_id {
                "finds it"
            } else {
                "does not find it"
            }
        );
        Ok(if listed {
            ProbeOutcome::Info(note)
        } else {
            ProbeOutcome::Pass(note)
        })
    }
}

fn line(id: u8, outcome: ProbeOutcome) -> ProbeLine {
    let question = ROWS
        .iter()
        .find(|(row, _)| *row == id)
        .map_or("", |(_, q)| *q);
    ProbeLine {
        id,
        question,
        outcome,
    }
}

fn skipped(why: String) -> Vec<ProbeLine> {
    ROWS.iter()
        .map(|(id, _)| line(*id, ProbeOutcome::Skipped(why.clone())))
        .collect()
}

/// Uses a throwaway folder, trashes it afterwards.
pub async fn run_probes(tokens: std::sync::Arc<TokenProvider>, cfg: DriveConfig) -> Vec<ProbeLine> {
    let backend = match DriveBackend::new(tokens, cfg) {
        Ok(backend) => backend,
        Err(e) => return skipped(format!("cannot set up the Drive client: {e}")),
    };
    let name = format!("{PROBE_PREFIX}{}", util::hex(&util::random::<4>()));
    let folder = async {
        let folder = backend.new_ids(1).await?.remove(0);
        backend
            .create_folder(&folder, &Handle::top(), &name)
            .await?;
        Ok::<_, BackendError>(folder)
    };
    let folder = match folder.await {
        Ok(folder) => folder,
        Err(e) => return skipped(format!("cannot create the probe folder: {e}")),
    };
    let probe = Probe {
        backend: &backend,
        folder,
    };
    let failed = |r: Result<ProbeOutcome, BackendError>| {
        r.unwrap_or_else(|e| ProbeOutcome::Fail(e.to_string()))
    };
    let mut lines = vec![
        line(6, failed(probe.conflict().await)),
        line(8, failed(probe.list_lag().await)),
        line(9, failed(probe.completion_fields().await)),
        line(10, failed(probe.generate_ids().await)),
        line(12, failed(probe.multipart_boundary().await)),
        line(13, failed(probe.unfinished_visibility().await)),
    ];
    if let Err(e) = backend.trash(&probe.folder).await {
        lines.push(ProbeLine {
            id: 0,
            question: "clean-up",
            outcome: ProbeOutcome::Info(format!(
                "could not trash the probe folder {name}: {e}; remove it in drive.google.com"
            )),
        });
    }
    lines
}
