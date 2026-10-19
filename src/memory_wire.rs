//! Lossless v2 wire consumer. Accounting stays on the backend's exact serialized
//! result; transport envelopes never become additional model-facing memory text.
use anyhow::{Context, Result, ensure};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::{BufReader, Seek, Write};
use std::os::unix::{
    fs::{DirBuilderExt, MetadataExt},
    io::{AsRawFd, FromRawFd},
};
use std::sync::{Arc, Mutex};
use uuid::Uuid;

/// Local request admission has a separate, metadata-only lock: capturing a
/// lifetime never waits for spool I/O. Transition entry/exit and final delivery
/// use this same lock, so a generation check cannot race result release.
#[derive(Default)]
pub(crate) struct ReadLifecycle(Mutex<ReadGeneration>);
#[derive(Default)]
struct ReadGeneration {
    generation: u64,
    transitions: usize,
}
pub(crate) struct ReadTransition(Arc<ReadLifecycle>);
impl Drop for ReadTransition {
    fn drop(&mut self) {
        let mut state = self.0.0.lock().unwrap_or_else(|e| e.into_inner());
        state.generation = state.generation.wrapping_add(1);
        state.transitions -= 1;
    }
}
#[derive(Clone)]
pub(crate) struct ReadLease {
    lifecycle: Arc<ReadLifecycle>,
    generation: u64,
    cancel: crate::fingerprint::Cancellation,
}
pub(crate) struct ReadAdmission {
    lease: ReadLease,
    permit: tokio::sync::OwnedSemaphorePermit,
    #[cfg(test)]
    hooks: ReadOwnerTestHooks,
}
pub(crate) struct ReadTarget {
    pub(crate) owner: crate::auth::BoundCredentialOwner,
    pub(crate) scope: String,
    pub(crate) arguments: Value,
}
#[cfg(test)]
#[derive(Default)]
struct ReadOwnerTestHooks {
    before_lock: Option<tokio::sync::oneshot::Sender<()>>,
    after_mutation: Option<(
        tokio::sync::oneshot::Sender<()>,
        std::sync::mpsc::Receiver<()>,
    )>,
}
impl ReadLifecycle {
    pub(crate) fn transition(self: &Arc<Self>) -> ReadTransition {
        let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
        state.generation = state.generation.wrapping_add(1);
        state.transitions += 1;
        ReadTransition(self.clone())
    }
    pub(crate) fn capture(
        self: &Arc<Self>,
        admission: Arc<tokio::sync::Semaphore>,
    ) -> Result<ReadAdmission> {
        let state = self.0.lock().unwrap_or_else(|e| e.into_inner());
        ensure!(
            state.transitions == 0,
            "PERSONA_MEMORY_READ_SEQUENCE_INVALID"
        );
        let permit = admission
            .try_acquire_owned()
            .context("PERSONA_MEMORY_READ_LIMIT")?;
        let cancel = crate::fingerprint::REQUEST_CANCELLATION
            .try_with(Clone::clone)
            .unwrap_or_default();
        Ok(ReadAdmission {
            lease: ReadLease {
                lifecycle: self.clone(),
                generation: state.generation,
                cancel,
            },
            permit,
            #[cfg(test)]
            hooks: ReadOwnerTestHooks::default(),
        })
    }
}
impl ReadLease {
    fn current<T>(&self, operation: impl FnOnce() -> Result<T>) -> Result<T> {
        let state = self.lifecycle.0.lock().unwrap_or_else(|e| e.into_inner());
        ensure!(
            state.transitions == 0 && state.generation == self.generation,
            "PERSONA_MEMORY_READ_SEQUENCE_INVALID"
        );
        ensure!(
            !self.cancel.is_canceled(),
            "PERSONA_MEMORY_READ_SEQUENCE_INVALID"
        );
        operation()
    }
    pub(crate) fn check(&self) -> Result<()> {
        self.current(|| Ok(()))
    }
}

/// A caller owns only cancellation and the final acknowledgement. The bounded
/// task owns the admission permit and every worker result until exact cleanup
/// finishes, including when this waiter is dropped before receiving a ticket.
pub(crate) struct ReadWaiter {
    result: tokio::sync::oneshot::Receiver<Result<Value>>,
    delivery: ReadDelivery,
}
pub(crate) struct ReadDelivery {
    lease: ReadLease,
    pages: Arc<Mutex<MemoryReadState>>,
    ticket: Arc<Mutex<Option<(ReadTicket, bool)>>>,
    accepted: Option<tokio::sync::oneshot::Sender<()>>,
}
impl Drop for ReadDelivery {
    fn drop(&mut self) {
        if self.accepted.is_some() {
            self.lease.cancel.cancel();
        }
    }
}
impl ReadDelivery {
    pub(crate) fn accept(mut self, result: Value) -> Result<Value> {
        // Lock order is always pages -> lifecycle. Transitions take lifecycle
        // only; no lock is held across an await. Returning the final Value is
        // the release linearization point, after all dispatch projections.
        let mut pages = self.pages.lock().map_err(|_| anyhow::anyhow!("INTERNAL"))?;
        let lease = self.lease.clone();
        lease.current(|| {
            let ticket = self
                .ticket
                .lock()
                .map_err(|_| anyhow::anyhow!("INTERNAL"))?;
            let (ticket, legacy) = ticket.as_ref().context("INTERNAL")?;
            if *legacy {
                pages.legacy_finish(ticket)?;
            } else {
                pages.publish(ticket)?;
            }
            self.accepted
                .take()
                .context("INTERNAL")?
                .send(())
                .map_err(|_| anyhow::anyhow!("INTERNAL"))?;
            Ok(result)
        })
    }
}
impl ReadWaiter {
    pub(crate) async fn ready(mut self) -> Result<(Value, ReadDelivery)> {
        let result = (&mut self.result).await.context("INTERNAL")??;
        Ok((result, self.delivery))
    }
}

#[derive(Clone)]
pub(crate) struct ReadOperation {
    pub(crate) lease: ReadLease,
    pages: Arc<Mutex<MemoryReadState>>,
    filesystem: crate::fingerprint::FingerprintService,
    transport_failed: Arc<std::sync::atomic::AtomicBool>,
}
impl ReadOperation {
    pub(crate) fn transport_failed(&self) {
        self.transport_failed
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }
    /// The request task, rather than its caller, awaits these workers. An
    /// uncancelled completion scope prevents the generic filesystem helper
    /// from discarding a newly mutated ticket on disconnect.
    async fn filesystem<T: Send + 'static>(
        &self,
        operation: impl FnOnce() -> Result<T> + Send + 'static,
    ) -> Result<T> {
        crate::fingerprint::REQUEST_CANCELLATION
            .scope(
                crate::fingerprint::Cancellation::default(),
                self.filesystem.filesystem(move |_| operation()),
            )
            .await
    }
    pub(crate) async fn finish(
        &self,
        ticket: ReadTicket,
        arguments: Value,
        result: Value,
        text: Option<String>,
    ) -> Result<()> {
        let pages = self.pages.clone();
        let lease = self.lease.clone();
        self.filesystem(move || {
            let mut pages = pages.lock().map_err(|_| anyhow::anyhow!("INTERNAL"))?;
            lease.check()?;
            pages.finish(
                &ticket,
                &arguments,
                &result,
                text.as_deref(),
                std::time::Instant::now(),
            )
        })
        .await
    }
    pub(crate) async fn invalidate_owner(&self, ticket: ReadTicket) -> Result<()> {
        let pages = self.pages.clone();
        self.filesystem(move || {
            pages
                .lock()
                .map_err(|_| anyhow::anyhow!("INTERNAL"))?
                .invalidate_owner(&ticket);
            Ok(())
        })
        .await
    }
}
impl ReadAdmission {
    pub(crate) fn spawn<F, Fut, Keep: Send + 'static>(
        self,
        pages: Arc<Mutex<MemoryReadState>>,
        filesystem: crate::fingerprint::FingerprintService,
        target: ReadTarget,
        keep: Keep,
        operation: F,
    ) -> ReadWaiter
    where
        F: FnOnce(ReadOperation, ReadTicket) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = Result<(Value, bool)>> + Send + 'static,
    {
        let (send, result) = tokio::sync::oneshot::channel();
        let ReadTarget {
            owner,
            scope,
            arguments,
        } = target;
        let (accepted, acknowledgement) = tokio::sync::oneshot::channel();
        let ticket = Arc::new(Mutex::new(None));
        let delivery = ReadDelivery {
            lease: self.lease.clone(),
            pages: pages.clone(),
            ticket: ticket.clone(),
            accepted: Some(accepted),
        };
        let waiter = ReadWaiter { result, delivery };
        let request = ReadOperation {
            lease: self.lease,
            pages: pages.clone(),
            filesystem,
            transport_failed: Arc::default(),
        };
        #[cfg(test)]
        let hooks = self.hooks;
        let reference = crate::fingerprint::REQUEST_REFERENCE
            .try_with(Clone::clone)
            .unwrap_or_else(|_| Uuid::new_v4().to_string());
        tokio::spawn(
            crate::fingerprint::REQUEST_REFERENCE.scope(reference, async move {
                let _keep = keep;
                let _permit = self.permit;
                let worker_pages = pages.clone();
                let lease = request.lease.clone();
                let begun = request
                    .filesystem(move || {
                        #[cfg(test)]
                        if let Some(entered) = hooks.before_lock {
                            let _ = entered.send(());
                        }
                        let mut pages = worker_pages
                            .lock()
                            .map_err(|_| anyhow::anyhow!("INTERNAL"))?;
                        let result = pages.begin_leased(
                            &lease,
                            owner,
                            scope,
                            &arguments,
                            std::time::Instant::now(),
                        );
                        drop(pages);
                        #[cfg(test)]
                        if let Some((mutated, resume)) = hooks.after_mutation {
                            let _ = mutated.send(());
                            let _ = resume.recv();
                        }
                        result
                    })
                    .await;
                let begun = match begun {
                    Ok(ticket) => ticket,
                    Err(error) => {
                        let _ = send.send(Err(error));
                        return;
                    }
                };
                let prepared = match request.lease.check() {
                    Ok(()) => operation(request.clone(), begun.clone()).await,
                    Err(error) => Err(error),
                };
                let accepted = match prepared {
                    Ok((value, legacy)) => {
                        *ticket.lock().unwrap_or_else(|e| e.into_inner()) =
                            Some((begun.clone(), legacy));
                        send.send(Ok(value)).is_ok() && acknowledgement.await.is_ok()
                    }
                    Err(error) => {
                        // Ordinary transport failures preserve a valid cursor. A
                        // canceled/stale request disposes only its exact serial.
                        let release = request
                            .transport_failed
                            .load(std::sync::atomic::Ordering::SeqCst)
                            && request.lease.check().is_ok();
                        let cleanup = request.clone();
                        let cleanup_ticket = begun.clone();
                        let settled = cleanup
                            .filesystem(move || {
                                let mut pages =
                                    pages.lock().map_err(|_| anyhow::anyhow!("INTERNAL"))?;
                                if release {
                                    pages.release(&cleanup_ticket);
                                } else {
                                    pages.abort(&cleanup_ticket);
                                }
                                Ok(())
                            })
                            .await;
                        let _ = send.send(settled.and(Err(error)));
                        return;
                    }
                };
                if !accepted {
                    let _ = request
                        .filesystem(move || {
                            pages
                                .lock()
                                .map_err(|_| anyhow::anyhow!("INTERNAL"))?
                                .abort(&begun);
                            Ok(())
                        })
                        .await;
                }
            }),
        );
        waiter
    }
}

const V2: &str = "ai.persona-memory/v2";
const INVALID: &str = "PERSONA_MEMORY_RESPONSE_INVALID";

pub(crate) fn canonical_result(data: &str) -> Result<String> {
    let envelope: HashMap<String, Box<serde_json::value::RawValue>> = serde_json::from_str(data)?;
    Ok(envelope.get("result").context(INVALID)?.get().into())
}
fn number(value: &Value) -> Result<u64> {
    value.as_u64().context(INVALID)
}
fn uuid(value: &Value) -> Result<()> {
    Uuid::parse_str(value.as_str().context(INVALID)?).context(INVALID)?;
    Ok(())
}
fn checksum(value: &Value) -> Result<&str> {
    let text = value.as_str().context(INVALID)?;
    ensure!(
        text.len() == 64
            && text
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
        INVALID
    );
    Ok(text)
}
pub(crate) fn validate_result(operation: &str, value: &Value, text: &str) -> Result<()> {
    ensure!(serde_json::from_str::<Value>(text)? == *value, INVALID);
    ensure!(
        value["ok"].is_boolean() && value["schemaVersion"] == V2,
        INVALID
    );
    ensure!(
        value["tool"] == format!("person_memory.{operation}"),
        INVALID
    );
    let budget = &value["budget"];
    ensure!(
        budget.as_object().is_some_and(|o| {
            o.len() == 3
                && o.keys().all(|key| {
                    ["accountingContract", "maxTokens", "maxBytes"].contains(&key.as_str())
                })
        }),
        INVALID
    );
    let (tokens, bytes) = if operation == "read" {
        (2048, 16384)
    } else {
        (4096, 32768)
    };
    ensure!(
        budget["accountingContract"] == "o200k_base/v1"
            && (1..=tokens).contains(&number(&budget["maxTokens"])?)
            && (1..=bytes).contains(&number(&budget["maxBytes"])?)
            && text.len() as u64 <= number(&budget["maxBytes"])?,
        INVALID
    );
    if value["ok"] == false {
        ensure!(
            value.as_object().is_some_and(|o| o.len() == 5
                && o.keys()
                    .all(|key| ["ok", "tool", "schemaVersion", "error", "budget"]
                        .contains(&key.as_str())))
                && value["error"]
                    == "Persona memory operation was rejected; inspect current context and policy.",
            INVALID
        );
        return Ok(());
    }
    let allowed = match operation {
        "search" => &[
            "ok",
            "tool",
            "schemaVersion",
            "memoryIds",
            "items",
            "snapshotId",
            "omittedCount",
            "truncated",
            "budget",
            "sourceWork",
        ][..],
        "read" => &[
            "ok",
            "tool",
            "schemaVersion",
            "memoryId",
            "revision",
            "page",
            "budget",
        ][..],
        "write" | "update" => &["ok", "tool", "schemaVersion", "memory", "budget"][..],
        _ => anyhow::bail!(INVALID),
    };
    ensure!(
        value
            .as_object()
            .is_some_and(|o| o.keys().all(|key| allowed.contains(&key.as_str()))),
        INVALID
    );
    match operation {
        "search" => {
            let items = value["items"].as_array().context(INVALID)?;
            let ids = value["memoryIds"].as_array().context(INVALID)?;
            ensure!(
                ids.len() == items.len() && value["truncated"].is_boolean(),
                INVALID
            );
            number(&value["omittedCount"])?;
            let mut seen = std::collections::HashSet::new();
            for (item, id) in items.iter().zip(ids) {
                uuid(id)?;
                ensure!(
                    item["id"] == *id && seen.insert(id.as_str().unwrap()),
                    INVALID
                );
                number(&item["revision"])?;
                let start = number(&item["passageStart"])?;
                let end = number(&item["passageEnd"])?;
                ensure!(
                    end >= start
                        && end - start
                            == item["matchedPassage"]
                                .as_str()
                                .context(INVALID)?
                                .chars()
                                .count() as u64,
                    INVALID
                );
                if let Some(source) = item.get("source") {
                    validate_source(source)?;
                }
            }
            if let Some(work) = value.get("sourceWork") {
                ensure!(
                    work["limited"].is_boolean()
                        && (work["limited"] != true || value["truncated"] == true),
                    INVALID
                );
                for (key, max) in [
                    ("maxArtifactBytes", 4194304),
                    ("maxTextBytes", 4194304),
                    ("maxArtifacts", 8),
                ] {
                    ensure!(number(&work[key])? <= max, INVALID);
                }
            }
        }
        "read" => {
            uuid(&value["memoryId"])?;
            number(&value["revision"])?;
            let page = &value["page"];
            let start = number(&page["start"])?;
            let end = number(&page["end"])?;
            let total = number(&page["totalChars"])?;
            let fragment = page["text"].as_str().context(INVALID)?;
            ensure!(
                page["encoding"] == "application/json; fragment=unicode-codepoints"
                    && end >= start
                    && end <= total
                    && end - start == fragment.chars().count() as u64
                    && (end > start || total == 0),
                INVALID
            );
            checksum(&page["documentSha256"])?;
            if page["complete"] == true {
                ensure!(end == total && page["nextCursor"].is_null(), INVALID);
            } else {
                ensure!(
                    page["complete"] == false
                        && end < total
                        && page["nextCursor"]
                            .as_str()
                            .is_some_and(|cursor| !cursor.is_empty() && cursor.len() <= 16384),
                    INVALID
                );
            }
        }
        "write" | "update" => {
            let memory = &value["memory"];
            ensure!(
                memory.as_object().is_some_and(|o| o.len() == 3
                    && o.keys()
                        .all(|key| ["id", "type", "status"].contains(&key.as_str()))),
                INVALID
            );
            uuid(&memory["id"])?;
            ensure!(
                [
                    "artifact_reference",
                    "constraint",
                    "decision",
                    "fact",
                    "interaction_summary",
                    "preference",
                    "relationship_context"
                ]
                .contains(&memory["type"].as_str().context(INVALID)?)
                    && memory["status"].is_string(),
                INVALID
            );
        }
        _ => anyhow::bail!(INVALID),
    }
    Ok(())
}
fn validate_source(source: &Value) -> Result<()> {
    ensure!(
        source["type"].is_string() && source["id"].is_string(),
        INVALID
    );
    checksum(&source["checksum"])?;
    for key in ["artifactId", "artifactVersionId"] {
        if !source[key].is_null() {
            uuid(&source[key])?;
        }
    }
    Ok(())
}

#[derive(Default)]
pub(crate) struct ReadPages {
    documents: HashMap<String, Document>,
}
struct Document {
    revision: Value,
    checksum: String,
    total: u64,
    end: u64,
    cursor: String,
    spool: std::fs::File,
    hash: Sha256,
    bytes: u64,
}
impl ReadPages {
    /// Retain only an explicitly requested document. No page is fetched or injected
    /// automatically, and incomplete JSON is never interpreted as a memory record.
    pub(crate) fn is_empty(&self) -> bool {
        self.documents.is_empty()
    }
    pub(crate) fn retained_bytes(&self) -> usize {
        self.documents
            .values()
            .map(|d| d.cursor.capacity() + d.checksum.capacity() + std::mem::size_of::<Document>())
            .sum()
    }
    pub(crate) fn disk_bytes(&self) -> u64 {
        self.documents.values().map(|d| d.bytes).sum()
    }
    pub(crate) fn discard(&mut self, arguments: &Value) {
        if let Some(id) = arguments["memoryId"].as_str() {
            self.documents.remove(id);
        }
    }
    pub(crate) fn accept_checked(
        &mut self,
        arguments: &Value,
        value: &Value,
        text: &str,
    ) -> Result<()> {
        if let Err(error) = validate_result("read", value, text) {
            self.discard(arguments);
            return Err(error);
        }
        self.accept(arguments, value)
    }
    pub(crate) fn document_count(&self) -> usize {
        self.documents.len()
    }
    pub(crate) fn accept(&mut self, arguments: &Value, value: &Value) -> Result<()> {
        if value["ok"] != true {
            return Ok(());
        }
        let id = value["memoryId"].as_str().context(INVALID)?.to_owned();
        ensure!(arguments["memoryId"] == id, INVALID);
        let page = &value["page"];
        let start = number(&page["start"])?;
        let mut document = if start == 0 {
            ensure!(
                arguments.get("cursor").is_none() || arguments["cursor"].is_null(),
                INVALID
            );
            ensure!(
                self.documents.len() < 16 || self.documents.contains_key(&id),
                "PERSONA_MEMORY_READ_LIMIT"
            );
            // Explicit restart discards the old anonymous descriptor even when
            // opening its replacement fails.
            self.documents.remove(&id);
            Document {
                revision: value["revision"].clone(),
                checksum: checksum(&page["documentSha256"])?.into(),
                total: number(&page["totalChars"])?,
                end: 0,
                cursor: String::new(),
                spool: anonymous_spool()?,
                hash: Sha256::new(),
                bytes: 0,
            }
        } else {
            self.documents
                .remove(&id)
                .context("PERSONA_MEMORY_READ_SEQUENCE_INVALID")?
        };
        ensure!(
            document.end == start
                && document.revision == value["revision"]
                && document.checksum == checksum(&page["documentSha256"])?
                && document.total == number(&page["totalChars"])?
                && (start == 0 || arguments["cursor"] == document.cursor),
            "PERSONA_MEMORY_READ_SEQUENCE_INVALID"
        );
        let fragment = page["text"].as_str().context(INVALID)?;
        document.bytes = document
            .bytes
            .checked_add(fragment.len() as u64)
            .context("PERSONA_MEMORY_READ_LIMIT")?;
        // Operational disk resource limits, separate from each wire page's
        // accounting budget. No complete document is retained in process RAM.
        ensure!(
            document.bytes <= 64 * 1024 * 1024
                && self.disk_bytes() + document.bytes <= 256 * 1024 * 1024,
            "PERSONA_MEMORY_READ_LIMIT"
        );
        document
            .spool
            .write_all(fragment.as_bytes())
            .context("PERSONA_MEMORY_READ_LIMIT")?;
        document.hash.update(fragment.as_bytes());
        document.end = number(&page["end"])?;
        if page["complete"] == true {
            ensure!(
                document.end == document.total
                    && hex::encode(document.hash.finalize()) == document.checksum,
                "PERSONA_MEMORY_CHECKSUM_MISMATCH"
            );
            document
                .spool
                .rewind()
                .context("PERSONA_MEMORY_READ_LIMIT")?;
            // The canonical backend authorizes and validates artifact source pins
            // and source bytes. The consumer verifies every returned document byte,
            // full JSON grammar, and its requested root identity/revision. Ignored
            // values are streamed, including escaped source and parent content.
            #[derive(serde::Deserialize)]
            struct Identity {
                id: Uuid,
                revision: u64,
            }
            let mut decoder = serde_json::Deserializer::from_reader(BufReader::new(document.spool));
            let decoded: Identity =
                serde::Deserialize::deserialize(&mut decoder).context(INVALID)?;
            decoder.end().context(INVALID)?;
            ensure!(
                decoded.id.to_string() == id
                    && json_revision(decoded.revision) == document.revision,
                INVALID
            );
        } else {
            document.cursor = page["nextCursor"].as_str().context(INVALID)?.into();
            self.documents.insert(id.clone(), document);
            if self.disk_bytes() > 256 * 1024 * 1024 {
                self.documents.remove(&id);
                anyhow::bail!("PERSONA_MEMORY_READ_LIMIT");
            }
        }
        Ok(())
    }
}

fn json_revision(revision: u64) -> Value {
    Value::from(revision)
}

/// Anonymous owner-only spool. All callers perform this blocking operation in a
/// blocking worker. Unlink must succeed before any private content is written.
fn anonymous_spool() -> Result<std::fs::File> {
    use std::ffi::CString;
    let uid = unsafe { libc::geteuid() };
    let directory = std::path::PathBuf::from(format!("/tmp/loomex-persona-memory-{uid}"));
    match std::fs::DirBuilder::new().mode(0o700).create(&directory) {
        Ok(()) => (),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => (),
        Err(_) => anyhow::bail!("PERSONA_MEMORY_READ_LIMIT"),
    }
    let name = CString::new(directory.as_os_str().as_encoded_bytes())?;
    let fd = unsafe {
        libc::open(
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    ensure!(fd >= 0, "PERSONA_MEMORY_READ_LIMIT");
    let directory = unsafe { std::fs::File::from_raw_fd(fd) };
    let metadata = directory.metadata().context("PERSONA_MEMORY_READ_LIMIT")?;
    ensure!(
        metadata.is_dir() && metadata.uid() == uid && metadata.mode() & 0o777 == 0o700,
        "PERSONA_MEMORY_READ_LIMIT"
    );
    let name = CString::new(Uuid::new_v4().to_string())?;
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    ensure!(fd >= 0, "PERSONA_MEMORY_READ_LIMIT");
    let file = unsafe { std::fs::File::from_raw_fd(fd) };
    ensure!(
        unsafe { libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), 0) } == 0,
        "PERSONA_MEMORY_READ_LIMIT"
    );
    let metadata = file.metadata().context("PERSONA_MEMORY_READ_LIMIT")?;
    ensure!(
        metadata.is_file()
            && metadata.uid() == uid
            && metadata.mode() & 0o777 == 0o600
            && metadata.nlink() == 0,
        "PERSONA_MEMORY_READ_LIMIT"
    );
    Ok(file)
}

/// Ephemeral daemon chat state. Every mutation, eviction and descriptor disposal
/// is called only by the existing bounded filesystem owner.
#[derive(Default)]
pub(crate) struct MemoryReadState {
    epoch: u64,
    admission_generation: Option<u64>,
    serial: u64,
    owner: Option<crate::auth::BoundCredentialOwner>,
    contexts: HashMap<String, ChatReadContext>,
    in_flight: HashMap<(String, String), (u64, bool)>,
}
struct ChatReadContext {
    pages: ReadPages,
    touched: std::time::Instant,
}
#[derive(Clone)]
pub(crate) struct ReadTicket {
    epoch: u64,
    serial: u64,
    scope: String,
    memory: String,
    owner: crate::auth::BoundCredentialOwner,
}
impl MemoryReadState {
    fn begin_leased(
        &mut self,
        lease: &ReadLease,
        owner: crate::auth::BoundCredentialOwner,
        scope: String,
        arguments: &Value,
        now: std::time::Instant,
    ) -> Result<ReadTicket> {
        lease.check()?;
        // A transition canceled before its disposal worker was submitted still
        // invalidates old cursors. Disposal remains lazy and bounded by this
        // existing worker; an old lease never resets a replacement generation.
        if self.admission_generation != Some(lease.generation) {
            self.invalidate();
        }
        let result = self.begin(owner, scope, arguments, now);
        self.admission_generation = Some(lease.generation);
        result
    }
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.contexts.len()
    }
    #[cfg(test)]
    pub(crate) fn is_empty(&self) -> bool {
        self.contexts.is_empty() && self.in_flight.is_empty()
    }
    pub(crate) fn invalidate(&mut self) {
        self.epoch = self.epoch.wrapping_add(1);
        self.contexts.clear();
        self.in_flight.clear();
        self.owner = None;
    }
    pub(crate) fn invalidate_owner(&mut self, ticket: &ReadTicket) {
        if self.epoch == ticket.epoch && self.owner.as_ref() == Some(&ticket.owner) {
            self.invalidate();
        }
    }
    fn evict(&mut self, scope: &str) {
        self.contexts.remove(scope);
        self.in_flight
            .retain(|(candidate, _), _| candidate != scope);
    }
    fn oldest(&self, except: &str) -> Option<String> {
        self.contexts
            .iter()
            .filter(|(scope, _)| scope.as_str() != except)
            .min_by_key(|(_, state)| state.touched)
            .map(|(scope, _)| scope.clone())
    }
    pub(crate) fn begin(
        &mut self,
        owner: crate::auth::BoundCredentialOwner,
        scope: String,
        arguments: &Value,
        now: std::time::Instant,
    ) -> Result<ReadTicket> {
        if self.owner.as_ref() != Some(&owner) {
            self.invalidate();
            self.owner = Some(owner.clone());
        }
        let stale: Vec<_> = self
            .contexts
            .iter()
            .filter(|(_, context)| {
                now.saturating_duration_since(context.touched)
                    >= std::time::Duration::from_secs(15 * 60)
            })
            .map(|(scope, _)| scope.clone())
            .collect();
        for scope in stale {
            self.evict(&scope);
        }
        let memory = arguments["memoryId"].as_str().context(INVALID)?;
        Uuid::parse_str(memory).context(INVALID)?; // Bound retained request identities by the existing UUID contract.
        let memory = memory.to_owned();
        let key = (scope.clone(), memory.clone());
        let first = arguments.get("cursor").is_none_or(Value::is_null);
        if !first {
            ensure!(
                !self.in_flight.contains_key(&key),
                "PERSONA_MEMORY_READ_SEQUENCE_INVALID"
            );
            let context = self
                .contexts
                .get(&scope)
                .context("PERSONA_MEMORY_READ_SEQUENCE_INVALID")?;
            let document = context
                .pages
                .documents
                .get(&memory)
                .context("PERSONA_MEMORY_READ_SEQUENCE_INVALID")?;
            ensure!(
                arguments["cursor"] == document.cursor,
                "PERSONA_MEMORY_READ_SEQUENCE_INVALID"
            );
        } else {
            // An explicit restart invalidates the pending old request as well as
            // its partial bytes. Late responses may never overwrite the restart.
            self.in_flight.remove(&key);
            if let Some(context) = self.contexts.get_mut(&scope) {
                context.pages.discard(arguments);
            }
            if !self.contexts.contains_key(&scope) && self.contexts.len() >= 64 {
                let oldest = self.oldest(&scope).context("PERSONA_MEMORY_READ_LIMIT")?;
                self.evict(&oldest);
            }
            if self
                .contexts
                .values()
                .map(|c| c.pages.document_count())
                .sum::<usize>()
                >= 64
            {
                let oldest = self.oldest(&scope).context("PERSONA_MEMORY_READ_LIMIT")?;
                self.evict(&oldest);
            }
        }
        ensure!(
            self.in_flight.len() < 64
                && self.in_flight.keys().filter(|(s, _)| s == &scope).count() < 16,
            "PERSONA_MEMORY_READ_LIMIT"
        );
        let context = self
            .contexts
            .entry(scope.clone())
            .or_insert_with(|| ChatReadContext {
                pages: ReadPages::default(),
                touched: now,
            });
        context.touched = now;
        self.serial = self
            .serial
            .checked_add(1)
            .context("PERSONA_MEMORY_READ_LIMIT")?;
        self.in_flight.insert(key, (self.serial, false));
        Ok(ReadTicket {
            epoch: self.epoch,
            serial: self.serial,
            scope,
            memory,
            owner,
        })
    }
    fn matches(&self, ticket: &ReadTicket) -> bool {
        self.epoch == ticket.epoch
            && self.owner.as_ref() == Some(&ticket.owner)
            && self
                .in_flight
                .get(&(ticket.scope.clone(), ticket.memory.clone()))
                .is_some_and(|(serial, _)| *serial == ticket.serial)
    }
    pub(crate) fn release(&mut self, ticket: &ReadTicket) {
        if !self.matches(ticket) {
            return;
        }
        self.in_flight
            .remove(&(ticket.scope.clone(), ticket.memory.clone()));
        self.remove_empty(&ticket.scope);
    }
    pub(crate) fn legacy_finish(&mut self, ticket: &ReadTicket) -> Result<()> {
        ensure!(self.matches(ticket), "PERSONA_MEMORY_READ_SEQUENCE_INVALID");
        self.release(ticket);
        Ok(())
    }
    pub(crate) fn abort(&mut self, ticket: &ReadTicket) {
        if !self.matches(ticket) {
            return;
        }
        self.in_flight
            .remove(&(ticket.scope.clone(), ticket.memory.clone()));
        if let Some(context) = self.contexts.get_mut(&ticket.scope) {
            context.pages.documents.remove(&ticket.memory);
        }
        self.remove_empty(&ticket.scope);
    }
    fn remove_empty(&mut self, scope: &str) {
        if !self
            .in_flight
            .keys()
            .any(|(candidate, _)| candidate == scope)
            && self.contexts.get(scope).is_some_and(|c| c.pages.is_empty())
        {
            self.contexts.remove(scope);
        }
    }
    pub(crate) fn finish(
        &mut self,
        ticket: &ReadTicket,
        arguments: &Value,
        result: &Value,
        canonical: Option<&str>,
        now: std::time::Instant,
    ) -> Result<()> {
        ensure!(self.matches(ticket), "PERSONA_MEMORY_READ_SEQUENCE_INVALID");
        let accepted = (|| {
            let text = canonical.context(INVALID)?;
            validate_result("read", result, text)?;
            if result["ok"] == true {
                let disk = self
                    .contexts
                    .values()
                    .map(|c| c.pages.disk_bytes())
                    .sum::<u64>();
                let bytes = result["page"]["text"].as_str().context(INVALID)?.len() as u64;
                ensure!(
                    disk + bytes <= 512 * 1024 * 1024,
                    "PERSONA_MEMORY_READ_LIMIT"
                );
                self.contexts
                    .get_mut(&ticket.scope)
                    .context("PERSONA_MEMORY_READ_SEQUENCE_INVALID")?
                    .pages
                    .accept_checked(arguments, result, text)?;
                ensure!(
                    self.contexts
                        .values()
                        .map(|c| c.pages.document_count())
                        .sum::<usize>()
                        <= 64
                        && self
                            .contexts
                            .values()
                            .map(|c| c.pages.retained_bytes())
                            .sum::<usize>()
                            <= 16 * 1024 * 1024,
                    "PERSONA_MEMORY_READ_LIMIT"
                );
            }
            Ok(())
        })();
        if accepted.is_err() {
            self.abort(ticket);
            return accepted;
        }
        self.contexts.get_mut(&ticket.scope).unwrap().touched = now;
        self.in_flight
            .get_mut(&(ticket.scope.clone(), ticket.memory.clone()))
            .unwrap()
            .1 = true;
        Ok(())
    }
    /// Called after the post-worker auth fence immediately before publication.
    /// No file I/O or descriptor disposal occurs here: empty contexts have no file.
    pub(crate) fn publish(&mut self, ticket: &ReadTicket) -> Result<()> {
        ensure!(
            self.matches(ticket)
                && self
                    .in_flight
                    .get(&(ticket.scope.clone(), ticket.memory.clone()))
                    .unwrap()
                    .1,
            "PERSONA_MEMORY_READ_SEQUENCE_INVALID"
        );
        self.in_flight
            .remove(&(ticket.scope.clone(), ticket.memory.clone()));
        self.remove_empty(&ticket.scope);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    struct MaintenanceOwner {
        lifecycle: Arc<ReadLifecycle>,
        pages: Arc<Mutex<MemoryReadState>>,
        slots: Arc<tokio::sync::Semaphore>,
        filesystem: crate::fingerprint::FingerprintService,
    }
    struct MaintenanceDone(Option<tokio::sync::oneshot::Sender<()>>);
    impl Drop for MaintenanceDone {
        fn drop(&mut self) {
            let _ = self.0.take().unwrap().send(());
        }
    }
    impl MaintenanceOwner {
        fn new() -> Self {
            Self {
                lifecycle: Arc::default(),
                pages: Arc::default(),
                slots: Arc::new(tokio::sync::Semaphore::new(64)),
                filesystem: Default::default(),
            }
        }
        fn admit(&self) -> ReadAdmission {
            self.lifecycle.capture(self.slots.clone()).unwrap()
        }
        fn start<F, Fut>(
            &self,
            admission: ReadAdmission,
            scope: &str,
            index: usize,
            operation: F,
        ) -> (ReadWaiter, tokio::sync::oneshot::Receiver<()>)
        where
            F: FnOnce(ReadOperation, ReadTicket) -> Fut + Send + 'static,
            Fut: std::future::Future<Output = Result<(Value, bool)>> + Send + 'static,
        {
            let (send, done) = tokio::sync::oneshot::channel();
            let waiter = admission.spawn(
                self.pages.clone(),
                self.filesystem.clone(),
                ReadTarget {
                    owner: chat_owner("inert"),
                    scope: scope.into(),
                    arguments: json!({"memoryId":format!("00000000-0000-4000-8000-{index:012}")}),
                },
                MaintenanceDone(Some(send)),
                operation,
            );
            (waiter, done)
        }
        async fn assert_restored(&self, done: tokio::sync::oneshot::Receiver<()>) {
            done.await.unwrap();
            assert!(self.pages.lock().unwrap().is_empty());
            assert_eq!(self.slots.available_permits(), 64);
            assert_eq!(self.filesystem.diagnostics()["inFlight"], 0);
        }
        async fn fresh_read(&self) {
            let (waiter, done) = self.start(self.admit(), "literal-scope", 1, |_, _| async {
                Ok((json!({"literal":"ready"}), true))
            });
            let (value, delivery) = waiter.ready().await.unwrap();
            assert_eq!(delivery.accept(value).unwrap(), json!({"literal":"ready"}));
            self.assert_restored(done).await;
        }
    }
    #[tokio::test]
    async fn maintenance_entry_lifetime_rejects_delayed_begin() {
        let owner = MaintenanceOwner::new();
        let admitted = owner.admit();
        let transition = owner.lifecycle.transition();
        owner.pages.lock().unwrap().invalidate();
        drop(transition);
        let phases = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let next = phases.clone();
        let (waiter, done) = owner.start(admitted, "literal-scope", 1, move |_, _| async move {
            next.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok((json!(null), true))
        });
        assert!(waiter.ready().await.is_err());
        owner.assert_restored(done).await;
        assert_eq!(phases.load(std::sync::atomic::Ordering::SeqCst), 0);
        owner.fresh_read().await;
    }
    #[test]
    fn maintenance_overlapping_failed_and_canceled_transitions_reopen_only_after_last_guard() {
        let owner = MaintenanceOwner::new();
        let stale = owner.admit();
        let one = owner.lifecycle.transition();
        let two = owner.lifecycle.transition();
        assert!(owner.lifecycle.capture(owner.slots.clone()).is_err());
        drop(one);
        assert!(owner.lifecycle.capture(owner.slots.clone()).is_err());
        drop(two);
        assert!(stale.lease.check().is_err());
        drop(stale);
        assert!(owner.admit().lease.check().is_ok());
        let accepted_receipt = json!({"literalReceipt":"already-accepted"});
        {
            let _failed = owner.lifecycle.transition();
            let _local_error: Result<()> = Err(anyhow::anyhow!("literal-failure"));
        }
        assert_eq!(
            accepted_receipt,
            json!({"literalReceipt":"already-accepted"})
        );
        assert!(owner.admit().lease.check().is_ok());
        assert_eq!(owner.slots.available_permits(), 64);
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn maintenance_cancellation_while_begin_waits_for_mutex() {
        let owner = MaintenanceOwner::new();
        let pages = owner.pages.clone();
        let (locked, locked_rx) = tokio::sync::oneshot::channel();
        let (unlock, unlock_rx) = std::sync::mpsc::channel();
        let holder = std::thread::spawn(move || {
            let _lock = pages.lock().unwrap();
            locked.send(()).unwrap();
            unlock_rx.recv().unwrap();
        });
        locked_rx.await.unwrap();
        let mut admission = owner.admit();
        let (before_lock, entered) = tokio::sync::oneshot::channel();
        admission.hooks.before_lock = Some(before_lock);
        let phases = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let next = phases.clone();
        let (waiter, done) = owner.start(admission, "literal-scope", 1, move |_, _| async move {
            next.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok((json!(null), true))
        });
        entered.await.unwrap();
        drop(waiter);
        assert_eq!(owner.slots.available_permits(), 63);
        unlock.send(()).unwrap();
        holder.join().unwrap();
        owner.assert_restored(done).await;
        assert_eq!(phases.load(std::sync::atomic::Ordering::SeqCst), 0);
        owner.fresh_read().await;
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn maintenance_dropped_begin_result_restores_capacity_and_retains_outstanding_io() {
        let owner = MaintenanceOwner::new();
        let mut admission = owner.admit();
        let (mutated, observed) = tokio::sync::oneshot::channel();
        let (resume, resume_rx) = std::sync::mpsc::channel();
        admission.hooks.after_mutation = Some((mutated, resume_rx));
        let phases = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let next = phases.clone();
        let (waiter, mut done) =
            owner.start(admission, "literal-scope", 1, move |_, _| async move {
                next.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Ok((json!(null), true))
            });
        observed.await.unwrap();
        assert_eq!(owner.pages.lock().unwrap().in_flight.len(), 1);
        drop(waiter);
        // A shutdown/drain owner stays live through outstanding I/O and rollback.
        assert!(matches!(
            done.try_recv(),
            Err(tokio::sync::oneshot::error::TryRecvError::Empty)
        ));
        assert_eq!(owner.slots.available_permits(), 63);
        assert_eq!(owner.filesystem.diagnostics()["activeWorkers"], 1);
        resume.send(()).unwrap();
        owner.assert_restored(done).await;
        assert_eq!(phases.load(std::sync::atomic::Ordering::SeqCst), 0);
        owner.fresh_read().await;
    }
    #[tokio::test]
    async fn maintenance_cancellation_after_ticket_handoff_and_after_result_handoff() {
        let owner = MaintenanceOwner::new();
        let (entered, reached) = tokio::sync::oneshot::channel();
        let (resume, resume_rx) = tokio::sync::oneshot::channel();
        let (waiter, done) = owner.start(
            owner.admit(),
            "literal-scope",
            1,
            move |request, _| async move {
                entered.send(()).unwrap();
                resume_rx.await.unwrap();
                request.lease.check()?;
                Ok((json!(null), true))
            },
        );
        reached.await.unwrap();
        drop(waiter);
        resume.send(()).unwrap();
        owner.assert_restored(done).await;
        let (waiter, done) = owner.start(owner.admit(), "literal-scope", 1, |_, _| async {
            Ok((json!(null), true))
        });
        let (_, delivery) = waiter.ready().await.unwrap();
        assert_eq!(owner.slots.available_permits(), 63);
        drop(delivery);
        owner.assert_restored(done).await;
        owner.fresh_read().await;
    }
    #[tokio::test]
    async fn maintenance_exact_serial_cleanup_preserves_replacement_and_unrelated_state() {
        let owner = MaintenanceOwner::new();
        let (entered, reached) = tokio::sync::oneshot::channel();
        let (resume, resume_rx) = tokio::sync::oneshot::channel();
        let (waiter, done) =
            owner.start(owner.admit(), "literal-scope", 1, move |_, _| async move {
                entered.send(()).unwrap();
                resume_rx.await.unwrap();
                Ok((json!(null), true))
            });
        reached.await.unwrap();
        let now = std::time::Instant::now();
        let args = json!({"memoryId":"00000000-0000-4000-8000-000000000001"});
        let other = json!({"memoryId":"00000000-0000-4000-8000-000000000002"});
        let (replacement, unrelated) = {
            let mut pages = owner.pages.lock().unwrap();
            (
                pages
                    .begin(chat_owner("inert"), "literal-scope".into(), &args, now)
                    .unwrap(),
                pages
                    .begin(chat_owner("inert"), "literal-scope".into(), &other, now)
                    .unwrap(),
            )
        };
        drop(waiter);
        resume.send(()).unwrap();
        done.await.unwrap();
        let mut pages = owner.pages.lock().unwrap();
        assert!(pages.matches(&replacement));
        assert!(pages.matches(&unrelated));
        assert_eq!(pages.in_flight.len(), 2);
        pages.abort(&replacement);
        pages.abort(&unrelated);
        assert!(pages.is_empty());
        assert_eq!(owner.slots.available_permits(), 64);
    }
    #[tokio::test]
    async fn maintenance_canceled_requests_restore_sixteen_and_sixty_four_limits() {
        let owner = MaintenanceOwner::new();
        for count in [16, 64, 16] {
            let reached = Arc::new(tokio::sync::Barrier::new(count + 1));
            let (resume, receiver) = tokio::sync::watch::channel(false);
            let mut pending = Vec::new();
            for index in 0..count {
                let barrier = reached.clone();
                let mut receiver = receiver.clone();
                pending.push(owner.start(
                    owner.admit(),
                    &format!("literal-scope-{}", index / 16),
                    index,
                    move |_, _| async move {
                        barrier.wait().await;
                        receiver.changed().await.unwrap();
                        Ok((json!(null), true))
                    },
                ));
            }
            reached.wait().await;
            assert_eq!(owner.pages.lock().unwrap().in_flight.len(), count);
            if count == 64 {
                assert!(owner.lifecycle.capture(owner.slots.clone()).is_err());
            } else {
                let (extra, done) =
                    owner.start(owner.admit(), "literal-scope-0", 999, |_, _| async {
                        panic!("per-context refusal must precede next phase")
                    });
                assert!(extra.ready().await.is_err());
                done.await.unwrap();
            }
            let mut completions = Vec::new();
            for (waiter, done) in pending {
                drop(waiter);
                completions.push(done);
            }
            resume.send(true).unwrap();
            for done in completions {
                done.await.unwrap();
            }
            assert!(owner.pages.lock().unwrap().is_empty());
            assert_eq!(owner.slots.available_permits(), 64);
            assert_eq!(owner.filesystem.diagnostics()["inFlight"], 0);
        }
        owner.fresh_read().await;
    }
    #[tokio::test]
    async fn maintenance_final_delivery_rejects_transition_and_preserves_typed_false_cursor() {
        let owner = MaintenanceOwner::new();
        let document =
            r#"{"id":"00000000-0000-4000-8000-000000000001","revision":4,"content":"literal"}"#;
        let mut first = page(document, 0, 20);
        first["memoryId"] = json!("00000000-0000-4000-8000-000000000001");
        let arguments = json!({"memoryId":first["memoryId"]});
        let args = arguments.clone();
        let (waiter, done) = owner.start(
            owner.admit(),
            "literal-scope",
            1,
            move |request, ticket| async move {
                request
                    .finish(ticket, args, first.clone(), Some(first.to_string()))
                    .await?;
                Ok((first, false))
            },
        );
        let (value, delivery) = waiter.ready().await.unwrap();
        delivery.accept(value).unwrap();
        done.await.unwrap();
        let refused = json!({"ok":false,"tool":"person_memory.read","schemaVersion":V2,
            "error":"Persona memory operation was rejected; inspect current context and policy.",
            "budget":{"accountingContract":"o200k_base/v1","maxTokens":2048,"maxBytes":16384}});
        let cursor = json!({"memoryId":arguments["memoryId"],"cursor":"opaque-cursor"});
        let (send, done) = tokio::sync::oneshot::channel();
        let text = refused.to_string();
        let waiter = owner.admit().spawn(
            owner.pages.clone(),
            owner.filesystem.clone(),
            ReadTarget {
                owner: chat_owner("inert"),
                scope: "literal-scope".into(),
                arguments: cursor.clone(),
            },
            MaintenanceDone(Some(send)),
            move |request, ticket| async move {
                request
                    .finish(ticket, cursor, refused.clone(), Some(text))
                    .await?;
                Ok((refused, false))
            },
        );
        let (value, delivery) = waiter.ready().await.unwrap();
        delivery.accept(value).unwrap();
        done.await.unwrap();
        assert_eq!(
            owner.pages.lock().unwrap().contexts["literal-scope"]
                .pages
                .document_count(),
            1
        );
        let (waiter, done) = owner.start(owner.admit(), "other-scope", 2, |_, _| async {
            Ok((json!({"literal":"must-not-release"}), true))
        });
        let (value, delivery) = waiter.ready().await.unwrap();
        let transition = owner.lifecycle.transition();
        assert!(delivery.accept(value).is_err());
        drop(transition);
        done.await.unwrap();
        assert_eq!(owner.slots.available_permits(), 64);
        assert_eq!(
            owner.pages.lock().unwrap().contexts["literal-scope"]
                .pages
                .document_count(),
            1
        );
        // Even if a transition was canceled before submitting disposal, a
        // fresh request cannot reuse a cursor retained in its old generation.
        let (send, done) = tokio::sync::oneshot::channel();
        let waiter = owner.admit().spawn(
            owner.pages.clone(),
            owner.filesystem.clone(),
            ReadTarget {
                owner: chat_owner("inert"),
                scope: "literal-scope".into(),
                arguments: json!({"memoryId":arguments["memoryId"],"cursor":"opaque-cursor"}),
            },
            MaintenanceDone(Some(send)),
            |_, _| async { panic!("old cursor must not reach next phase") },
        );
        assert!(waiter.ready().await.is_err());
        owner.assert_restored(done).await;
        owner.fresh_read().await;
    }
    #[tokio::test]
    async fn maintenance_aborted_transition_task_drops_its_admission_guard() {
        let owner = MaintenanceOwner::new();
        let stale = owner.admit();
        let lifecycle = owner.lifecycle.clone();
        let (entered, observed) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            let _transition = lifecycle.transition();
            entered.send(()).unwrap();
            std::future::pending::<()>().await;
        });
        observed.await.unwrap();
        assert!(owner.lifecycle.capture(owner.slots.clone()).is_err());
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert!(stale.lease.check().is_err());
        drop(stale);
        owner.fresh_read().await;
    }
    #[test]
    fn maintenance_release_and_transition_share_one_linearization_lock() {
        let owner = MaintenanceOwner::new();
        let admission = owner.admit();
        let lease = admission.lease.clone();
        let (entered, entered_rx) = std::sync::mpsc::channel();
        let (resume, resume_rx) = std::sync::mpsc::channel();
        let release = std::thread::spawn(move || {
            lease
                .current(|| {
                    entered.send(()).unwrap();
                    resume_rx.recv().unwrap();
                    Ok(json!({"literal":"released-under-generation-lock"}))
                })
                .unwrap()
        });
        entered_rx.recv().unwrap();
        assert!(owner.lifecycle.0.try_lock().is_err());
        let lifecycle = owner.lifecycle.clone();
        let (trying, trying_rx) = std::sync::mpsc::channel();
        let transition = std::thread::spawn(move || {
            trying.send(()).unwrap();
            lifecycle.transition()
        });
        trying_rx.recv().unwrap();
        resume.send(()).unwrap();
        assert_eq!(
            release.join().unwrap()["literal"],
            "released-under-generation-lock"
        );
        drop(transition.join().unwrap());
        assert!(admission.lease.check().is_err());
        drop(admission);
        assert!(owner.admit().lease.check().is_ok());
    }
    #[tokio::test]
    async fn maintenance_transport_failure_preserves_cursor_but_local_failure_aborts_it() {
        let owner = MaintenanceOwner::new();
        let document =
            r#"{"id":"00000000-0000-4000-8000-000000000001","revision":4,"content":"literal"}"#;
        let mut first = page(document, 0, 20);
        first["memoryId"] = json!("00000000-0000-4000-8000-000000000001");
        let arguments = json!({"memoryId":first["memoryId"]});
        let (waiter, done) = owner.start(
            owner.admit(),
            "literal-scope",
            1,
            move |request, ticket| async move {
                request
                    .finish(ticket, arguments, first.clone(), Some(first.to_string()))
                    .await?;
                Ok((first, false))
            },
        );
        let (value, delivery) = waiter.ready().await.unwrap();
        delivery.accept(value).unwrap();
        done.await.unwrap();
        for transport in [true, false] {
            let (send, done) = tokio::sync::oneshot::channel();
            let waiter = owner.admit().spawn(owner.pages.clone(), owner.filesystem.clone(),
                ReadTarget { owner: chat_owner("inert"), scope: "literal-scope".into(),
                    arguments: json!({"memoryId":"00000000-0000-4000-8000-000000000001", "cursor":"opaque-cursor"}) },
                MaintenanceDone(Some(send)), move |request, _| async move {
                    if transport { request.transport_failed(); }
                    Err(anyhow::anyhow!("literal-local-error"))
                });
            let error = match waiter.ready().await {
                Ok(_) => panic!("expected literal error"),
                Err(error) => error,
            };
            assert_eq!(error.to_string(), "literal-local-error");
            done.await.unwrap();
            assert_eq!(owner.slots.available_permits(), 64);
            let pages = owner.pages.lock().unwrap();
            assert!(pages.in_flight.is_empty());
            if transport {
                assert_eq!(pages.contexts["literal-scope"].pages.document_count(), 1);
            } else {
                assert!(pages.is_empty());
            }
        }
        owner.fresh_read().await;
    }
    fn page(document: &str, start: usize, end: usize) -> Value {
        let chars: Vec<char> = document.chars().collect();
        json!({"ok":true,"tool":"person_memory.read","schemaVersion":V2,"memoryId":"11111111-1111-4111-8111-111111111111","revision":4,"budget":{"accountingContract":"o200k_base/v1","maxTokens":2048,"maxBytes":16384},"page":{"text":chars[start..end].iter().collect::<String>(),"encoding":"application/json; fragment=unicode-codepoints","start":start,"end":end,"totalChars":chars.len(),"documentSha256":crate::state::digest(document.as_bytes()),"complete":end==chars.len(),"nextCursor":if end==chars.len(){Value::Null}else{json!("opaque-cursor")}}})
    }
    #[test]
    fn full_read_accepts_large_escaped_source_with_bounded_page_state() {
        // The optional file is an exact authorized backend formatter artifact used
        // by qualification; the default synthetic case protects the same boundary.
        let document = if let Ok(path) = std::env::var("LOOMEX_QA_CANONICAL_DOCUMENT") {
            std::fs::read_to_string(path).unwrap()
        } else {
            json!({"id":"11111111-1111-4111-8111-111111111111","revision":4,
                "content":"fixture","artifactSources":[{"type":"artifact","id":"source",
                "checksum":crate::state::digest(&vec![1;1024*1024]),
                "text":"\u{0001}".repeat(1024*1024)}]})
            .to_string()
        };
        let decoded: Value = serde_json::from_str(&document).unwrap();
        let id = decoded["id"].as_str().unwrap();
        let revision = decoded["revision"].as_u64().unwrap();
        assert!(document.len() > 4 * 1024 * 1024);
        assert!(document.is_ascii());
        let digest = crate::state::digest(document.as_bytes());
        let mut pages = ReadPages::default();
        for (index, fragment) in document.as_bytes().chunks(2048).enumerate() {
            let start = index * 2048;
            let end = start + fragment.len();
            let complete = end == document.len();
            let page = json!({"ok":true,"tool":"person_memory.read","schemaVersion":V2,
                "memoryId":id,"revision":revision,"budget":{"accountingContract":"o200k_base/v1","maxTokens":2048,"maxBytes":16384},
                "page":{"text":std::str::from_utf8(fragment).unwrap(),"encoding":"application/json; fragment=unicode-codepoints",
                "start":start,"end":end,"totalChars":document.len(),"documentSha256":digest,
                "complete":complete,"nextCursor":if complete{Value::Null}else{json!(format!("page-{end}"))}}});
            let args = if start == 0 {
                json!({"memoryId":id})
            } else {
                json!({"memoryId":id,"cursor":format!("page-{start}")})
            };
            validate_result("read", &page, &page.to_string()).unwrap();
            pages.accept(&args, &page).unwrap();
            assert!(
                pages.retained_bytes() < 32768,
                "only bounded cursor/hash/identity state retained in RAM"
            );
        }
        assert!(pages.is_empty());
    }
    #[allow(clippy::unnecessary_cast)] // Unix stat ABI aliases differ between macOS and Linux.
    fn assert_descriptor_closed_or_reused(fd: libc::c_int, original: &std::fs::Metadata) {
        // Other library tests may allocate the same numeric fd immediately after
        // close. Verify the original spool identity is absent, not global fd reuse.
        let mut current = std::mem::MaybeUninit::<libc::stat>::uninit();
        if unsafe { libc::fstat(fd, current.as_mut_ptr()) } == 0 {
            let current = unsafe { current.assume_init() };
            assert_ne!(
                (current.st_dev as u64, current.st_ino as u64),
                (original.dev(), original.ino())
            );
        }
    }
    #[test]
    fn anonymous_spool_is_private_unlinked_cloexec_and_closes_on_disposal() {
        let file = anonymous_spool().unwrap();
        let fd = file.as_raw_fd();
        let metadata = file.metadata().unwrap();
        assert_eq!(metadata.nlink(), 0);
        assert_eq!(metadata.mode() & 0o777, 0o600);
        assert_ne!(
            unsafe { libc::fcntl(fd, libc::F_GETFD) } & libc::FD_CLOEXEC,
            0
        );
        drop(file);
        assert_descriptor_closed_or_reused(fd, &metadata);
        let document =
            r#"{"id":"11111111-1111-4111-8111-111111111111","revision":4,"content":"cancel"}"#;
        let mut pages = ReadPages::default();
        pages
            .accept(
                &json!({"memoryId":"11111111-1111-4111-8111-111111111111"}),
                &page(document, 0, 20),
            )
            .unwrap();
        let fd = pages.documents.values().next().unwrap().spool.as_raw_fd();
        let metadata = pages
            .documents
            .values()
            .next()
            .unwrap()
            .spool
            .metadata()
            .unwrap();
        drop(pages); // MCP disposal/cancel closes an unfinished read.
        assert_descriptor_closed_or_reused(fd, &metadata);
    }
    #[test]
    fn complete_spooled_document_rejects_bad_json_identity_revision_and_trailing_data() {
        for text in [
            r#"{"id":"11111111-1111-4111-8111-111111111111","revision":4"#,
            r#"{"id":"22222222-2222-4222-8222-222222222222","revision":4}"#,
            r#"{"id":"11111111-1111-4111-8111-111111111111","revision":5}"#,
            r#"{"id":"11111111-1111-4111-8111-111111111111","revision":4}{}"#,
        ] {
            let mut pages = ReadPages::default();
            let value = page(text, 0, text.chars().count());
            assert!(
                pages
                    .accept(&json!({"memoryId":value["memoryId"]}), &value)
                    .is_err()
            );
            assert!(pages.is_empty());
        }
    }
    #[test]
    fn spooled_io_failure_discards_partial_document_and_cannot_report_completion() {
        let document =
            r#"{"id":"11111111-1111-4111-8111-111111111111","revision":4,"content":"failure"}"#;
        let mut pages = ReadPages::default();
        let first = page(document, 0, 20);
        pages
            .accept(&json!({"memoryId":first["memoryId"]}), &first)
            .unwrap();
        pages.documents.values_mut().next().unwrap().spool =
            std::fs::File::open("/dev/null").unwrap();
        let last = page(document, 20, document.chars().count());
        let result = pages.accept(
            &json!({"memoryId":last["memoryId"],"cursor":"opaque-cursor"}),
            &last,
        );
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("PERSONA_MEMORY_READ_LIMIT")
        );
        assert!(pages.is_empty());
    }
    #[tokio::test]
    async fn canceled_blocking_page_owner_retains_permit_until_spool_is_closed() {
        let service = crate::fingerprint::FingerprintService::default();
        let worker = service.clone();
        let (opened_tx, opened_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let (closed_tx, closed_rx) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            worker
                .filesystem(move |cancel| {
                    let file = anonymous_spool()?;
                    let fd = file.as_raw_fd();
                    opened_tx.send((fd, file.metadata().unwrap())).unwrap();
                    release_rx.recv().unwrap();
                    assert!(cancel.is_canceled());
                    drop(file);
                    closed_tx.send(()).unwrap();
                    Ok(())
                })
                .await
        });
        let (fd, metadata) = opened_rx.await.unwrap();
        task.abort();
        let _ = task.await;
        assert_eq!(service.diagnostics()["activeWorkers"], 1);
        assert_ne!(unsafe { libc::fcntl(fd, libc::F_GETFD) }, -1);
        release_tx.send(()).unwrap();
        closed_rx.await.unwrap();
        assert_descriptor_closed_or_reused(fd, &metadata);
        for _ in 0..100 {
            if service.diagnostics()["inFlight"] == 0 {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(service.diagnostics()["inFlight"], 0);
    }
    #[test]
    fn malformed_envelope_closes_requested_spool_but_typed_refusal_preserves_cursor() {
        let document =
            r#"{"id":"11111111-1111-4111-8111-111111111111","revision":4,"content":"partial"}"#;
        let mut pages = ReadPages::default();
        let first = page(document, 0, 20);
        let args = json!({"memoryId":first["memoryId"]});
        pages
            .accept_checked(&args, &first, &first.to_string())
            .unwrap();
        let fd = pages.documents.values().next().unwrap().spool.as_raw_fd();
        let metadata = pages
            .documents
            .values()
            .next()
            .unwrap()
            .spool
            .metadata()
            .unwrap();
        let rejected = json!({"ok":false,"tool":"person_memory.read","schemaVersion":V2,
            "error":"Persona memory operation was rejected; inspect current context and policy.",
            "budget":{"accountingContract":"o200k_base/v1","maxTokens":2048,"maxBytes":16384}});
        pages
            .accept_checked(&args, &rejected, &rejected.to_string())
            .unwrap();
        assert_eq!(pages.document_count(), 1);
        assert_ne!(unsafe { libc::fcntl(fd, libc::F_GETFD) }, -1);
        let mut malformed = page(document, 20, document.chars().count());
        malformed["page"]["nextCursor"] = json!("invalid completion cursor");
        assert!(
            pages
                .accept_checked(&args, &malformed, &malformed.to_string())
                .is_err()
        );
        assert!(pages.is_empty());
        assert_descriptor_closed_or_reused(fd, &metadata);
        let last = page(document, 20, document.chars().count());
        assert!(
            pages
                .accept_checked(
                    &json!({"memoryId":first["memoryId"],"cursor":"opaque-cursor"}),
                    &last,
                    &last.to_string()
                )
                .is_err()
        );
        pages
            .accept_checked(&args, &first, &first.to_string())
            .unwrap();
        pages
            .accept_checked(
                &json!({"memoryId":first["memoryId"],"cursor":"opaque-cursor"}),
                &last,
                &last.to_string(),
            )
            .unwrap();
        assert!(pages.is_empty());
    }
    fn chat_owner(account: &str) -> crate::auth::BoundCredentialOwner {
        crate::auth::BoundCredentialOwner {
            organization: "org".into(),
            account: account.into(),
            identity: crate::auth::CredentialIdentity {
                installation_id: "installation".into(),
                device_id: Some("device".into()),
            },
        }
    }
    #[test]
    fn chat_read_generations_reject_late_http_worker_and_duplicate_continuations_without_erasing_new_state()
     {
        let document = r#"{"id":"11111111-1111-4111-8111-111111111111","revision":4,"content":"fresh generations"}"#;
        let first = page(document, 0, 20);
        let last = page(document, 20, document.chars().count());
        let args = json!({"memoryId":first["memoryId"]});
        let next = json!({"memoryId":first["memoryId"],"cursor":"opaque-cursor"});
        let now = std::time::Instant::now();
        let mut state = MemoryReadState::default();
        let stale_first = state
            .begin(chat_owner("one"), "scope".into(), &args, now)
            .unwrap();
        state
            .finish(&stale_first, &args, &first, Some(&first.to_string()), now)
            .unwrap();
        let fresh_first = state
            .begin(chat_owner("one"), "scope".into(), &args, now)
            .unwrap();
        assert!(
            state
                .finish(&stale_first, &args, &first, Some(&first.to_string()), now)
                .is_err()
        );
        assert!(state.publish(&stale_first).is_err());
        state.abort(&stale_first);
        state
            .finish(&fresh_first, &args, &first, Some(&first.to_string()), now)
            .unwrap();
        state.publish(&fresh_first).unwrap();
        let old_continuation = state
            .begin(chat_owner("one"), "scope".into(), &next, now)
            .unwrap();
        assert!(
            state
                .begin(chat_owner("one"), "scope".into(), &next, now)
                .is_err()
        );
        let restarted = state
            .begin(chat_owner("one"), "scope".into(), &args, now)
            .unwrap();
        state
            .finish(&restarted, &args, &first, Some(&first.to_string()), now)
            .unwrap();
        state.publish(&restarted).unwrap();
        assert!(
            state
                .finish(
                    &old_continuation,
                    &next,
                    &last,
                    Some(&last.to_string()),
                    now
                )
                .is_err()
        );
        state.abort(&old_continuation);
        let current = state
            .begin(chat_owner("one"), "scope".into(), &next, now)
            .unwrap();
        state
            .finish(&current, &next, &last, Some(&last.to_string()), now)
            .unwrap();
        state.publish(&current).unwrap();
        assert!(state.is_empty());
        assert!(
            state
                .begin(chat_owner("one"), "scope".into(), &next, now)
                .is_err()
        );
    }
    #[test]
    fn chat_read_idle_lru_owner_epoch_and_inflight_limits_are_request_driven() {
        let document = r#"{"id":"11111111-1111-4111-8111-111111111111","revision":4,"content":"bounded eviction"}"#;
        let first = page(document, 0, 20);
        let args = json!({"memoryId":first["memoryId"]});
        let next = json!({"memoryId":first["memoryId"],"cursor":"opaque-cursor"});
        let now = std::time::Instant::now();
        let mut state = MemoryReadState::default();
        assert!(
            state
                .begin(
                    chat_owner("one"),
                    "scope".into(),
                    &json!({"memoryId":"x".repeat(1024*1024)}),
                    now
                )
                .is_err()
        );
        assert!(state.is_empty());
        let old = state
            .begin(chat_owner("one"), "old".into(), &args, now)
            .unwrap();
        for index in 1..64 {
            let time = now + std::time::Duration::from_millis(index);
            let ticket = state
                .begin(chat_owner("one"), format!("scope-{index}"), &args, time)
                .unwrap();
            state
                .finish(&ticket, &args, &first, Some(&first.to_string()), time)
                .unwrap();
            state.publish(&ticket).unwrap();
        }
        let newest = state
            .begin(
                chat_owner("one"),
                "newest".into(),
                &args,
                now + std::time::Duration::from_secs(1),
            )
            .unwrap();
        assert_eq!(state.len(), 64);
        assert!(
            state
                .finish(&old, &args, &first, Some(&first.to_string()), now)
                .is_err()
        );
        assert!(!state.contexts.contains_key("old"));
        state
            .finish(&newest, &args, &first, Some(&first.to_string()), now)
            .unwrap();
        state.publish(&newest).unwrap();
        let after_idle = now + std::time::Duration::from_secs(901);
        assert!(
            state
                .begin(chat_owner("one"), "newest".into(), &next, after_idle)
                .is_err()
        );
        assert!(state.is_empty());
        let invalidated = state
            .begin(chat_owner("one"), "scope".into(), &args, after_idle)
            .unwrap();
        state.invalidate();
        assert!(
            state
                .finish(
                    &invalidated,
                    &args,
                    &first,
                    Some(&first.to_string()),
                    after_idle
                )
                .is_err()
        );
        let replacement = state
            .begin(chat_owner("two"), "scope".into(), &args, after_idle)
            .unwrap();
        state.invalidate_owner(&invalidated);
        state
            .finish(
                &replacement,
                &args,
                &first,
                Some(&first.to_string()),
                after_idle,
            )
            .unwrap();
        state.publish(&replacement).unwrap();
        assert_eq!(state.len(), 1);
        // One context permits at most16 pending documents; a new scope can proceed.
        state.invalidate();
        for _ in 0..16 {
            let args = json!({"memoryId":Uuid::new_v4()});
            state
                .begin(chat_owner("one"), "scope".into(), &args, now)
                .unwrap();
        }
        assert!(
            state
                .begin(chat_owner("one"), "scope".into(), &args, now)
                .is_err()
        );
        state
            .begin(chat_owner("one"), "other".into(), &args, now)
            .unwrap();
    }
    #[test]
    fn malformed_chat_document_disposes_only_its_requested_partial() {
        let a = "11111111-1111-4111-8111-111111111111";
        let b = "22222222-2222-4222-8222-222222222222";
        let document = format!("{{\"id\":\"{a}\",\"revision\":4,\"content\":\"unrelated\"}}");
        let document_b = document.replace(a, b);
        let first_a = page(&document, 0, 20);
        let mut first_b = page(&document_b, 0, 20);
        first_b["memoryId"] = json!(b);
        let args_a = json!({"memoryId":a});
        let args_b = json!({"memoryId":b});
        let now = std::time::Instant::now();
        let mut state = MemoryReadState::default();
        for (args, value) in [(&args_a, &first_a), (&args_b, &first_b)] {
            let ticket = state
                .begin(chat_owner("one"), "scope".into(), args, now)
                .unwrap();
            state
                .finish(&ticket, args, value, Some(&value.to_string()), now)
                .unwrap();
            state.publish(&ticket).unwrap();
        }
        let next_a = json!({"memoryId":a,"cursor":"opaque-cursor"});
        let ticket = state
            .begin(chat_owner("one"), "scope".into(), &next_a, now)
            .unwrap();
        let mut malformed = page(&document, 20, document.chars().count());
        malformed["page"]["nextCursor"] = json!("not-complete");
        assert!(
            state
                .finish(
                    &ticket,
                    &next_a,
                    &malformed,
                    Some(&malformed.to_string()),
                    now
                )
                .is_err()
        );
        assert_eq!(state.contexts["scope"].pages.document_count(), 1);
        let next_b = json!({"memoryId":b,"cursor":"opaque-cursor"});
        let ticket = state
            .begin(chat_owner("one"), "scope".into(), &next_b, now)
            .unwrap();
        let mut last_b = page(&document_b, 20, document_b.chars().count());
        last_b["memoryId"] = json!(b);
        state
            .finish(&ticket, &next_b, &last_b, Some(&last_b.to_string()), now)
            .unwrap();
        state.publish(&ticket).unwrap();
        assert!(state.is_empty());
    }
    #[test]
    fn actual_backend_http_producer_contracts_and_strict_rejections() {
        let fixture: Value = serde_json::from_str(include_str!(
            "../tests/fixtures/persona-memory-v2-producer.json"
        ))
        .unwrap();
        for case in fixture["cases"].as_array().unwrap() {
            let operation = case["method"].as_str().unwrap();
            let result = &case["result"];
            validate_result(operation, result, case["canonicalText"].as_str().unwrap())
                .unwrap_or_else(|e| panic!("{}: {e}", case["name"]));
            if result["ok"] == false {
                for fault in ["tool", "raw_error", "extra", "extra_budget", "tiny"] {
                    let mut invalid = result.clone();
                    match fault {
                        "tool" => invalid["tool"] = json!("person_memory.other"),
                        "raw_error" => invalid["error"] = json!("private rejected content"),
                        "extra" => invalid["raw"] = json!("private rejected content"),
                        "extra_budget" => invalid["budget"]["raw"] = json!("private"),
                        "tiny" => invalid["budget"]["maxBytes"] = json!(1),
                        _ => unreachable!(),
                    }
                    assert!(
                        validate_result(operation, &invalid, &invalid.to_string()).is_err(),
                        "{} {fault}",
                        case["name"]
                    );
                }
            }
            if ["write", "update"].contains(&operation) && result["ok"] == true {
                let mut with_invented_revision = result.clone();
                with_invented_revision["memory"]["revision"] = json!(1);
                assert!(
                    validate_result(
                        operation,
                        &with_invented_revision,
                        &with_invented_revision.to_string()
                    )
                    .is_err()
                );
            }
        }
    }
    #[test]
    fn preserves_backend_key_order_unicode_and_escaping_in_final_text() {
        let raw = r#"{"result":{"z":"فارسی🙂\u2028","a":"\\\""}}"#;
        assert_eq!(
            canonical_result(raw).unwrap(),
            r#"{"z":"فارسی🙂\u2028","a":"\\\""}"#
        );
    }
    #[test]
    fn lossless_pages_require_exact_cursor_revision_contiguity_and_checksum() {
        let document = r#"{"id":"11111111-1111-4111-8111-111111111111","revision":4,"content":"فارسی🙂é\u2028"}"#;
        let split = 71;
        let len = document.chars().count();
        let first = page(document, 0, split);
        let last = page(document, split, len);
        let mut pages = ReadPages::default();
        let args = json!({"memoryId":first["memoryId"]});
        validate_result("read", &first, &first.to_string()).unwrap();
        pages.accept(&args, &first).unwrap();
        assert!(
            pages
                .accept(
                    &json!({"memoryId":first["memoryId"],"cursor":"wrong"}),
                    &last
                )
                .is_err()
        );
        pages.accept(&args, &first).unwrap();
        pages
            .accept(
                &json!({"memoryId":first["memoryId"],"cursor":"opaque-cursor"}),
                &last,
            )
            .unwrap();
        assert!(pages.documents.is_empty());
        assert!(
            pages
                .accept(
                    &json!({"memoryId":first["memoryId"],"cursor":"opaque-cursor"}),
                    &last
                )
                .is_err(),
            "a completed cursor cannot replay without an explicit new first page"
        );
        pages.accept(&args, &first).unwrap();
        pages.accept(&args, &first).unwrap(); // a new explicit read may restart its own partial document
        pages
            .accept(
                &json!({"memoryId":first["memoryId"],"cursor":"opaque-cursor"}),
                &last,
            )
            .unwrap();
        let mut tampered = page(document, 0, len);
        tampered["page"]["documentSha256"] = json!("0".repeat(64));
        assert!(pages.accept(&args, &tampered).is_err());
        let mut false_completion = last.clone();
        false_completion["page"]["nextCursor"] = json!("still-more");
        assert!(validate_result("read", &false_completion, &false_completion.to_string()).is_err());
    }
}
