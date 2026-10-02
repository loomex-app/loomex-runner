//! Fresh executable integrity checks. Only active work is shared; results are never cached.
use anyhow::{Result, bail};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::future::Future;
use std::{
    collections::{HashMap, VecDeque},
    fs::{File, Metadata, OpenOptions},
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    time::{Instant, UNIX_EPOCH},
};
use tokio::sync::{Notify, Semaphore, watch};

#[derive(Clone, Default)]
pub struct Cancellation(Arc<CancelState>);
#[derive(Default)]
struct CancelState {
    canceled: AtomicBool,
    notify: Notify,
}
impl Cancellation {
    pub fn cancel(&self) {
        self.0.canceled.store(true, Ordering::SeqCst);
        self.0.notify.notify_waiters();
    }
    pub fn is_canceled(&self) -> bool {
        self.0.canceled.load(Ordering::SeqCst)
    }
    async fn canceled(&self) {
        loop {
            let notified = self.0.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.is_canceled() {
                return;
            }
            notified.await;
        }
    }
}
tokio::task_local! { pub static REQUEST_CANCELLATION: Cancellation; pub static REQUEST_REFERENCE: String; }

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
struct Identity {
    dev: u64,
    ino: u64,
    size: u64,
    mtime: i64,
    mtime_ns: i64,
    ctime: i64,
    ctime_ns: i64,
    uid: u32,
    gid: u32,
    mode: u32,
}
impl Identity {
    fn read(m: &Metadata) -> Self {
        Self {
            dev: m.dev(),
            ino: m.ino(),
            size: m.len(),
            mtime: m.mtime(),
            mtime_ns: m.mtime_nsec(),
            ctime: m.ctime(),
            ctime_ns: m.ctime_nsec(),
            uid: m.uid(),
            gid: m.gid(),
            mode: m.mode(),
        }
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
struct Key {
    path: PathBuf,
    identity: Identity,
}
#[derive(Clone, Debug)]
pub struct Fingerprint {
    key: Key,
    descriptor: Arc<File>,
    pub checksum: String,
    pub size: u64,
    pub modified_nanos: String,
}
impl Fingerprint {
    pub fn path(&self) -> &Path {
        &self.key.path
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Failure {
    Unavailable,
    Changed,
    Canceled,
}
impl Failure {
    fn code(self) -> &'static str {
        match self {
            Self::Changed => "PROVIDER_CONFIGURATION_CHANGED",
            Self::Unavailable | Self::Canceled => "PROVIDER_UNAVAILABLE",
        }
    }
}
type Completion = std::result::Result<Fingerprint, Failure>;
struct Work {
    waiters: AtomicUsize,
    cancel: AtomicBool,
    cancel_notify: Notify,
    result: watch::Sender<Option<Completion>>,
}
impl Work {
    async fn canceled(&self) {
        loop {
            let notified = self.cancel_notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.cancel.load(Ordering::SeqCst) {
                return;
            }
            notified.await;
        }
    }
}
struct Waiter(Arc<Work>);
impl Drop for Waiter {
    fn drop(&mut self) {
        if self.0.waiters.fetch_sub(1, Ordering::SeqCst) == 1 {
            self.0.cancel.store(true, Ordering::SeqCst);
            self.0.cancel_notify.notify_waiters();
        }
    }
}
#[derive(Default)]
struct Stats {
    started: AtomicU64,
    shared: AtomicU64,
    bytes: AtomicU64,
    active: AtomicUsize,
    peak: AtomicUsize,
    queue_us: AtomicU64,
    hash_us: AtomicU64,
    unavailable: AtomicU64,
    changed: AtomicU64,
    canceled: AtomicU64,
    filesystem_tasks: AtomicUsize,
    queued: AtomicUsize,
}
struct ActiveWorker<'a>(&'a Stats, Instant);
impl Drop for ActiveWorker<'_> {
    fn drop(&mut self) {
        self.0
            .hash_us
            .fetch_add(self.1.elapsed().as_micros() as u64, Ordering::Relaxed);
        self.0.active.fetch_sub(1, Ordering::SeqCst);
    }
}
// Counters and permits outlive a detached request until its filesystem task exits.
struct CancelOnDrop(Cancellation);
impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.cancel();
    }
}
struct FilesystemTask(Arc<Inner>);
impl Drop for FilesystemTask {
    fn drop(&mut self) {
        self.0.stats.filesystem_tasks.fetch_sub(1, Ordering::SeqCst);
    }
}
struct Queued(Arc<Inner>);
impl Queued {
    fn new(inner: Arc<Inner>) -> Self {
        inner.stats.queued.fetch_add(1, Ordering::SeqCst);
        Self(inner)
    }
}
impl Drop for Queued {
    fn drop(&mut self) {
        self.0.stats.queued.fetch_sub(1, Ordering::SeqCst);
    }
}
struct FilesystemWorker(Arc<Inner>);
impl FilesystemWorker {
    fn new(inner: Arc<Inner>) -> Self {
        let active = inner.stats.active.fetch_add(1, Ordering::SeqCst) + 1;
        inner.stats.peak.fetch_max(active, Ordering::SeqCst);
        Self(inner)
    }
}
impl Drop for FilesystemWorker {
    fn drop(&mut self) {
        self.0.stats.active.fetch_sub(1, Ordering::SeqCst);
    }
}
struct Inner {
    workers: Arc<Semaphore>,
    registry: Mutex<HashMap<Key, Arc<Work>>>,
    stats: Stats,
    observations: Mutex<VecDeque<Value>>,
    #[cfg(test)]
    test_gate: Mutex<Option<Arc<TestGate>>>,
    #[cfg(test)]
    test_filesystem_gate: Mutex<Option<Arc<TestGate>>>,
}
#[derive(Clone)]
pub struct FingerprintService(Arc<Inner>);
impl Default for FingerprintService {
    fn default() -> Self {
        Self(Arc::new(Inner {
            workers: Arc::new(Semaphore::new(2)),
            registry: Mutex::new(HashMap::new()),
            stats: Stats::default(),
            observations: Mutex::new(VecDeque::new()),
            #[cfg(test)]
            test_gate: Mutex::new(None),
            #[cfg(test)]
            test_filesystem_gate: Mutex::new(None),
        }))
    }
}
impl FingerprintService {
    /// Safe, in-memory operator information; reading it never fingerprints files.
    pub fn diagnostics(&self) -> Value {
        let s = &self.0.stats;
        let in_flight = self
            .0
            .registry
            .lock()
            .map(|registry| registry.len())
            .unwrap_or(0);
        json!({"workerLimit":2,"activeWorkers":s.active.load(Ordering::Relaxed),"peakWorkers":s.peak.load(Ordering::Relaxed),"started":s.started.load(Ordering::Relaxed),"shared":s.shared.load(Ordering::Relaxed),"bytesHashed":s.bytes.load(Ordering::Relaxed),"queueMicros":s.queue_us.load(Ordering::Relaxed),"hashMicros":s.hash_us.load(Ordering::Relaxed),"unavailable":s.unavailable.load(Ordering::Relaxed),"changed":s.changed.load(Ordering::Relaxed),"canceled":s.canceled.load(Ordering::Relaxed),"completedCache":false,"inFlight":in_flight+s.filesystem_tasks.load(Ordering::Relaxed),"queued":s.queued.load(Ordering::Relaxed),"stageObservations":self.0.observations.lock().map(|observations|observations.iter().cloned().collect::<Vec<_>>()).unwrap_or_default()})
    }
    pub fn record_stage(
        &self,
        operation: &str,
        stage: &str,
        elapsed: std::time::Duration,
        bytes: u64,
        provider: &str,
        outcome: &str,
    ) {
        let reference = REQUEST_REFERENCE
            .try_with(Clone::clone)
            .ok()
            .filter(|reference| uuid::Uuid::parse_str(reference).is_ok())
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        let observation = json!({"operation":operation,"stage":stage,"durationMicros":elapsed.as_micros() as u64,"byteCount":bytes,"provider":provider,"correlationReference":reference,"outcome":outcome});
        if let Ok(mut records) = self.0.observations.lock() {
            if records.len() == 128 {
                records.pop_front();
            }
            records.push_back(observation);
        }
    }
    pub async fn measure<T>(
        &self,
        operation: &str,
        stage: &str,
        future: impl Future<Output = Result<T>>,
    ) -> Result<T> {
        let started = Instant::now();
        let result = future.await;
        let outcome = match result.as_ref().err().map(ToString::to_string).as_deref() {
            None => "completed",
            Some("PROVIDER_CONFIGURATION_CHANGED") => "changed",
            Some("PROVIDER_UNAVAILABLE") => "unavailable",
            Some(_) => "unknown",
        };
        self.record_stage(operation, stage, started.elapsed(), 0, "none", outcome);
        result
    }
    /// All provider filesystem work uses the same bounded admission as hashing.
    /// A canceled caller can detach, but running I/O retains its permit and counters.
    pub async fn filesystem<T: Send + 'static>(
        &self,
        operation: impl FnOnce(&Cancellation) -> Result<T> + Send + 'static,
    ) -> Result<T> {
        let cancel = REQUEST_CANCELLATION
            .try_with(Clone::clone)
            .unwrap_or_default();
        self.0.stats.filesystem_tasks.fetch_add(1, Ordering::SeqCst);
        let tracked = FilesystemTask(self.0.clone());
        let queued = Queued::new(self.0.clone());
        let permit = tokio::select! {
            _ = cancel.canceled() => {
                self.0.stats.canceled.fetch_add(1, Ordering::Relaxed);
                bail!("PROVIDER_UNAVAILABLE")
            },
            permit = self.0.workers.clone().acquire_owned() => permit.map_err(|_|anyhow::anyhow!("PROVIDER_UNAVAILABLE"))?
        };
        drop(queued);
        if cancel.is_canceled() {
            bail!("PROVIDER_UNAVAILABLE");
        }
        let inner = self.0.clone();
        let task_cancel = Cancellation::default();
        let _waiter = CancelOnDrop(task_cancel.clone());
        let task = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let _tracked = tracked;
            let _active = FilesystemWorker::new(inner.clone());
            #[cfg(test)]
            {
                let gate = inner.test_filesystem_gate.lock().unwrap().clone();
                if let Some(gate) = gate {
                    gate.pause();
                }
            }
            let result = if task_cancel.is_canceled() {
                Err(anyhow::anyhow!("PROVIDER_UNAVAILABLE"))
            } else {
                operation(&task_cancel)
            };
            if task_cancel.is_canceled() {
                inner.stats.canceled.fetch_add(1, Ordering::Relaxed);
                bail!("PROVIDER_UNAVAILABLE");
            }
            result
        });
        let result = tokio::select! {
            _ = cancel.canceled() => bail!("PROVIDER_UNAVAILABLE"),
            result = task => result.map_err(|_|anyhow::anyhow!("PROVIDER_UNAVAILABLE"))?
        };
        if cancel.is_canceled() {
            bail!("PROVIDER_UNAVAILABLE");
        }
        result
    }
    pub async fn fingerprint(&self, path: PathBuf) -> Result<Fingerprint> {
        self.fingerprint_provider(path, "none").await
    }
    pub async fn fingerprint_provider(&self, path: PathBuf, provider: &str) -> Result<Fingerprint> {
        let cancel = REQUEST_CANCELLATION
            .try_with(Clone::clone)
            .unwrap_or_default();
        let key = self
            .filesystem(move |_| identify(&path).map_err(|error| anyhow::anyhow!(error.code())))
            .await?;
        let (work, mut receiver, start) = {
            let mut registry = self
                .0
                .registry
                .lock()
                .map_err(|_| anyhow::anyhow!("INTERNAL"))?;
            if let Some(work) = registry
                .get(&key)
                .filter(|work| !work.cancel.load(Ordering::SeqCst))
            {
                work.waiters.fetch_add(1, Ordering::SeqCst);
                self.0.stats.shared.fetch_add(1, Ordering::Relaxed);
                (work.clone(), work.result.subscribe(), false)
            } else {
                let (tx, rx) = watch::channel(None);
                let work = Arc::new(Work {
                    waiters: AtomicUsize::new(1),
                    cancel: AtomicBool::new(false),
                    cancel_notify: Notify::new(),
                    result: tx,
                });
                registry.insert(key.clone(), work.clone());
                (work, rx, true)
            }
        };
        let _waiter = Waiter(work.clone());
        if start {
            self.start(key, work, provider.to_owned());
        }
        let completed = loop {
            if let Some(result) = receiver.borrow().clone() {
                break result;
            }
            tokio::select! {_=cancel.canceled()=>bail!("PROVIDER_UNAVAILABLE"), result=receiver.changed()=>{if result.is_err(){bail!("PROVIDER_UNAVAILABLE");}}}
        };
        let result = completed.map_err(|failure| anyhow::anyhow!(failure.code()))?;
        self.validate(std::slice::from_ref(&result)).await?;
        Ok(result)
    }
    fn start(&self, key: Key, work: Arc<Work>, provider: String) {
        let inner = self.0.clone();
        let reference = REQUEST_REFERENCE
            .try_with(Clone::clone)
            .ok()
            .filter(|reference| uuid::Uuid::parse_str(reference).is_ok())
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        tokio::spawn(REQUEST_REFERENCE.scope(reference, async move {
            let queued = Instant::now();
            let queue_counter = Queued::new(inner.clone());
            let permit = tokio::select! { permit=inner.workers.clone().acquire_owned()=>permit.ok(), _=work.canceled()=>None };
            drop(queue_counter);
            inner
                .stats
                .queue_us
                .fetch_add(queued.elapsed().as_micros() as u64, Ordering::Relaxed);
            let service = FingerprintService(inner.clone());
            service.record_stage(
                "provider.fingerprint",
                "queue",
                queued.elapsed(),
                key.identity.size,
                &provider,
                if permit.is_some() { "completed" } else { "canceled" },
            );
            let hash_started = Instant::now();
            let result = if let Some(permit) = permit {
                if work.cancel.load(Ordering::SeqCst) {
                    Err(Failure::Canceled)
                } else {
                    let hashing = inner.clone();
                    let task_work = work.clone();
                    let task_key = key.clone();
                    tokio::task::spawn_blocking(move || {
                        let _permit = permit;
                        let s = &hashing.stats;
                        let active = s.active.fetch_add(1, Ordering::SeqCst) + 1;
                        s.peak.fetch_max(active, Ordering::SeqCst);
                        s.started.fetch_add(1, Ordering::Relaxed);
                        let _active = ActiveWorker(s, Instant::now());
                        hash(&task_key, &task_work.cancel, &s.bytes, &|| {
                            #[cfg(test)]
                            {
                                let gate = hashing.test_gate.lock().unwrap().clone();
                                if let Some(gate) = gate {
                                    gate.pause();
                                }
                            }
                        })
                    })
                    .await
                    .unwrap_or(Err(Failure::Unavailable))
                }
            } else {
                Err(Failure::Canceled)
            };
            let outcome = match result {
                Ok(_) => "completed",
                Err(Failure::Unavailable) => "unavailable",
                Err(Failure::Changed) => "changed",
                Err(Failure::Canceled) => "canceled",
            };
            service.record_stage(
                "provider.fingerprint",
                "hash",
                hash_started.elapsed(),
                key.identity.size,
                &provider,
                outcome,
            );
            match result {
                Err(Failure::Unavailable) => {
                    inner.stats.unavailable.fetch_add(1, Ordering::Relaxed);
                }
                Err(Failure::Changed) => {
                    inner.stats.changed.fetch_add(1, Ordering::Relaxed);
                }
                Err(Failure::Canceled) => {
                    inner.stats.canceled.fetch_add(1, Ordering::Relaxed);
                }
                Ok(_) => {}
            }
            if let Ok(mut registry) = inner.registry.lock() {
                if registry
                    .get(&key)
                    .is_some_and(|entry| Arc::ptr_eq(entry, &work))
                {
                    registry.remove(&key);
                }
            }
            work.result.send_replace(Some(result));
        }));
    }
    pub async fn validate(&self, files: &[Fingerprint]) -> Result<()> {
        let files = files.to_vec();
        self.filesystem(move |cancel| {
            for file in files {
                if cancel.is_canceled() {
                    bail!("PROVIDER_UNAVAILABLE");
                }
                if Identity::read(
                    &file
                        .descriptor
                        .metadata()
                        .map_err(|_| anyhow::anyhow!("PROVIDER_UNAVAILABLE"))?,
                ) != file.key.identity
                {
                    bail!("PROVIDER_CONFIGURATION_CHANGED");
                }
                validate_key(&file.key).map_err(|error| anyhow::anyhow!(error.code()))?;
            }
            Ok(())
        })
        .await
    }
}
fn identify(path: &Path) -> std::result::Result<Key, Failure> {
    let canonical = std::fs::canonicalize(path).map_err(|_| Failure::Unavailable)?;
    if canonical != path {
        return Err(Failure::Changed);
    }
    let m = std::fs::symlink_metadata(&canonical).map_err(|_| Failure::Unavailable)?;
    if !m.is_file() || m.mode() & 0o111 == 0 {
        return Err(Failure::Unavailable);
    }
    Ok(Key {
        path: canonical,
        identity: Identity::read(&m),
    })
}
fn validate_key(key: &Key) -> std::result::Result<(), Failure> {
    let canonical = std::fs::canonicalize(&key.path).map_err(|_| Failure::Unavailable)?;
    let metadata = std::fs::symlink_metadata(&key.path).map_err(|_| Failure::Unavailable)?;
    if canonical != key.path || !metadata.is_file() || Identity::read(&metadata) != key.identity {
        return Err(Failure::Changed);
    }
    Ok(())
}

fn hash(key: &Key, cancel: &AtomicBool, bytes: &AtomicU64, after_chunk: &dyn Fn()) -> Completion {
    validate_key(key)?;
    let mut file: File = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&key.path)
        .map_err(|_| Failure::Unavailable)?;
    let before = file.metadata().map_err(|_| Failure::Unavailable)?;
    if Identity::read(&before) != key.identity {
        return Err(Failure::Changed);
    }
    validate_key(key)?;
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 65536];
    loop {
        if cancel.load(Ordering::SeqCst) {
            return Err(Failure::Canceled);
        }
        let n = file.read(&mut buffer).map_err(|_| Failure::Unavailable)?;
        if n == 0 {
            break;
        }
        bytes.fetch_add(n as u64, Ordering::Relaxed);
        digest.update(&buffer[..n]);
        after_chunk();
    }
    if Identity::read(&file.metadata().map_err(|_| Failure::Unavailable)?) != key.identity {
        return Err(Failure::Changed);
    }
    validate_key(key)?;
    Ok(Fingerprint {
        key: key.clone(),
        descriptor: Arc::new(file),
        checksum: hex::encode(digest.finalize()),
        size: before.len(),
        modified_nanos: before
            .modified()
            .map_err(|_| Failure::Unavailable)?
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Failure::Unavailable)?
            .as_nanos()
            .to_string(),
    })
}
#[cfg(test)]
pub(crate) fn synchronous(path: &Path) -> Result<Fingerprint> {
    let key = identify(path).map_err(|error| anyhow::anyhow!(error.code()))?;
    hash(&key, &AtomicBool::new(false), &AtomicU64::new(0), &|| {})
        .map_err(|error| anyhow::anyhow!(error.code()))
}

#[cfg(test)]
#[derive(Default)]
pub(crate) struct TestGate {
    pub entered: AtomicUsize,
    released: Mutex<bool>,
    wake: std::sync::Condvar,
}
#[cfg(test)]
impl TestGate {
    fn pause(&self) {
        self.entered.fetch_add(1, Ordering::SeqCst);
        let mut released = self.released.lock().unwrap();
        while !*released {
            released = self.wake.wait(released).unwrap();
        }
    }
    pub(crate) fn release(&self) {
        *self.released.lock().unwrap() = true;
        self.wake.notify_all();
    }
}
#[cfg(test)]
impl FingerprintService {
    pub(crate) fn test_hold(&self) -> Arc<TestGate> {
        let gate = Arc::new(TestGate::default());
        *self.0.test_gate.lock().unwrap() = Some(gate.clone());
        gate
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    fn executable(root: &Path, name: &str) -> PathBuf {
        let path = root.join(name);
        std::fs::write(&path, vec![42u8; 1024 * 1024]).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::canonicalize(path).unwrap()
    }
    async fn until(check: impl Fn() -> bool) {
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            while !check() {
                tokio::time::sleep(std::time::Duration::from_millis(1)).await;
            }
        })
        .await
        .unwrap();
    }
    #[tokio::test]
    async fn active_work_is_shared_but_later_checks_are_fresh() {
        let temp = tempfile::tempdir().unwrap();
        let path = executable(temp.path(), "provider");
        let service = FingerprintService::default();
        let gate = service.test_hold();
        let a = tokio::spawn({
            let service = service.clone();
            let path = path.clone();
            async move { service.fingerprint(path).await }
        });
        until(|| gate.entered.load(Ordering::SeqCst) > 0).await;
        let b = tokio::spawn({
            let service = service.clone();
            let path = path.clone();
            async move { service.fingerprint(path).await }
        });
        until(|| service.diagnostics()["shared"] == 1).await;
        // One disposed card cannot cancel the card still awaiting the same file.
        a.abort();
        gate.release();
        let result = b.await.unwrap().unwrap();
        assert_eq!(
            result.checksum,
            crate::state::digest(&vec![42u8; 1024 * 1024])
        );
        service.fingerprint(path).await.unwrap();
        assert_eq!(service.diagnostics()["started"], 2);
        assert_eq!(service.diagnostics()["inFlight"], 0);
    }
    #[tokio::test]
    async fn workers_are_bounded_and_last_waiter_cancellation_cleans_up() {
        let temp = tempfile::tempdir().unwrap();
        let service = FingerprintService::default();
        let gate = service.test_hold();
        let mut tasks = Vec::new();
        for name in ["one", "two", "three"] {
            let path = executable(temp.path(), name);
            let service = service.clone();
            tasks.push(tokio::spawn(async move { service.fingerprint(path).await }));
        }
        until(|| service.diagnostics()["activeWorkers"] == 2).await;
        for task in &tasks {
            task.abort();
        }
        for task in tasks {
            let _ = task.await;
        }
        gate.release();
        until(|| service.diagnostics()["inFlight"] == 0).await;
        assert_eq!(service.diagnostics()["peakWorkers"], 2);
        assert_eq!(service.diagnostics()["activeWorkers"], 0);
        assert!(service.diagnostics()["canceled"].as_u64().unwrap() > 0);
    }
    struct ReleaseOnDrop(Arc<TestGate>);
    impl Drop for ReleaseOnDrop {
        fn drop(&mut self) {
            self.0.release();
        }
    }
    #[tokio::test]
    async fn metadata_cannot_escape_an_active_hash_worker_limit() {
        let temp = tempfile::tempdir().unwrap();
        let service = FingerprintService::default();
        let hash_gate = service.test_hold();
        let _hash_release = ReleaseOnDrop(hash_gate.clone());
        let a = tokio::spawn({
            let service = service.clone();
            let path = executable(temp.path(), "hash");
            async move { service.fingerprint(path).await }
        });
        until(|| hash_gate.entered.load(Ordering::SeqCst) == 1).await;
        let metadata_gate = Arc::new(TestGate::default());
        let _metadata_release = ReleaseOnDrop(metadata_gate.clone());
        *service.0.test_filesystem_gate.lock().unwrap() = Some(metadata_gate.clone());
        let mut tasks = Vec::new();
        for name in ["metadata1", "metadata2", "metadata3"] {
            let path = executable(temp.path(), name);
            let service = service.clone();
            tasks.push(tokio::spawn(async move { service.fingerprint(path).await }));
        }
        until(|| {
            metadata_gate.entered.load(Ordering::SeqCst) == 1
                && service.diagnostics()["queued"] == 2
        })
        .await;
        assert_eq!(service.diagnostics()["activeWorkers"], 2);
        assert_eq!(service.diagnostics()["inFlight"], 4);
        assert_eq!(service.diagnostics()["started"], 1);
        for task in &tasks {
            task.abort();
        }
        for task in tasks {
            let _ = task.await;
        }
        a.abort();
        let _ = a.await;
        assert_eq!(service.diagnostics()["inFlight"], 2);
        assert_eq!(service.diagnostics()["queued"], 0);
        assert_eq!(metadata_gate.entered.load(Ordering::SeqCst), 1);
        metadata_gate.release();
        hash_gate.release();
        until(|| service.diagnostics()["inFlight"] == 0).await;
        assert_eq!(service.diagnostics()["activeWorkers"], 0);
        assert_eq!(service.diagnostics()["peakWorkers"], 2);
    }
    #[tokio::test]
    async fn all_filesystem_stages_remain_bounded_and_tracked_after_cancel() {
        let temp = tempfile::tempdir().unwrap();
        let path = executable(temp.path(), "provider");
        let service = FingerprintService::default();
        let fingerprint = service.fingerprint(path.clone()).await.unwrap();
        let gate = Arc::new(TestGate::default());
        let _release = ReleaseOnDrop(gate.clone());
        *service.0.test_filesystem_gate.lock().unwrap() = Some(gate.clone());
        let a = tokio::spawn({
            let service = service.clone();
            async move { service.filesystem(|_| Ok(())).await }
        });
        let b = tokio::spawn({
            let service = service.clone();
            async move { service.validate(&[fingerprint]).await }
        });
        until(|| gate.entered.load(Ordering::SeqCst) == 2).await;
        let c = tokio::spawn({
            let service = service.clone();
            async move { service.fingerprint(path).await }
        });
        until(|| service.diagnostics()["queued"] == 1).await;
        assert_eq!(service.diagnostics()["inFlight"], 3);
        a.abort();
        b.abort();
        c.abort();
        let _ = a.await;
        let _ = b.await;
        let _ = c.await;
        assert_eq!(service.diagnostics()["activeWorkers"], 2);
        assert_eq!(service.diagnostics()["inFlight"], 2);
        assert_eq!(service.diagnostics()["queued"], 0);
        assert_eq!(gate.entered.load(Ordering::SeqCst), 2);
        gate.release();
        until(|| service.diagnostics()["inFlight"] == 0).await;
        assert_eq!(service.diagnostics()["activeWorkers"], 0);
        assert_eq!(service.diagnostics()["peakWorkers"], 2);
    }
    #[tokio::test]
    async fn tampering_and_permission_changes_fail_closed() {
        let temp = tempfile::tempdir().unwrap();
        let path = executable(temp.path(), "provider");
        let service = FingerprintService::default();
        let gate = service.test_hold();
        let task = tokio::spawn({
            let service = service.clone();
            let path = path.clone();
            async move { service.fingerprint(path).await }
        });
        until(|| gate.entered.load(Ordering::SeqCst) > 0).await;
        let replacement = executable(temp.path(), "replacement");
        std::fs::rename(replacement, &path).unwrap();
        gate.release();
        assert_eq!(
            task.await.unwrap().unwrap_err().to_string(),
            "PROVIDER_CONFIGURATION_CHANGED"
        );
        let fresh = service.fingerprint(path.clone()).await.unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            service.validate(&[fresh]).await.unwrap_err().to_string(),
            "PROVIDER_CONFIGURATION_CHANGED"
        );
        assert_eq!(
            service
                .fingerprint(temp.path().join("missing"))
                .await
                .unwrap_err()
                .to_string(),
            "PROVIDER_UNAVAILABLE"
        );
    }
    #[tokio::test]
    async fn content_and_execute_mode_changes_during_hash_are_rejected() {
        for change in ["content", "mode"] {
            let temp = tempfile::tempdir().unwrap();
            let path = executable(temp.path(), "provider");
            let service = FingerprintService::default();
            let gate = service.test_hold();
            let task = tokio::spawn({
                let service = service.clone();
                let path = path.clone();
                async move { service.fingerprint(path).await }
            });
            until(|| gate.entered.load(Ordering::SeqCst) > 0).await;
            if change == "content" {
                use std::io::Write;
                OpenOptions::new()
                    .write(true)
                    .open(&path)
                    .unwrap()
                    .write_all(&[1])
                    .unwrap();
            } else {
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
            }
            gate.release();
            assert_eq!(
                task.await.unwrap().unwrap_err().to_string(),
                "PROVIDER_CONFIGURATION_CHANGED"
            );
        }
    }
    #[tokio::test]
    async fn request_cancellation_detaches_without_canceling_a_shared_waiter() {
        let temp = tempfile::tempdir().unwrap();
        let path = executable(temp.path(), "provider");
        let service = FingerprintService::default();
        let gate = service.test_hold();
        let canceled = Cancellation::default();
        let a = tokio::spawn({
            let service = service.clone();
            let path = path.clone();
            let canceled = canceled.clone();
            async move {
                REQUEST_CANCELLATION
                    .scope(canceled, service.fingerprint(path))
                    .await
            }
        });
        until(|| gate.entered.load(Ordering::SeqCst) > 0).await;
        let b = tokio::spawn({
            let service = service.clone();
            let path = path.clone();
            async move { service.fingerprint(path).await }
        });
        until(|| service.diagnostics()["shared"] == 1).await;
        canceled.cancel();
        assert!(a.await.unwrap().is_err());
        gate.release();
        assert!(b.await.unwrap().is_ok());
    }
    #[tokio::test]
    async fn stats_are_bounded_and_contain_no_executable_paths_or_contents() {
        let service = FingerprintService::default();
        for _ in 0..200 {
            service.record_stage(
                "preparations.get",
                "total",
                std::time::Duration::from_micros(1),
                0,
                "none",
                "completed",
            );
        }
        let value = service.diagnostics();
        assert_eq!(value["stageObservations"].as_array().unwrap().len(), 128);
        assert!(!value.to_string().contains("/"));
        assert_eq!(value["started"], 0);
    }
}
