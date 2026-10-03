use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum JournalPhase {
    Leased,
    StartPending,
    Started,
    SpawnIntent,
    Running,
    Exited,
    TerminalPending,
    Acknowledged,
    DeliveryBlocked,
}
impl JournalPhase {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::Leased => "leased",
            Self::StartPending => "start_pending",
            Self::Started => "started",
            Self::SpawnIntent => "spawn_intent",
            Self::Running => "running",
            Self::Exited => "exited",
            Self::TerminalPending => "terminal_pending",
            Self::Acknowledged => "acknowledged",
            Self::DeliveryBlocked => "delivery_blocked",
        }
    }
}
impl PartialEq<&str> for JournalPhase {
    fn eq(&self, other: &&str) -> bool {
        self.as_str() == *other
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum DeliveryDiagnosticCategory {
    OutputDelivery,
    ArtifactFinalization,
    TerminalSubmission,
    LeaseReclaim,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct DeliveryDiagnostic {
    pub(super) schema_version: String,
    pub(super) category: DeliveryDiagnosticCategory,
    pub(super) code: String,
    pub(super) observed_at_epoch_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) correlation_id: Option<String>,
}
impl Journal {
    pub(super) fn transition(&mut self, next: JournalPhase) -> Result<()> {
        use JournalPhase::*;
        let valid = self.phase == next
            || matches!(
                (self.phase, next),
                (Leased, StartPending)
                    | (StartPending, Started)
                    | (Started, SpawnIntent)
                    | (Started, Running)
                    | (SpawnIntent, Running)
                    | (Running, Exited)
                    | (
                        Leased | StartPending | Started | SpawnIntent | Running | Exited,
                        TerminalPending
                    )
                    | (Exited | TerminalPending, DeliveryBlocked)
                    | (TerminalPending, Acknowledged)
            );
        if !valid {
            bail!("INVALID_JOURNAL_TRANSITION");
        }
        self.phase = next;
        Ok(())
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Journal {
    pub(super) job: Value,
    pub(super) organization: String,
    pub(super) session: String,
    #[serde(default)]
    pub(super) recovery_session: Option<String>,
    pub(super) phase: JournalPhase,
    pub(super) identity: Option<ProcessIdentity>,
    pub(super) result: Option<Value>,
    pub(super) error: Option<Value>,
    pub(super) terminal_key: String,
    pub(super) started_at: u64,
    #[serde(default)]
    pub(super) acknowledged_at: Option<u64>,
    /// Optional bounded diagnostic for the exact delivery failure that left
    /// this journal blocked. Older journals deserialize without this field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) delivery_diagnostic: Option<DeliveryDiagnostic>,
    /// The first failed output/finalization step is immutable evidence even if
    /// a later terminal submission fails for a different reason.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) first_failure_diagnostic: Option<DeliveryDiagnostic>,
    #[serde(skip)]
    pub(super) event_sender: Arc<tokio::sync::Mutex<()>>,
    #[serde(skip)]
    pub(super) durable_writer: Arc<EvidenceIo>,
    #[serde(default)]
    pub(super) stdout_pending: Option<usize>,
    #[serde(default)]
    pub(super) stderr_pending: Option<usize>,
    /// Private parser checkpoint for safe provider progress recognition. Raw
    /// provider output remains in the local spool and is never sent as progress.
    #[serde(default)]
    pub(super) progress_buffer: Vec<u8>,
    #[serde(default)]
    pub(super) progress_buffer_offset: u64,
    #[serde(default)]
    pub(super) progress_discarding: bool,
    #[serde(default)]
    pub(super) progress_pending: Option<Vec<Value>>,
    /// Latest accepted public status that has not been assigned a transport
    /// identity. Replacements coalesce while an older exact event is pending.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) public_status_latest: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) public_status_pending: Option<Value>,
    #[serde(default)]
    pub(super) public_status_next_sequence: u64,
    #[serde(default)]
    pub(super) public_status_last_sent_at_ms: u64,
    pub(super) stdout_offset: u64,
    pub(super) stderr_offset: u64,
}
pub(super) struct Observer {
    pub(super) path: PathBuf,
    pub(super) journal: Arc<Mutex<Journal>>,
}
impl ExecutionObserver for Observer {
    fn after_blocking(&self) -> Result<()> {
        let j = snapshot(&self.journal)?;
        let supervisor = j.durable_writer.supervisor.lock().unwrap().clone();
        let binding = j.durable_writer.launch_binding.lock().unwrap();
        anyhow::ensure!(
            binding
                .as_ref()
                .is_none_or(|expected| expected == &local_execution_binding(&j)),
            "LOCAL_EXECUTION_AUTHORIZATION_REQUIRED"
        );
        anyhow::ensure!(
            matches!(j.phase, JournalPhase::SpawnIntent | JournalPhase::Running)
                && j.job["leasedUntilEpochMs"].as_u64().unwrap_or(0) > now_millis()
                && j.recovery_session.is_none()
                && j.job["status"] != "canceling"
                && supervisor.is_none_or(|owner| !owner.is_draining() && !owner.logout_requested()),
            "LOCAL_EXECUTION_AUTHORIZATION_REQUIRED"
        );
        Ok(())
    }
    fn blocking_guard(&self) -> Option<Box<dyn Send>> {
        let j = snapshot(&self.journal).ok()?;
        let mut binding = j.durable_writer.launch_binding.lock().ok()?;
        binding.get_or_insert_with(|| local_execution_binding(&j));
        Some(Box::new(j.durable_writer.own()))
    }
    fn before_spawn(&self, _: &ExecutionRequest) -> Result<()> {
        update_sync(&self.path, &self.journal, |j| {
            j.transition(JournalPhase::SpawnIntent)
        })
    }
    fn spawned(&self, identity: &ProcessIdentity) -> Result<()> {
        update_sync(&self.path, &self.journal, |j| {
            j.identity = Some(identity.clone());
            j.transition(JournalPhase::Running)
        })
    }
}

fn local_execution_binding(j: &Journal) -> Value {
    json!({"organization":j.organization,"session":j.session,"recoverySession":j.recovery_session,
        "terminalKey":j.terminal_key,"jobId":j.job["id"],"runnerId":j.job["runnerId"],
        "connectionGeneration":j.job["connectionGeneration"],"payloadDigest":j.job["payloadDigest"]})
}

pub(super) fn snapshot(j: &Arc<Mutex<Journal>>) -> Result<Journal> {
    Ok(j.lock()
        .map_err(|_| anyhow::anyhow!("journal lock"))?
        .clone())
}
/// All production writes of job evidence pass through this durability boundary.
pub(super) fn persist(path: &Path, record: &Journal) -> Result<()> {
    state::write_json(path, record)
}

/// Serialize the entire read/change/fsync/publish transaction without holding
/// the journal snapshot mutex during disk I/O. Readers observe only committed
/// records. A synchronous spawn observer uses this same per-job writer gate.
pub(super) fn update_sync<T>(
    path: &Path,
    journal: &Arc<Mutex<Journal>>,
    change: impl FnOnce(&mut Journal) -> Result<T>,
) -> Result<T> {
    let writer = snapshot(journal)?.durable_writer;
    let _writing = writer
        .writer
        .lock()
        .map_err(|_| anyhow::anyhow!("journal writer lock"))?;
    let mut next = snapshot(journal)?;
    let result = change(&mut next)?;
    #[cfg(test)]
    if let Some((ready, release)) = writer.delay_write.lock().unwrap().take() {
        let _ = ready.send(());
        release
            .recv_timeout(Duration::from_secs(5))
            .context("delayed write release")?;
    }
    persist(path, &next)?;
    #[cfg(test)]
    writer.commits.fetch_add(1, Ordering::SeqCst);
    *journal
        .lock()
        .map_err(|_| anyhow::anyhow!("journal lock"))? = next;
    Ok(result)
}

// Shared by artifact hashing and asynchronous journal commits. Admission is
// bounded before spawn_blocking; cancellation drops only the waiter, never the
// worker's permit or daemon quiescence ownership.
const BLOCKING_IO_WORKERS: usize = 2;
#[derive(Default)]
pub(super) struct EvidenceIo {
    writer: Mutex<()>,
    pending: std::sync::atomic::AtomicUsize,
    idle: tokio::sync::Notify,
    pub(super) supervisor: Mutex<Option<Arc<supervisor::ExecutionSupervisor>>>,
    launch_binding: Mutex<Option<Value>>,
    #[cfg(test)]
    pub(super) delay_write: Mutex<
        Option<(
            tokio::sync::oneshot::Sender<()>,
            std::sync::mpsc::Receiver<()>,
        )>,
    >,
    #[cfg(test)]
    pub(super) delay_hash: Mutex<
        Option<(
            tokio::sync::oneshot::Sender<()>,
            std::sync::mpsc::Receiver<()>,
        )>,
    >,
    #[cfg(test)]
    pub(super) test_slots: Mutex<Option<Arc<TestIoSlots>>>,
    #[cfg(test)]
    pub(super) commits: std::sync::atomic::AtomicUsize,
}
impl EvidenceIo {
    pub(super) fn own(self: &Arc<Self>) -> EvidenceOwnership {
        self.pending.fetch_add(1, Ordering::SeqCst);
        let supervisor = self.supervisor.lock().unwrap().clone();
        if let Some(owner) = &supervisor {
            owner.begin_quiescence();
        }
        EvidenceOwnership {
            evidence: self.clone(),
            supervisor,
        }
    }
    pub(super) async fn wait_idle(&self) {
        loop {
            let wake = self.idle.notified();
            if self.pending.load(Ordering::SeqCst) == 0 {
                return;
            }
            wake.await;
        }
    }
}
pub(super) struct EvidenceOwnership {
    evidence: Arc<EvidenceIo>,
    supervisor: Option<Arc<supervisor::ExecutionSupervisor>>,
}
impl Drop for EvidenceOwnership {
    fn drop(&mut self) {
        if let Some(owner) = &self.supervisor {
            owner.end_quiescence();
        }
        self.evidence.pending.fetch_sub(1, Ordering::SeqCst);
        self.evidence.idle.notify_waiters();
    }
}
pub(crate) async fn blocking_io<T: Send + 'static>(
    work: impl FnOnce() -> Result<T> + Send + 'static,
) -> Result<T> {
    static SLOTS: std::sync::OnceLock<Arc<tokio::sync::Semaphore>> = std::sync::OnceLock::new();
    let permit = SLOTS
        .get_or_init(|| Arc::new(tokio::sync::Semaphore::new(BLOCKING_IO_WORKERS)))
        .clone()
        .acquire_owned()
        .await?;
    run_blocking(permit, work).await
}

async fn run_blocking<T: Send + 'static>(
    permit: tokio::sync::OwnedSemaphorePermit,
    work: impl FnOnce() -> Result<T> + Send + 'static,
) -> Result<T> {
    match tokio::task::spawn_blocking(move || {
        let _permit = permit;
        work()
    })
    .await
    {
        Ok(result) => result,
        Err(error) if error.is_panic() => std::panic::resume_unwind(error.into_panic()),
        Err(error) => Err(error).context("job I/O worker"),
    }
}
pub(super) async fn job_io<T: Send + 'static>(
    daemon: &Daemon,
    journal: &Arc<Mutex<Journal>>,
    work: impl FnOnce() -> Result<T> + Send + 'static,
) -> Result<T> {
    let evidence = snapshot(journal)?.durable_writer;
    *evidence.supervisor.lock().unwrap() = Some(daemon.execution.clone());
    let owner = evidence.own();
    let owned_work = move || {
        let _owner = owner;
        work()
    };
    #[cfg(test)]
    {
        let slots = evidence.test_slots.lock().unwrap().clone();
        if let Some(slots) = slots {
            let permit = slots.blocking.clone().acquire_owned().await?;
            return run_blocking(permit, owned_work).await;
        }
    }
    blocking_io(owned_work).await
}
/// Hash admission precedes shared blocking admission, reserving one of the two
/// actual workers for journal/observer durability even with many large files.
pub(super) async fn job_hash_io<T: Send + 'static>(
    daemon: &Daemon,
    journal: &Arc<Mutex<Journal>>,
    work: impl FnOnce() -> Result<T> + Send + 'static,
) -> Result<T> {
    let permit = hash_slot(journal)?.acquire_owned().await?;
    #[cfg(test)]
    let evidence = snapshot(journal)?.durable_writer;
    job_io(daemon, journal, move || {
        let _hash_permit = permit;
        #[cfg(test)]
        if let Some((ready, release)) = evidence.delay_hash.lock().unwrap().take() {
            let _ = ready.send(());
            release
                .recv_timeout(Duration::from_secs(5))
                .context("delayed hash release")?;
        }
        work()
    })
    .await
}
fn hash_slot(journal: &Arc<Mutex<Journal>>) -> Result<Arc<tokio::sync::Semaphore>> {
    #[cfg(test)]
    if let Some(slots) = snapshot(journal)?
        .durable_writer
        .test_slots
        .lock()
        .unwrap()
        .clone()
    {
        return Ok(slots.hashing.clone());
    }
    #[cfg(not(test))]
    let _ = journal;
    static HASH_SLOT: std::sync::OnceLock<Arc<tokio::sync::Semaphore>> = std::sync::OnceLock::new();
    Ok(HASH_SLOT
        .get_or_init(|| Arc::new(tokio::sync::Semaphore::new(1)))
        .clone())
}

/// Fault fixtures hold workers for seconds. Their private admissions use the
/// same executor and bounds, without saturating unrelated fixture runtimes.
/// Ordinary fixtures and every production caller keep the process-global slots.
#[cfg(test)]
pub(super) struct TestIoSlots {
    blocking: Arc<tokio::sync::Semaphore>,
    hashing: Arc<tokio::sync::Semaphore>,
}
#[cfg(test)]
impl Default for TestIoSlots {
    fn default() -> Self {
        Self {
            blocking: Arc::new(tokio::sync::Semaphore::new(BLOCKING_IO_WORKERS)),
            hashing: Arc::new(tokio::sync::Semaphore::new(1)),
        }
    }
}

pub(super) async fn update<T: Send + 'static>(
    daemon: &Daemon,
    path: &Path,
    journal: &Arc<Mutex<Journal>>,
    change: impl FnOnce(&mut Journal) -> Result<T> + Send + 'static,
) -> Result<T> {
    let path = path.to_owned();
    let journal = journal.clone();
    let ownership_journal = journal.clone();
    job_io(daemon, &ownership_journal, move || {
        update_sync(&path, &journal, change)
    })
    .await
}

/// The worker keeps the event sender lock through fsync, even when its waiter
/// is aborted. A terminal drain or replacement sender cannot overtake it.
pub(super) async fn update_while_sending<T: Send + 'static>(
    daemon: &Daemon,
    path: &Path,
    journal: &Arc<Mutex<Journal>>,
    sender: Arc<tokio::sync::OwnedMutexGuard<()>>,
    change: impl FnOnce(&mut Journal) -> Result<T> + Send + 'static,
) -> Result<T> {
    let path = path.to_owned();
    let journal = journal.clone();
    let ownership_journal = journal.clone();
    job_io(daemon, &ownership_journal, move || {
        let _sender = sender;
        update_sync(&path, &journal, change)
    })
    .await
}

#[cfg(test)]
mod transition_tests {
    use super::*;
    #[test]
    fn serialized_phases_remain_compatible_and_unknown_values_fail_closed() {
        for phase in [
            "leased",
            "start_pending",
            "started",
            "spawn_intent",
            "running",
            "exited",
            "terminal_pending",
            "acknowledged",
            "delivery_blocked",
        ] {
            let decoded: JournalPhase = serde_json::from_value(json!(phase)).unwrap();
            assert_eq!(serde_json::to_value(decoded).unwrap(), json!(phase));
        }
        assert!(serde_json::from_value::<JournalPhase>(json!("future_phase")).is_err());
    }
}
