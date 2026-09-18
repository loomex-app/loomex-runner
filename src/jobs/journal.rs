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
    #[serde(skip)]
    pub(super) event_sender: Arc<tokio::sync::Mutex<()>>,
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
    pub(super) stdout_offset: u64,
    pub(super) stderr_offset: u64,
}
pub(super) struct Observer {
    pub(super) path: PathBuf,
    pub(super) journal: Arc<Mutex<Journal>>,
}
impl ExecutionObserver for Observer {
    fn before_spawn(&self, _: &ExecutionRequest) -> Result<()> {
        let mut j = self
            .journal
            .lock()
            .map_err(|_| anyhow::anyhow!("journal lock"))?;
        j.transition(JournalPhase::SpawnIntent)?;
        persist(&self.path, &j)
    }
    fn spawned(&self, identity: &ProcessIdentity) -> Result<()> {
        let mut j = self
            .journal
            .lock()
            .map_err(|_| anyhow::anyhow!("journal lock"))?;
        j.identity = Some(identity.clone());
        j.transition(JournalPhase::Running)?;
        persist(&self.path, &j)
    }
}
pub(super) fn snapshot(j: &Arc<Mutex<Journal>>) -> Result<Journal> {
    Ok(j.lock()
        .map_err(|_| anyhow::anyhow!("journal lock"))?
        .clone())
}
pub(super) fn save(j: &Arc<Mutex<Journal>>, path: &Path) -> Result<()> {
    let record = j.lock().map_err(|_| anyhow::anyhow!("journal lock"))?;
    persist(path, &record)
}

/// All production writes of job evidence pass through this durability boundary.
pub(super) fn persist(path: &Path, record: &Journal) -> Result<()> {
    state::write_json(path, record)
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
