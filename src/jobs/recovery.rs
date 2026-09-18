use super::*;

pub(super) async fn recover(daemon: Arc<Daemon>, org: &str, session: &str) -> Result<()> {
    let root = daemon.dir.join("jobs");
    if !root.exists() {
        return Ok(());
    }
    for entry in std::fs::read_dir(root)? {
        let path = entry?.path().join("journal.json");
        if !path.exists() {
            continue;
        };
        let mut j: Journal = match state::read_json(&path) {
            Ok(record) => record,
            Err(_) => {
                eprintln!("JOB_JOURNAL_UNREADABLE: {}", path.display());
                continue;
            }
        };
        if j.organization != org || ["acknowledged", "delivery_blocked"].contains(&j.phase.as_str())
        {
            continue;
        };
        let Some(id) = j.job["id"]
            .as_str()
            .filter(|id| Uuid::parse_str(id).is_ok())
        else {
            eprintln!("JOB_JOURNAL_INVALID_ID: {}", path.display());
            continue;
        };
        let Some(registration) = daemon.execution.claim(id.to_owned()) else {
            continue;
        };
        j.recovery_session = Some(session.into());
        if !["exited", "terminal_pending"].contains(&j.phase.as_str()) {
            j.error = Some(
                json!({"code":"EXECUTION_INDETERMINATE","message":"Daemon restarted before durable terminal outcome; command was not replayed","indeterminate":true}),
            );
            j.result = None;
            j.transition(JournalPhase::TerminalPending)?;
        }
        persist(&path, &j)?;

        let d = daemon.clone();
        let active = ActiveJob::new(d.clone());
        daemon.execution.spawn_recovery(registration, async move {
            let _active = active;
            let _ = deliver(d.clone(), &path, Arc::new(Mutex::new(j))).await;
        });
    }
    Ok(())
}
