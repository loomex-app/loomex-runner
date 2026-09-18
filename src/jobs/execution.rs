use super::*;

pub(super) async fn execute_job(
    daemon: Arc<Daemon>,
    path: &Path,
    journal: Arc<Mutex<Journal>>,
    cancel: Arc<AtomicBool>,
    scope: Arc<ExecutionScope>,
) -> Result<()> {
    if daemon.execution.is_draining() {
        bail!("DAEMON_DRAINING")
    }
    let current = snapshot(&journal)?;
    let job = &current.job;
    let id = job["id"].as_str().context("BACKEND_PROTOCOL_ERROR")?;
    let authorized = authorize(&daemon, &current).await?;
    let payload = authorized.payload();
    if payload["executionPolicy"] != "host_user/v1" {
        bail!("UNSUPPORTED_EXECUTION_POLICY")
    }
    let is_http = job["kind"] == "http.request";
    let output_dir = path.parent().context("journal parent")?.to_path_buf();
    let request = if is_http {
        None
    } else {
        Some(command_request(&authorized, id, path, journal.clone())?)
    };
    let mut j = snapshot(&journal)?;
    j.transition(JournalPhase::StartPending)?;
    {
        *journal.lock().unwrap() = j.clone();
    }
    save(&journal, path)?;
    let started = daemon
        .backend(
            &j.organization,
            "POST",
            &format!("v1/jobs/{id}/start/"),
            Some(fence(&j)),
            None,
        )
        .await?;
    {
        let mut locked = journal.lock().unwrap();
        locked.job = started["job"].clone();
        locked.transition(JournalPhase::Started)?;
    }
    save(&journal, path)?;
    let finished = scope.finished.clone();
    let tick_finished = finished.clone();
    let d = daemon.clone();
    let jr = journal.clone();
    let jp = path.to_owned();
    let token = cancel.clone();

    let tick_active = Quiescence::new(daemon.clone());
    let tick = tokio::spawn(async move {
        let _active = tick_active;
        while !tick_finished.load(Ordering::SeqCst) {
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            if tick_finished.load(Ordering::SeqCst) {
                break;
            };
            let Ok(j) = snapshot(&jr) else { break };
            let id = j.job["id"].as_str().unwrap_or("");
            match d
                .backend(
                    &j.organization,
                    "POST",
                    &format!("v1/jobs/{id}/renew/"),
                    Some(fence(&j)),
                    None,
                )
                .await
            {
                Ok(response) => {
                    if response["job"]["status"] == "canceling" {
                        token.store(true, Ordering::SeqCst)
                    }
                    if let Ok(mut locked) = jr.lock() {
                        locked.job = response["job"].clone();
                        let _ = persist(&jp, &locked);
                    }
                }
                Err(_) => {
                    let expires = j.job["leasedUntilEpochMs"].as_u64().unwrap_or(0) / 1000;
                    if state::now() >= expires {
                        token.store(true, Ordering::SeqCst);
                    }
                }
            }
            let _ = stream_events(&d, &jp, &jr).await;
        }
    });
    scope.register(tick);
    let authority_journal = journal.clone();
    let authority_cancel = cancel.clone();
    let authority_finished = finished.clone();

    let authority_active = Quiescence::new(daemon.clone());
    let authority_watch = tokio::spawn(async move {
        let _active = authority_active;
        while !authority_finished.load(Ordering::SeqCst) {
            if let Ok(j) = snapshot(&authority_journal) {
                let expiry = j.job["leasedUntilEpochMs"].as_u64().unwrap_or(0);
                let now_ms = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u64;
                if expiry == 0 || now_ms >= expiry {
                    authority_cancel.store(true, Ordering::SeqCst);
                    break;
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        }
    });
    scope.register(authority_watch);
    let outcome = if is_http {
        {
            let mut record = journal.lock().unwrap();
            record.transition(JournalPhase::Running)?;
            persist(path, &record)?;
        }
        let response_path = output_dir.join("http-response-body");
        let result = execute_authorized_http(&authorized, cancel.clone(), &response_path).await?;
        {
            let mut record = journal.lock().unwrap();
            record.transition(JournalPhase::Exited)?;
            record.result = Some(result);
            persist(path, &record)?;
        }
        drain_events(&daemon, path, &journal).await?;
        materialize_terminal(&daemon, path, &journal).await?;
        scope.stop().await;
        return Ok(());
    } else {
        execute_authorized_command(&authorized, request.context("INVALID_COMMAND")?, cancel).await
    };
    let terminal: Result<()> = async {
        let outcome = outcome?;
        if outcome.error.is_some() {
            bail!("EXECUTION_INDETERMINATE");
        }
        {
            let mut record = journal.lock().unwrap();
            record.transition(JournalPhase::Exited)?;
            record.result = Some(json!({
                "exitCode": outcome.exit_code,
                "durationSeconds": state::now().saturating_sub(record.started_at),
                "timedOut": false,
                "cancelled": outcome.canceled,
                "truncated": false,
                "indeterminate": outcome.indeterminate,
                "managedGroupStopped": outcome.managed_group_stopped,
                "descendantCleanup": outcome.descendant_cleanup,
                "stdoutPath": outcome.stdout_path,
                "stderrPath": outcome.stderr_path
            }));
            persist(path, &record)?;
        }
        drain_events(&daemon, path, &journal).await?;
        materialize_terminal(&daemon, path, &journal).await
    }
    .await;
    scope.stop().await;
    terminal
}
