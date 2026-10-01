use super::*;

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
enum CancellationCause {
    LocalLeaseExpired,
}

struct LeaseExpiryCancellation {
    token: Arc<AtomicBool>,
    cause: AtomicBool,
    gate: Mutex<()>,
}

impl LeaseExpiryCancellation {
    fn new(token: Arc<AtomicBool>) -> Self {
        Self {
            token,
            cause: AtomicBool::new(false),
            gate: Mutex::new(()),
        }
    }

    fn trigger(&self) {
        let _gate = self.gate.lock().unwrap();
        // The first cancellation source wins. A backend or supervisor
        // cancellation that arrived first must not be attributed to lease
        // expiry. Hold the gate until the cause is visible to result capture.
        if self
            .token
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            self.cause.store(true, Ordering::SeqCst);
        }
    }

    fn cause(&self, canceled: bool) -> Option<CancellationCause> {
        let _gate = self.gate.lock().unwrap();
        cancellation_cause(canceled, self.cause.load(Ordering::SeqCst))
    }
}

fn cancellation_cause(canceled: bool, local_lease_expired: bool) -> Option<CancellationCause> {
    (canceled && local_lease_expired).then_some(CancellationCause::LocalLeaseExpired)
}

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
    let mut request = if is_http {
        None
    } else {
        Some(command_request(&authorized, id, path, journal.clone())?)
    };
    let status_server = if dispatch_enabled(job) {
        let provider = payload["provider"]
            .as_str()
            .context("PUBLIC_STATUS_PROVIDER_UNSUPPORTED")?;
        let request = request
            .as_mut()
            .context("PUBLIC_STATUS_PROVIDER_UNSUPPORTED")?;
        let server = StatusServer::start(&daemon, path, journal.clone())?;
        server.configure_request(request, provider)?;
        Some(server)
    } else {
        None
    };
    let mut j = snapshot(&journal)?;
    j.transition(JournalPhase::StartPending)?;
    {
        *journal.lock().unwrap() = j.clone();
    }
    save(&journal, path)?;
    let started = backend_job(
        &daemon,
        &journal,
        &j,
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
    let lease_expiry = Arc::new(LeaseExpiryCancellation::new(cancel.clone()));
    let tick_lease_expiry = lease_expiry.clone();

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
            match backend_job(
                &d,
                &jr,
                &j,
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
                        tick_lease_expiry.trigger();
                    }
                }
            }
            let _ = stream_events(&d, &jp, &jr).await;
        }
    });
    scope.register(tick);
    let authority_journal = journal.clone();
    let authority_lease_expiry = lease_expiry.clone();
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
                    authority_lease_expiry.trigger();
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
        let result = {
            let _idle_sleep = crate::power::IdleSleepGuard::acquire();
            execute_authorized_http(&authorized, cancel.clone(), &response_path).await?
        };
        {
            let mut record = journal.lock().unwrap();
            record.transition(JournalPhase::Exited)?;
            record.result = Some(result);
            persist(path, &record)?;
        }
        initial_finalization(&daemon, path, &journal).await?;
        scope.stop().await;
        return Ok(());
    } else {
        execute_authorized_command(&authorized, request.context("INVALID_COMMAND")?, cancel).await
    };
    // The provider process has stopped. Its scoped reporter can no longer
    // submit statuses, while already accepted journal entries may still drain.
    drop(status_server);
    let terminal: Result<()> = async {
        let outcome = outcome?;
        if outcome.error.is_some() {
            bail!("EXECUTION_INDETERMINATE");
        }
        {
            let mut record = journal.lock().unwrap();
            record.transition(JournalPhase::Exited)?;
            let mut result = json!({
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
            });
            if let Some(cause) = lease_expiry.cause(outcome.canceled) {
                result["cancellationCause"] = json!(cause);
            }
            record.result = Some(result);
            persist(path, &record)?;
        }
        initial_finalization(&daemon, path, &journal).await
    }
    .await;
    scope.stop().await;
    terminal
}

#[cfg(test)]
mod cancellation_cause_tests {
    use super::*;

    #[test]
    fn local_lease_expiry_has_a_fixed_result_cause_only_for_canceled_work() {
        let cancel = Arc::new(AtomicBool::new(false));
        let expiry = LeaseExpiryCancellation::new(cancel.clone());
        expiry.trigger();
        assert!(cancel.load(Ordering::SeqCst));
        assert_eq!(json!(expiry.cause(true)), json!("local_lease_expired"));
        assert!(expiry.cause(false).is_none());
    }

    #[test]
    fn prior_cancellation_does_not_acquire_a_lease_expiry_cause() {
        let cancel = Arc::new(AtomicBool::new(true));
        let expiry = LeaseExpiryCancellation::new(cancel);
        expiry.trigger();
        assert!(expiry.cause(true).is_none());
    }

    #[test]
    fn concurrent_backend_cancellation_keeps_precedence_over_waiting_lease_check() {
        let cancel = Arc::new(AtomicBool::new(false));
        let expiry = Arc::new(LeaseExpiryCancellation::new(cancel.clone()));
        let gate = expiry.gate.lock().unwrap();
        let ready = Arc::new(std::sync::Barrier::new(2));
        let worker_expiry = expiry.clone();
        let worker_ready = ready.clone();
        let worker = std::thread::spawn(move || {
            worker_ready.wait();
            worker_expiry.trigger();
        });
        ready.wait();
        cancel.store(true, Ordering::SeqCst);
        drop(gate);
        worker.join().unwrap();
        assert!(expiry.cause(true).is_none());
    }
}
