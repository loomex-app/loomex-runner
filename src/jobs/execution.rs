use super::*;
use anyhow::ensure;

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

fn require_job_admission(
    daemon: &Daemon,
    expected: &Journal,
    journal: &Arc<Mutex<Journal>>,
    cancel: &AtomicBool,
) -> Result<()> {
    ensure!(
        job_authority_unchanged(expected, journal, true)
            && !cancel.load(Ordering::SeqCst)
            && !daemon.execution.is_draining(),
        "LOCAL_EXECUTION_AUTHORIZATION_REQUIRED"
    );
    Ok(())
}
pub(super) async fn execute_job(
    daemon: Arc<Daemon>,
    path: &Path,
    journal: Arc<Mutex<Journal>>,
    cancel: Arc<AtomicBool>,
    scope: Arc<ExecutionScope>,
) -> Result<()> {
    let evidence = snapshot(&journal)?.durable_writer;
    *evidence.supervisor.lock().unwrap() = Some(daemon.execution.clone());
    *scope.evidence.lock().unwrap() = Some(evidence);
    if daemon.execution.is_draining() {
        bail!("DAEMON_DRAINING")
    }
    let current = snapshot(&journal)?;
    let job = &current.job;
    let id = job["id"].as_str().context("BACKEND_PROTOCOL_ERROR")?;
    let authorized = authorize(&daemon, &current).await?;
    require_job_admission(&daemon, &current, &journal, &cancel)?;
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
    let memory_server = if persona_memory::enabled(payload) {
        let provider = payload["provider"]
            .as_str()
            .context("PERSONA_MEMORY_PROVIDER_UNSUPPORTED")?;
        ensure!(
            persona_memory::provider_supported(&daemon, provider).await?,
            "PERSONA_MEMORY_PROVIDER_UNSUPPORTED"
        );
        let server = persona_memory::MemoryServer::start(
            daemon.clone(),
            path,
            journal.clone(),
            cancel.clone(),
        )?;
        server.configure_request(
            request
                .as_mut()
                .context("PERSONA_MEMORY_PROVIDER_UNSUPPORTED")?,
            provider,
        )?;
        Some(server)
    } else {
        ensure!(
            !persona_memory::required_memory(payload),
            "PERSONA_MEMORY_UNAVAILABLE"
        );
        None
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
    // Qualification is another asynchronous filesystem stage. Re-read the exact
    // committed local authority using the original verified snapshot, without
    // applying a preparation TTL to an already committed job or hashing again.
    authorized.revalidate(&daemon, &current).await?;
    require_job_admission(&daemon, &current, &journal, &cancel)?;
    update(&daemon, path, &journal, |j| {
        j.transition(JournalPhase::StartPending)
    })
    .await?;
    let j = snapshot(&journal)?;
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
    update(&daemon, path, &journal, move |locked| {
        locked.job = started["job"].clone();
        locked.transition(JournalPhase::Started)
    })
    .await?;
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
        maintain_lease(
            d,
            jp,
            jr,
            token,
            tick_finished,
            tick_lease_expiry,
            Duration::from_secs(5),
        )
        .await;
    });
    scope.register(tick);
    let output_finished = Arc::new(AtomicBool::new(false));
    if !is_http {
        let output_d = daemon.clone();
        let output_j = journal.clone();
        let output_p = path.to_owned();
        let output_done = output_finished.clone();
        let scope_done = finished.clone();
        let output_active = Quiescence::new(daemon.clone());
        scope.register(tokio::spawn(async move {
            let _active = output_active;
            while !scope_done.load(Ordering::SeqCst) && !output_done.load(Ordering::SeqCst) {
                match stream_event_batch(&output_d, &output_p, &output_j).await {
                    Ok(true) => tokio::task::yield_now().await,
                    _ => tokio::time::sleep(Duration::from_millis(250)).await,
                }
            }
        }));
    }
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
        update(&daemon, path, &journal, |record| {
            record.transition(JournalPhase::Running)
        })
        .await?;
        let response_path = output_dir.join("http-response-body");
        let result = {
            let _idle_sleep = crate::power::IdleSleepGuard::acquire();
            execute_authorized_http(&authorized, cancel.clone(), &response_path).await?
        };
        update(&daemon, path, &journal, move |record| {
            record.transition(JournalPhase::Exited)?;
            record.result = Some(result);
            Ok(())
        })
        .await?;
        initial_finalization(&daemon, path, &journal).await?;
        scope.stop().await;
        return Ok(());
    } else {
        execute_authorized_command(&authorized, request.context("INVALID_COMMAND")?, cancel).await
    };
    output_finished.store(true, Ordering::SeqCst);
    // The provider process has stopped. Its scoped reporter can no longer
    // submit statuses, while already accepted journal entries may still drain.
    drop(status_server);
    drop(memory_server);
    let terminal: Result<()> = async {
        let outcome = outcome?;
        if outcome.error.is_some() {
            bail!("EXECUTION_INDETERMINATE");
        }
        update(&daemon, path, &journal, move |record| {
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
            Ok(())
        })
        .await?;
        initial_finalization(&daemon, path, &journal).await
    }
    .await;
    scope.stop().await;
    terminal
}

async fn maintain_lease(
    daemon: Arc<Daemon>,
    path: PathBuf,
    journal: Arc<Mutex<Journal>>,
    cancel: Arc<AtomicBool>,
    finished: Arc<AtomicBool>,
    expiry: Arc<LeaseExpiryCancellation>,
    cadence: Duration,
) {
    while !finished.load(Ordering::SeqCst) {
        tokio::time::sleep(cadence).await;
        if finished.load(Ordering::SeqCst) {
            break;
        }
        let Ok(j) = snapshot(&journal) else { break };
        let id = j.job["id"].as_str().unwrap_or("");
        match backend_job(
            &daemon,
            &journal,
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
                    cancel.store(true, Ordering::SeqCst);
                }
                let _ = update(&daemon, &path, &journal, move |locked| {
                    // A delayed renewal may not overwrite a replacement lease
                    // or changed owner that committed while the request waited.
                    ensure!(
                        locked.organization == j.organization
                            && locked.session == j.session
                            && locked.recovery_session == j.recovery_session
                            && locked.terminal_key == j.terminal_key
                            && locked.job["id"] == j.job["id"]
                            && locked.job["runnerId"] == j.job["runnerId"]
                            && locked.job["connectionGeneration"] == j.job["connectionGeneration"]
                            && locked.job["payloadDigest"] == j.job["payloadDigest"]
                            && locked.job["leaseVersion"] == j.job["leaseVersion"]
                            && locked.job["leasedUntilEpochMs"] == j.job["leasedUntilEpochMs"],
                        "RUNNER_JOB_LOCAL_AUTHORITY_CHANGED"
                    );
                    locked.job = response["job"].clone();
                    Ok(())
                })
                .await;
            }
            Err(_) => {
                if now_millis() >= j.job["leasedUntilEpochMs"].as_u64().unwrap_or(0) {
                    expiry.trigger();
                }
            }
        }
    }
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

#[cfg(test)]
mod fingerprint_admission_tests {
    use super::*;
    #[test]
    fn fingerprint_await_cannot_extend_lease_or_ignore_cancellation() {
        let temp = tempfile::tempdir().unwrap();
        let api = crate::api::Api::for_test_origin("http://127.0.0.1:9").unwrap();
        let daemon = Daemon::new(
            temp.path().into(),
            api.clone(),
            crate::auth::Auth::test_enrolled(api, "org", "runner"),
        )
        .unwrap();
        let original = crate::jobs::protocol_tests::journal();
        let journal = Arc::new(Mutex::new(original.clone()));
        let cancel = AtomicBool::new(false);
        assert!(require_job_admission(&daemon, &original, &journal, &cancel).is_ok());
        cancel.store(true, Ordering::SeqCst);
        assert!(require_job_admission(&daemon, &original, &journal, &cancel).is_err());
        cancel.store(false, Ordering::SeqCst);
        for drift in [
            "leaseVersion",
            "leasedUntilEpochMs",
            "runnerId",
            "payloadDigest",
        ] {
            let mut changed = original.clone();
            changed.job[drift] = json!(0);
            *journal.lock().unwrap() = changed;
            assert!(require_job_admission(&daemon, &original, &journal, &cancel).is_err());
        }
        *journal.lock().unwrap() = original.clone();
        daemon.execution.set_draining(true);
        assert!(require_job_admission(&daemon, &original, &journal, &cancel).is_err());
    }
}

#[cfg(test)]
mod responsiveness_tests {
    use super::*;
    use crate::jobs::protocol_tests::{daemon, journal, receive, reply};
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn responsive_renewal_proceeds_while_output_response_is_held() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let temp = tempfile::tempdir().unwrap();
        let daemon = daemon(
            temp.path(),
            format!("http://{}", listener.local_addr().unwrap()),
        );
        let shared = Arc::new(Mutex::new(journal()));
        let path = temp.path().join("jobs/slow-output/journal.json");
        state::write_json(&path, &snapshot(&shared).unwrap()).unwrap();
        std::fs::write(path.parent().unwrap().join("stdout"), b"held output").unwrap();
        let d = daemon.clone();
        let j = shared.clone();
        let p = path.clone();
        let output = tokio::spawn(async move { stream_events(&d, &p, &j).await });
        let (held, body) = receive(&listener).await;
        assert_eq!(body["events"][0]["eventType"], "output");
        let finished = Arc::new(AtomicBool::new(false));
        let cancel = Arc::new(AtomicBool::new(false));
        let lease = tokio::spawn(maintain_lease(
            daemon.clone(),
            path.clone(),
            shared.clone(),
            cancel.clone(),
            finished.clone(),
            Arc::new(LeaseExpiryCancellation::new(cancel.clone())),
            Duration::from_millis(30),
        ));
        let start = Instant::now();
        for version in 8..=10 {
            let (stream, body) = tokio::time::timeout(Duration::from_secs(2), receive(&listener))
                .await
                .unwrap();
            assert!(body.get("events").is_none());
            assert_eq!(body["leaseVersion"], version - 1);
            let mut renewed = snapshot(&shared).unwrap().job;
            renewed["leaseVersion"] = json!(version);
            if version == 10 {
                renewed["status"] = json!("canceling");
            }
            reply(stream, json!({"job":renewed})).await;
        }
        finished.store(true, Ordering::SeqCst);
        lease.await.unwrap();
        assert!(cancel.load(Ordering::SeqCst));
        assert!(!output.is_finished());
        assert_eq!(snapshot(&shared).unwrap().job["leaseVersion"], 10);
        println!(
            "independent renewal: held_output=true renewals=3 cadence_ms=30 elapsed_ms={}",
            start.elapsed().as_millis()
        );
        reply(held, json!({})).await;
        assert!(output.await.unwrap().unwrap());
        assert_eq!(snapshot(&shared).unwrap().stdout_offset, 11);
    }
}

#[cfg(test)]
mod observer_binding_tests {
    use super::*;

    #[test]
    fn responsive_observer_disk_await_fences_binding_drift_and_allows_renewal() {
        let original = crate::jobs::protocol_tests::journal();
        let shared = Arc::new(Mutex::new(original.clone()));
        let observer = Observer {
            path: PathBuf::from("unused"),
            journal: shared.clone(),
        };
        drop(observer.blocking_guard().unwrap());
        assert!(observer.after_blocking().is_ok());
        // The renewal task may advance its mutable lease between fsync and
        // target admission without changing this committed execution owner.
        let mut renewed = original.clone();
        renewed.job["leaseVersion"] = json!(8);
        renewed.job["leasedUntilEpochMs"] = json!(2_100_000_000_000u64);
        *shared.lock().unwrap() = renewed;
        assert!(observer.after_blocking().is_ok());
        for field in ["id", "runnerId", "connectionGeneration", "payloadDigest"] {
            let mut changed = original.clone();
            changed.job[field] = json!("replacement");
            *shared.lock().unwrap() = changed;
            assert!(observer.after_blocking().is_err(), "{field}");
        }
        for field in [
            "organization",
            "session",
            "recovery",
            "terminal_key",
            "expired",
            "phase",
        ] {
            let mut changed = original.clone();
            match field {
                "organization" => changed.organization = "replacement".into(),
                "session" => changed.session = "replacement".into(),
                "recovery" => changed.recovery_session = Some("replacement".into()),
                "terminal_key" => changed.terminal_key = "replacement".into(),
                "expired" => changed.job["leasedUntilEpochMs"] = json!(0),
                "phase" => changed.phase = JournalPhase::TerminalPending,
                _ => unreachable!(),
            }
            *shared.lock().unwrap() = changed;
            assert!(observer.after_blocking().is_err(), "{field}");
        }
    }
}
