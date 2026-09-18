use super::*;

pub(super) fn delivery_blocked(code: &str) -> bool {
    [
        "AUTH_REQUIRED",
        "AUTH_EXPIRED",
        "LOGOUT_PENDING",
        "AUTHORIZATION_FAILED",
    ]
    .contains(&code)
        || code.ends_with("_NOT_FOUND")
        || code.ends_with("_TOKEN_INVALID")
}
pub(super) fn fence_error(code: &str) -> bool {
    [
        "RUNNER_JOB_NOT_FOUND",
        "RUNNER_SESSION_NOT_FOUND",
        "RUNNER_JOB_LEASE_EXPIRED",
        "RUNNER_JOB_LEASE_CONFLICT",
        "RUNNER_JOB_LEASE_INVALID",
    ]
    .contains(&code)
}
pub(super) async fn reclaim_terminal(
    daemon: &Daemon,
    path: &Path,
    journal: &Arc<Mutex<Journal>>,
) -> Result<()> {
    let j = snapshot(journal)?;
    let id = j.job["id"].as_str().context("BACKEND_PROTOCOL_ERROR")?;
    let session = j.recovery_session.as_ref().unwrap_or(&j.session);
    let response = daemon.backend(&j.organization, "POST", &format!("v1/jobs/{id}/reclaim/"),
        Some(json!({"sessionId":session,"expectedLeaseVersion":j.job["leaseVersion"],"payloadDigest":j.job["payloadDigest"],"terminalSubmission":true,"idempotencyKey":j.terminal_key})), Some(&j.terminal_key)).await?;
    {
        let mut record = journal.lock().unwrap();
        record.job = response["job"].clone();
        record.session = session.clone();
        record.recovery_session = None;
    }
    save(journal, path)
}
pub(super) async fn retry_delivery(
    daemon: &Daemon,
    path: &Path,
    journal: &Arc<Mutex<Journal>>,
    error: anyhow::Error,
) -> Result<()> {
    let code = error.to_string();
    if fence_error(&code) {
        if let Err(reclaim_error) = reclaim_terminal(daemon, path, journal).await {
            let reclaim_code = reclaim_error.to_string();
            if delivery_blocked(&reclaim_code)
                || [
                    "RUNNER_JOB_NOT_RECLAIMABLE",
                    "RUNNER_JOB_PAYLOAD_MISMATCH",
                    "RUNNER_JOB_IDEMPOTENCY_MISMATCH",
                ]
                .contains(&reclaim_code.as_str())
            {
                journal
                    .lock()
                    .unwrap()
                    .transition(JournalPhase::DeliveryBlocked)?;
                save(journal, path)?;
                return Err(reclaim_error);
            }
        }
    } else if delivery_blocked(&code)
        || !error
            .downcast_ref::<crate::api::ApiError>()
            .is_some_and(|e| e.retryable)
    {
        journal
            .lock()
            .unwrap()
            .transition(JournalPhase::DeliveryBlocked)?;
        save(journal, path)?;
        return Err(error);
    }
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    Ok(())
}
pub(super) async fn deliver(
    daemon: Arc<Daemon>,
    path: &Path,
    journal: Arc<Mutex<Journal>>,
) -> Result<()> {
    loop {
        let mut j = snapshot(&journal)?;
        if crate::retention::deleted(&daemon.dir, &j.job) {
            crate::retention::purge_job(path)?;
            return Ok(());
        }
        if j.phase == "exited" {
            match async {
                drain_events(&daemon, path, &journal).await?;
                materialize_terminal(&daemon, path, &journal).await
            }
            .await
            {
                Ok(()) => j = snapshot(&journal)?,
                Err(error) => {
                    let code = error.to_string();
                    if fence_error(&code)
                        || delivery_blocked(&code)
                        || error
                            .downcast_ref::<crate::api::ApiError>()
                            .is_some_and(|e| e.retryable)
                    {
                        retry_delivery(&daemon, path, &journal, error).await?;
                        continue;
                    }
                    {
                        let mut record = journal.lock().unwrap();
                        record.transition(JournalPhase::TerminalPending)?;
                        record.result = None;
                        record.error = Some(
                            json!({"code":"ARTIFACT_FINALIZATION_FAILED","message":"Declared output could not be registered"}),
                        );
                    }
                    save(&journal, path)?;
                    j = snapshot(&journal)?;
                }
            }
        }
        let id = j.job["id"].as_str().context("BACKEND_PROTOCOL_ERROR")?;
        let failed = j.error.is_some();
        let mut body = fence(&j);
        body["idempotencyKey"] = json!(j.terminal_key);
        if failed {
            body["error"] = j.error.clone().unwrap()
        } else {
            body["result"] = j.result.clone().context("TERMINAL_MISSING")?
        };
        match daemon
            .backend(
                &j.organization,
                "POST",
                &format!("v1/jobs/{id}/{}/", if failed { "fail" } else { "complete" }),
                Some(body),
                Some(&j.terminal_key),
            )
            .await
        {
            Ok(_) => {
                {
                    let mut locked = journal.lock().unwrap();
                    locked.transition(JournalPhase::Acknowledged)?;
                    locked.acknowledged_at = Some(state::now());
                }
                save(&journal, path)?;
                return Ok(());
            }
            Err(error) => {
                // A replacement fence permits terminal delivery and output replay only.
                retry_delivery(&daemon, path, &journal, error).await?;
            }
        }
    }
}
