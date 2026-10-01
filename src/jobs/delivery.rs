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
        "RUNNER_JOB_LOCAL_AUTHORITY_CHANGED",
        "RUNNER_JOB_LOCAL_LEASE_CHANGED",
    ]
    .contains(&code)
}
pub(super) fn delivery_diagnostic(
    category: DeliveryDiagnosticCategory,
    error: &anyhow::Error,
) -> DeliveryDiagnostic {
    let api = error.downcast_ref::<crate::api::ApiError>();
    let local_code = error.to_string();
    // Never persist a free-form error message or provider output as a
    // diagnostic code. Local typed failures use the same narrow grammar.
    let candidate = api.map_or(local_code.as_str(), |error| error.code.as_str());
    let code = if !candidate.is_empty()
        && candidate.len() <= 100
        && candidate
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
    {
        candidate.to_owned()
    } else {
        "DELIVERY_FAILED".into()
    };
    DeliveryDiagnostic {
        schema_version: "loomex.runner.delivery-diagnostic/v1".into(),
        category,
        code,
        observed_at_epoch_ms: now_millis(),
        correlation_id: api
            .and_then(|error| error.correlation_id.as_deref())
            .and_then(|value| Uuid::parse_str(value).ok())
            .map(|value| value.to_string()),
    }
}

fn block_delivery(
    path: &Path,
    journal: &Arc<Mutex<Journal>>,
    category: DeliveryDiagnosticCategory,
    error: &anyhow::Error,
) -> Result<()> {
    let mut record = journal
        .lock()
        .map_err(|_| anyhow::anyhow!("journal lock"))?;
    record.transition(JournalPhase::DeliveryBlocked)?;
    record.delivery_diagnostic = Some(delivery_diagnostic(category, error));
    persist(path, &record)
}

pub(super) async fn handle_finalization_error(
    daemon: &Daemon,
    path: &Path,
    journal: &Arc<Mutex<Journal>>,
    category: DeliveryDiagnosticCategory,
    error: anyhow::Error,
) -> Result<()> {
    {
        let mut record = journal
            .lock()
            .map_err(|_| anyhow::anyhow!("journal lock"))?;
        if record.first_failure_diagnostic.is_none() {
            record.first_failure_diagnostic = Some(delivery_diagnostic(category, &error));
        }
    }
    save(journal, path)?;
    let code = error.to_string();
    if fence_error(&code)
        || delivery_blocked(&code)
        || error
            .downcast_ref::<crate::api::ApiError>()
            .is_some_and(|e| e.retryable)
    {
        retry_delivery(daemon, path, journal, category, error).await?;
    } else {
        {
            let mut record = journal.lock().unwrap();
            record.transition(JournalPhase::TerminalPending)?;
            // The original process result and spool paths remain private,
            // durable evidence. `deliver` sends only `error` when both exist.
            record.error = Some(json!({
                "code":"ARTIFACT_FINALIZATION_FAILED",
                "message":"Declared output could not be registered"
            }));
        }
        save(journal, path)?;
    }
    Ok(())
}
pub(super) async fn reclaim_terminal(
    daemon: &Daemon,
    path: &Path,
    journal: &Arc<Mutex<Journal>>,
) -> Result<()> {
    let j = snapshot(journal)?;
    let id = j.job["id"].as_str().context("BACKEND_PROTOCOL_ERROR")?;
    let session = j.recovery_session.as_ref().unwrap_or(&j.session);
    let credential = daemon.auth.credential(&j.organization).await?;
    if j.job["runnerId"]
        .as_str()
        .is_some_and(|id| id != credential.subject)
    {
        bail!("RUNNER_JOB_RUNNER_MISMATCH");
    }
    // Reclaim is fenced by the idempotency key of the original job. The
    // terminal key belongs only to complete/fail and can differ from it.
    // Older keyless jobs are represented by null in the backend projection;
    // an absent field in an older journal has the same server-side meaning.
    let reclaim_key = match j.job.get("idempotencyKey") {
        Some(Value::String(key)) => key.as_str(),
        None | Some(Value::Null) => "",
        _ => bail!("BACKEND_PROTOCOL_ERROR"),
    };
    let response = daemon.api.request_job_with_stale_proof_retry(
        "POST",
        &format!("v1/jobs/{id}/reclaim/"),
        Some(json!({"sessionId":session,"expectedLeaseVersion":j.job["leaseVersion"],"payloadDigest":j.job["payloadDigest"],"terminalSubmission":true,"idempotencyKey":reclaim_key})),
        &credential,
        (!reclaim_key.is_empty()).then_some(reclaim_key),
        || job_authority_unchanged(&j, journal, false),
    ).await?;
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
    category: DeliveryDiagnosticCategory,
    error: anyhow::Error,
) -> Result<()> {
    let code = error.to_string();
    if category == DeliveryDiagnosticCategory::LeaseReclaim {
        // This is the result of a reclaim attempt, not an error that should
        // start another reclaim. A definitive fence rejection is one outcome.
        if code != "RUNNER_JOB_LEASE_ACTIVE"
            && !error
                .downcast_ref::<crate::api::ApiError>()
                .is_some_and(|error| error.retryable)
        {
            block_delivery(path, journal, category, &error)?;
            return Err(error);
        }
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        return Ok(());
    }
    if fence_error(&code) {
        // Reclaim must use a new, independently connected session. Keeping an
        // old worker alive here would hold the local job claim forever and
        // prevent `recover` from seeing its durable terminal evidence.
        if snapshot(journal)?.recovery_session.is_none() {
            return Err(anyhow::anyhow!("RUNNER_JOB_RECOVERY_SESSION_REQUIRED"));
        }
        if let Err(reclaim_error) = reclaim_terminal(daemon, path, journal).await {
            let reclaim_code = reclaim_error.to_string();
            // A reclaim rejection is authoritative. Only an active lease or
            // explicitly retryable transport/server failure may be observed
            // again; repeating a rejected proof would hide the failure.
            if reclaim_code != "RUNNER_JOB_LEASE_ACTIVE"
                && !reclaim_error
                    .downcast_ref::<crate::api::ApiError>()
                    .is_some_and(|error| error.retryable)
            {
                block_delivery(
                    path,
                    journal,
                    DeliveryDiagnosticCategory::LeaseReclaim,
                    &reclaim_error,
                )?;
                return Err(reclaim_error);
            }
        }
    } else if delivery_blocked(&code)
        || !error
            .downcast_ref::<crate::api::ApiError>()
            .is_some_and(|e| e.retryable)
    {
        block_delivery(path, journal, category, &error)?;
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
        if j.recovery_session.is_some() {
            // A fresh session must acquire terminal-only authority before any
            // old output chunk or artifact transfer is sent again.
            match reclaim_terminal(&daemon, path, &journal).await {
                Ok(()) => continue,
                Err(error) if error.to_string() == "RUNNER_JOB_LEASE_ACTIVE" => {
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    continue;
                }
                Err(error) => {
                    retry_delivery(
                        &daemon,
                        path,
                        &journal,
                        DeliveryDiagnosticCategory::LeaseReclaim,
                        error,
                    )
                    .await?;
                    continue;
                }
            }
        }
        if j.phase == "exited" {
            let finalization = match drain_events(&daemon, path, &journal).await {
                Ok(()) => materialize_terminal(&daemon, path, &journal)
                    .await
                    .map_err(|error| (DeliveryDiagnosticCategory::ArtifactFinalization, error)),
                Err(error) => Err((DeliveryDiagnosticCategory::OutputDelivery, error)),
            };
            match finalization {
                Ok(()) => j = snapshot(&journal)?,
                Err((category, error)) => {
                    handle_finalization_error(&daemon, path, &journal, category, error).await?;
                    j = snapshot(&journal)?;
                    if j.phase == JournalPhase::Exited {
                        continue;
                    }
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
        match backend_job(
            &daemon,
            &journal,
            &j,
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
                retry_delivery(
                    &daemon,
                    path,
                    &journal,
                    DeliveryDiagnosticCategory::TerminalSubmission,
                    error,
                )
                .await?;
            }
        }
    }
}
