//! Separate pre-adoption maintenance authority. Historical uninstall bytes are
//! immutable; resolving local observation obligations is not a destructive gate.
use super::*;

const WORK_SCHEMA: &str = "app.loomex.runner.uninstall-work/v1";
#[derive(Debug)]
pub(crate) struct WorkRefusal(pub &'static str);
impl std::fmt::Display for WorkRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for WorkRefusal {}
fn refusal(code: &'static str) -> anyhow::Error {
    WorkRefusal(code).into()
}
#[derive(Debug)]
struct WorkNativeFailure {
    code: &'static str,
    diagnostic: Value,
}
impl std::fmt::Display for WorkNativeFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code)
    }
}
impl std::error::Error for WorkNativeFailure {}
fn require_result(result: &Value) -> Result<()> {
    if result["ok"] == true {
        return Ok(());
    }
    let native = &result["error"];
    let diagnostic = if native["code"].as_str().is_some_and(|code| {
        matches!(
            code,
            "STORE_ACCESS_REQUIRED"
                | "STORE_ACCESS_DENIED"
                | "STORE_OPERATION_PENDING"
                | "STORE_INVALID"
                | "STORE_OWNER_BUSY"
                | "STORE_UNAVAILABLE"
                | "AUTH_IDENTITY_CHANGED"
                | "AUTH_RECONCILIATION_REQUIRED"
                | "AUTH_RECOVERY_PENDING"
                | "INVALID_API_ORIGIN"
        )
    }) {
        serde_json::from_str(&maintenance_failure(&serde_json::to_vec(native)?).to_string())
            .unwrap_or(Value::Null)
    } else {
        Value::Null
    };
    Err(WorkNativeFailure {
        code: native_failure_code(result),
        diagnostic,
    }
    .into())
}
pub(crate) fn valid_work_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}
fn require(test: bool, code: &'static str) -> Result<()> {
    if !test {
        return Err(refusal(code));
    }
    Ok(())
}

pub(crate) fn work_owner_reference(paths: &lifecycle::Paths) -> Value {
    let path = paths.state_dir.join("bootstrap-uninstall.json");
    let Ok(bytes) = regular_bytes(&path) else {
        return Value::Null;
    };
    let Ok(journal) = serde_json::from_slice::<Value>(&bytes) else {
        return Value::Null;
    };
    if !matches!(journal["schema"].as_str(), Some(SCHEMA | OLD_SCHEMA))
        || !matches!(
            journal["phase"].as_str(),
            Some(
                "prepared"
                    | "idle_verified"
                    | "stop_intent"
                    | "stopped"
                    | "revocation_pending"
                    | "revoked"
                    | "cleanup"
                    | "terminal"
            )
        )
    {
        return Value::Null;
    }
    let operation = (journal["schema"] == SCHEMA)
        .then(|| {
            journal["operationId"]
                .as_str()
                .and_then(|value| Uuid::parse_str(value).ok())
        })
        .flatten();
    json!({"owner":"bootstrap_uninstall","journalSchema":journal["schema"],"journalSha256":state::digest(&bytes),"phase":journal["phase"],"adoptionStarted":!journal["recovery"].is_null(),"operationId":operation})
}
fn journal_binding(paths: &lifecycle::Paths, args: &Arguments) -> Result<(Value, Vec<u8>, Value)> {
    let bytes = regular_bytes(&paths.state_dir.join("bootstrap-uninstall.json"))?;
    let old: Value = serde_json::from_slice(&bytes)?;
    require(
        args.expected_old_journal_sha256.as_deref() == Some(&state::digest(&bytes)),
        "UNINSTALL_WORK_BINDING_CHANGED",
    )?;
    require(
        matches!(old["schema"].as_str(), Some(SCHEMA | OLD_SCHEMA))
            && old["phase"] == "prepared"
            && old["recovery"].is_null()
            && old["cleanup"]["stateDeletingStarted"] != true,
        "UNINSTALL_WORK_PHASE_UNSUPPORTED",
    )?;
    lifecycle::require_terminal_before_uninstall(paths)?;
    validate_owned_installation(paths, &old["receipt"], &journal_owned(&old), false)?;
    validate_helper(paths, &old)?;
    require(
        serde_json::from_slice::<Value>(&regular_bytes(
            &paths.state_dir.join("install-receipt.json"),
        )?)? == old["receipt"],
        "UNINSTALL_WORK_BINDING_CHANGED",
    )?;
    let identity = if old["schema"] == SCHEMA {
        validate_journal(paths, &old)?;
        validated_current_identity(&old)?
    } else {
        prior_identity(paths)?
    };
    Ok((old, bytes, identity))
}

/// Used by native preflight without the destructive managed-work eligibility gate.
pub(crate) async fn work_preflight(
    paths: &lifecycle::Paths,
    args: &Arguments,
    release: &Path,
    manifest: &Value,
    payload: &Path,
) -> Result<Value> {
    let (old, bytes, _) = journal_binding(paths, args)?;
    require(
        bytes.len() <= 16 * 1024 * 1024,
        "UNINSTALL_WORK_AUDIT_LIMIT",
    )?;
    require(
        digest_file(&std::env::current_exe()?)? == manifest["bootstrap"]["sha256"],
        "UNINSTALL_WORK_BINDING_CHANGED",
    )?;
    let transition = validate_recovery_candidate(args, &old, manifest, payload).await?;
    let expected_release = args.expected_release_path.as_deref().unwrap_or(release);
    if paths.state_dir.join("uninstall-work.json").try_exists()? {
        let work: Value = work_json(&paths.state_dir.join("uninstall-work.json"))?;
        require(
            work["schema"] == WORK_SCHEMA
                && work["journalSha256"] == state::digest(&bytes)
                && work["releasePath"].as_str()
                    == Some(expected_release.to_string_lossy().as_ref())
                && work["releaseManifestSha256"] == digest_file(&release.join("manifest.json"))?,
            "UNINSTALL_WORK_BINDING_CHANGED",
        )?;
    }
    let assessment = uninstall_state::assess_state(&paths.state_dir)?;
    if args.work_action.as_deref() == Some("retire-local") {
        let work: Option<Value> = if paths.state_dir.join("uninstall-work.json").try_exists()? {
            Some(work_json(&paths.state_dir.join("uninstall-work.json"))?)
        } else {
            None
        };
        let resuming = work.as_ref().is_some_and(|value| {
            value["attempt"]["action"] == "retire-local"
                && value["attempt"]["expectedAssessmentSha256"].as_str()
                    == args.expected_assessment_sha256.as_deref()
        });
        require(
            resuming
                || args.expected_assessment_sha256.as_deref()
                    == Some(&assessment.assessment_digest),
            "UNINSTALL_WORK_ASSESSMENT_CHANGED",
        )?;
    }
    require(
        uninstall_state::maintenance_preview(&paths.state_dir)?.len() <= 256,
        "UNINSTALL_WORK_PREVIEW_LIMIT",
    )?;
    Ok(
        json!({"eligible":true,"readOnly":true,"action":args.work_action,"signingTransition":if transition==SigningTransition::ForegroundAuthorizationRequired {"needs_explicit_transition"}else{"eligible"},"accessAttempted":false,"nativeAccessVerified":false,"ownerReference":work_owner_reference(paths),"assessment":assessment}),
    )
}

fn jobs_quiescent(paths: &lifecycle::Paths) -> Result<()> {
    let root = paths.state_dir.join("jobs");
    if !root.try_exists()? {
        return Ok(());
    }
    require(
        fs::symlink_metadata(&root)?.is_dir()
            && !fs::symlink_metadata(&root)?.file_type().is_symlink(),
        "UNINSTALL_WORK_QUIESCENCE_REQUIRED",
    )?;
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        if entry
            .file_name()
            .to_str()
            .and_then(|s| Uuid::parse_str(s).ok())
            .is_none()
        {
            return Err(refusal("UNINSTALL_WORK_QUIESCENCE_REQUIRED"));
        }
        let record: Value =
            serde_json::from_slice(&regular_bytes(&entry.path().join("journal.json"))?)?;
        let terminal = matches!(
            record["phase"].as_str(),
            Some("acknowledged" | "terminal_pending" | "delivery_blocked" | "exited")
        );
        require(terminal, "UNINSTALL_WORK_QUIESCENCE_REQUIRED")?;
        if !record["identity"].is_null() {
            require(
                record["result"]["managedGroupStopped"] == true
                    && record["result"]["indeterminate"] == false,
                "UNINSTALL_WORK_QUIESCENCE_REQUIRED",
            )?;
            require(
                record["result"]["descendantCleanup"]
                    .as_str()
                    .is_some_and(|value| !value.starts_with("indeterminate")),
                "UNINSTALL_WORK_QUIESCENCE_REQUIRED",
            )?;
            for (key, group) in [("pid", false), ("pgid", true)] {
                let pid = record["identity"][key]
                    .as_i64()
                    .and_then(|p| i32::try_from(p).ok())
                    .filter(|p| *p > 1)
                    .ok_or_else(|| refusal("UNINSTALL_WORK_QUIESCENCE_REQUIRED"))?;
                let rc = unsafe { libc::kill(if group { -pid } else { pid }, 0) };
                require(
                    rc == -1 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH),
                    "UNINSTALL_WORK_QUIESCENCE_REQUIRED",
                )?;
            }
        } else {
            require(
                record["phase"] == "acknowledged"
                    || (record["result"].is_object() && record["error"]["indeterminate"] != true),
                "UNINSTALL_WORK_QUIESCENCE_REQUIRED",
            )?;
        }
    }
    Ok(())
}
fn work_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    Ok(serde_json::from_slice(&regular_bytes(path)?)?)
}
fn save_work(paths: &lifecycle::Paths, value: &Value) -> Result<()> {
    state::write_json(&paths.state_dir.join("uninstall-work.json"), value)
}
async fn stop_service(paths: &lifecycle::Paths, old: &Value, work: &mut Value) -> Result<()> {
    let observation = label_observation(paths)
        .await
        .map_err(|_| refusal("UNINSTALL_WORK_QUIESCENCE_REQUIRED"))?;
    let Some(pid) = observation else {
        verify_recorded_process_exit(old)?;
        return Ok(());
    };
    // An uncertain previous stop is observation-only. Never boot out a reused PID.
    if work["serviceStop"]["request"] == "unconfirmed" {
        return Err(refusal("UNINSTALL_WORK_MAINTENANCE_PENDING"));
    }
    let marker: Value = work_json(&paths.state_dir.join("drain.json"))?;
    require(
        marker["idempotencyKey"]
            .as_str()
            .and_then(|s| Uuid::parse_str(s).ok())
            .is_some(),
        "UNINSTALL_WORK_QUIESCENCE_REQUIRED",
    )?;
    let status = control::client(&paths.state_dir, "status.get", json!({})).await?;
    require(
        status.get("error").is_none()
            && status["result"]["activeJobs"] == 0
            && status["result"]["draining"] == true
            && status["result"]["version"] == old["receipt"]["version"],
        "UNINSTALL_WORK_QUIESCENCE_REQUIRED",
    )?;
    jobs_quiescent(paths)?;
    let agent = paths.launch_agents_dir.join("app.loomex.runner.plist");
    require(
        digest_file(&agent)? == old["receipt"]["launchAgentSha256"]
            || old["receipt"]["launchAgentSha256"].is_null(),
        "UNINSTALL_WORK_BINDING_CHANGED",
    )?;
    work["serviceStop"] = json!({"request":"unconfirmed","pid":pid,"launchAgentSha256":digest_file(&agent)?,"drainSha256":digest_file(&paths.state_dir.join("drain.json"))?});
    save_work(paths, work)?;
    let mut command = tokio::process::Command::new("/bin/launchctl");
    command
        .arg("bootout")
        .arg(format!("gui/{}/app.loomex.runner", unsafe {
            libc::geteuid()
        }))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    let mut child = command
        .spawn()
        .map_err(|_| refusal("UNINSTALL_WORK_MAINTENANCE_PENDING"))?;
    tokio::time::timeout(std::time::Duration::from_secs(8), child.wait())
        .await
        .map_err(|_| refusal("UNINSTALL_WORK_MAINTENANCE_PENDING"))??;
    require(
        label_observation(paths).await?.is_none(),
        "UNINSTALL_WORK_MAINTENANCE_PENDING",
    )?;
    let mut stopped = json!({"stopEvidence":{"pid":pid}});
    stopped["paths"] = old["paths"].clone();
    verify_recorded_process_exit(&stopped)
        .map_err(|_| refusal("UNINSTALL_WORK_MAINTENANCE_PENDING"))?;
    Ok(())
}
async fn quiescent_singleton(paths: &lifecycle::Paths, old: &Value) -> Result<File> {
    require(
        label_observation(paths).await?.is_none(),
        "UNINSTALL_WORK_QUIESCENCE_REQUIRED",
    )?;
    verify_recorded_process_exit(old)?;
    jobs_quiescent(paths)?;
    let guard =
        singleton(paths, false).map_err(|_| refusal("UNINSTALL_WORK_MAINTENANCE_PENDING"))?;
    let targets = old["paths"]
        .as_array()
        .context("invalid work paths")?
        .iter()
        .map(|v| v.as_str().map(PathBuf::from).context("invalid work path"))
        .collect::<Result<Vec<_>>>()?;
    lifecycle::prune_in_use(&targets)
        .await
        .map_err(|_| refusal("UNINSTALL_WORK_QUIESCENCE_REQUIRED"))?;
    Ok(guard)
}
fn audit_projection(value: &Value) -> Value {
    if value["kind"] == "presentation_operation" {
        let mut safe = json!({"kind":"presentation_operation","privateRecordSha256":state::json_digest(value)});
        for key in [
            "recordDigest",
            "operationReference",
            "scopeReference",
            "originalKeyReference",
            "receiptDigest",
            "responseDigest",
        ] {
            if value[key].as_str().is_some_and(valid_work_digest) {
                safe[key] = value[key].clone();
            }
        }
        if value.get("params").is_some() {
            safe["paramsDigest"] = json!(state::json_digest(&value["params"]));
            safe["reconciliationDigest"] = json!(state::json_digest(&value["reconciliation"]));
            safe["operationReference"] = json!(state::json_digest(&value["recordId"]));
            safe["scopeReference"] = json!(state::json_digest(&json!([
                value["organizationId"],
                value["accountSubject"],
                value["installationId"]
            ])));
            safe["originalKeyReference"] = json!(state::json_digest(&value["operationKey"]));
        }
        if matches!(
            value["method"].as_str(),
            Some(
                "workflows.create"
                    | "workflows.update"
                    | "workflows.patch"
                    | "workflows.publish"
                    | "builder.start"
                    | "editor.start"
                    | "persona.roles.create"
                    | "personas.create"
                    | "personas.chat_context.create"
                    | "personas.memory.write"
                    | "personas.memory.update"
            )
        ) {
            safe["method"] = value["method"].clone();
        }
        if matches!(
            value["status"].as_str(),
            Some("pending" | "ambiguous" | "completed")
        ) {
            safe["status"] = value["status"].clone();
        }
        if value["schemaVersion"] == "loomex.domain-operation-reconciliation/v1" {
            safe["schemaVersion"] = value["schemaVersion"].clone();
        }
        if matches!(value["state"].as_str(), Some("unresolved" | "reconciled")) {
            safe["state"] = value["state"].clone();
        }
        return safe;
    }
    match value {
        Value::Array(values) => Value::Array(values.iter().map(audit_projection).collect()),
        Value::Object(values) => Value::Object(
            values
                .iter()
                .map(|(key, value)| (key.clone(), audit_projection(value)))
                .collect(),
        ),
        _ => value.clone(),
    }
}
fn audit_cache_projection(value: &Value) -> Value {
    let mut safe = json!({"schema":"app.loomex.runner.uninstall-work-cache-audit/v1","privateRecordSha256":state::json_digest(value)});
    for key in [
        "requestDigest",
        "beforeSha256",
        "afterSha256",
        "responseDigest",
        "keyReference",
    ] {
        if value["transition"][key]
            .as_str()
            .is_some_and(valid_work_digest)
        {
            safe[key] = value["transition"][key].clone();
        }
    }
    safe["pathReference"] = json!(state::json_digest(&value["transition"]["path"]));
    if let Some(targets) = value["transition"]["relatedTargets"].as_array() {
        safe["relatedTargets"] = Value::Array(targets.iter().map(|target| {
            let mut summary = json!({"pathReference":state::json_digest(&target["path"]),"privateRecordSha256":state::json_digest(target)});
            for key in ["requestDigest","beforeSha256","afterSha256","responseDigest","keyReference"] {
                if target[key].as_str().is_some_and(valid_work_digest) {summary[key]=target[key].clone();}
            }
            summary
        }).collect());
    }
    safe
}
fn audit(paths: &lifecycle::Paths, work: &Value, old_bytes: &[u8], result: &Value) -> Result<()> {
    let id = work["operationId"].as_str().context("invalid work owner")?;
    let parent = paths.state_dir.join("recovery-evidence");
    state::private_dir(&parent)?;
    let root = parent.join(id);
    state::private_dir(&root)?;
    immutable_copy(&root.join("original-uninstall.json"), old_bytes)?;
    let attempt = result["attemptId"]
        .as_str()
        .context("invalid work attempt")?;
    Uuid::parse_str(attempt)?;
    // Only scoped continuation receipts, never credentials or human answers.
    let evidence_files = fs::read_dir(&root)?.collect::<std::io::Result<Vec<_>>>()?;
    require(
        evidence_files.len() < 20_000
            && evidence_files
                .iter()
                .map(|entry| entry.metadata().map(|metadata| metadata.len()))
                .collect::<std::io::Result<Vec<_>>>()?
                .iter()
                .sum::<u64>()
                < 64 * 1024 * 1024,
        "UNINSTALL_WORK_AUDIT_LIMIT",
    )?;
    let encoded = serde_json::to_vec(&audit_projection(result))?;
    require(
        encoded.len() <= 16 * 1024 * 1024 && old_bytes.len() <= 16 * 1024 * 1024,
        "UNINSTALL_WORK_AUDIT_LIMIT",
    )?;
    immutable_copy(
        &root.join(format!(
            "resolution-{attempt}-{}.json",
            state::digest(&encoded)
        )),
        &encoded,
    )?;
    archive_approval(paths, work, old_bytes, result, &root)?;
    let requests = paths
        .state_dir
        .join(format!("uninstall-work-requests-{attempt}.json"));
    if requests.try_exists()? {
        immutable_copy(
            &root.join(format!("requests-{attempt}.json")),
            &serde_json::to_vec(&audit_projection(&work_json(&requests)?))?,
        )?;
    }
    for index in 0..256 {
        let path = paths
            .state_dir
            .join(format!("uninstall-work-checkpoint-{attempt}-{index}.json"));
        if path.try_exists()? {
            immutable_copy(
                &root.join(format!("record-{attempt}-{index}.json")),
                &serde_json::to_vec(&audit_projection(&work_json(&path)?))?,
            )?;
        }
        let cache = paths
            .state_dir
            .join(format!("uninstall-work-cache-{attempt}-{index}.json"));
        if cache.try_exists()? {
            let value: Value = work_json(&cache)?;
            let request_set: Value = work_json(&requests)?;
            let request = &request_set["requests"][index];
            require(
                value["schema"] == "app.loomex.runner.uninstall-work-cache-transition/v1"
                    && value["operationId"] == id
                    && value["attemptId"] == attempt
                    && value["index"] == index
                    && request["kind"] == "presentation_operation"
                    && value["requestDigest"] == state::json_digest(request)
                    && value["transition"]["schema"] == "app.loomex.runner.uninstall-work-cache/v1"
                    && value["transition"]["beforeSha256"]
                        .as_str()
                        .is_some_and(valid_work_digest)
                    && value["transition"]["afterSha256"]
                        .as_str()
                        .is_some_and(valid_work_digest),
                "UNINSTALL_WORK_BINDING_CHANGED",
            )?;
            if let Some(targets) = value["transition"]["relatedTargets"].as_array() {
                require(
                    targets.len() <= 1
                        && targets.iter().all(|target| {
                            target["schema"] == "app.loomex.runner.uninstall-work-cache/v1"
                                && target["beforeSha256"]
                                    .as_str()
                                    .is_some_and(valid_work_digest)
                                && target["afterSha256"]
                                    .as_str()
                                    .is_some_and(valid_work_digest)
                        }),
                    "UNINSTALL_WORK_BINDING_CHANGED",
                )?;
            } else {
                require(
                    value["transition"]["relatedTargets"].is_null(),
                    "UNINSTALL_WORK_BINDING_CHANGED",
                )?;
            }
            immutable_copy(
                &root.join(format!("cache-{attempt}-{index}.json")),
                &serde_json::to_vec(&audit_cache_projection(&value))?,
            )?;
            // A failed attempt may gain further exact settlements on resume.
            // Bind each immutable transition separately; never replace the
            // attempt's original approval with an expanding list.
            immutable_copy(
                &root.join(format!("cache-approval-{attempt}-{index}.json")),
                &serde_json::to_vec(
                    &json!({"schema":"app.loomex.runner.uninstall-work-cache-approval/v1","operationId":id,"attemptId":attempt,"index":index,"privateSha256":digest_file(&cache)?,"approvalSha256":digest_file(&root.join(format!("approval-{attempt}.json")))?}),
                )?,
            )?;
        }
    }
    Ok(())
}
fn archive_approval(
    paths: &lifecycle::Paths,
    work: &Value,
    old_bytes: &[u8],
    result: &Value,
    root: &Path,
) -> Result<()> {
    let attempt = result["attemptId"]
        .as_str()
        .context("invalid work attempt")?;
    let id = work["operationId"].as_str().context("invalid work owner")?;
    let context_path = paths
        .state_dir
        .join(format!("uninstall-work-context-{attempt}.json"));
    let context_bytes = regular_bytes(&context_path)?;
    let context: Value = serde_json::from_slice(&context_bytes)?;
    let old: Value = serde_json::from_slice(old_bytes)?;
    let expected_identity = if old["schema"] == OLD_SCHEMA {
        prior_identity(paths)?
    } else {
        validated_current_identity(&old)?
    };
    require(
        context["operationId"] == id
            && result["operationId"] == id
            && context["attemptId"] == attempt
            && work["attempt"]["id"] == attempt
            && context["action"] == work["attempt"]["action"]
            && matches!(
                context["action"].as_str(),
                Some("reconcile" | "retire-local")
            )
            && context["journalSha256"] == state::digest(old_bytes)
            && context["journalSha256"] == work["journalSha256"]
            && work["attempt"]["contextSha256"] == state::digest(&context_bytes)
            && context["receiptSha256"] == state::json_digest(&old["receipt"]),
        "UNINSTALL_WORK_BINDING_CHANGED",
    )?;
    require(
        context["expectedIdentity"] == expected_identity,
        "UNINSTALL_WORK_BINDING_CHANGED",
    )?;
    if context["action"] == "retire-local" {
        require(
            context["expectedAssessmentSha256"]
                .as_str()
                .is_some_and(valid_work_digest)
                && context["expectedAssessmentSha256"]
                    == work["attempt"]["expectedAssessmentSha256"],
            "UNINSTALL_WORK_BINDING_CHANGED",
        )?;
    }
    let requests = paths
        .state_dir
        .join(format!("uninstall-work-requests-{attempt}.json"));
    if !requests.try_exists()? {
        require(result["ok"] != true, "UNINSTALL_WORK_BINDING_CHANGED")?;
        return Ok(());
    }
    let request_bytes = regular_bytes(&requests)?;
    let saved: Value = serde_json::from_slice(&request_bytes)?;
    require(
        saved["operationId"] == id && saved["attemptId"] == attempt && saved["requests"].is_array(),
        "UNINSTALL_WORK_BINDING_CHANGED",
    )?;
    let authorization = paths
        .state_dir
        .join(format!("uninstall-work-authorization-{attempt}.json"));
    let checkpoint = if authorization.try_exists()? {
        let bytes = regular_bytes(&authorization)?;
        let value: Value = serde_json::from_slice(&bytes)?;
        require(
            value["operationId"] == id
                && value["attemptId"] == attempt
                && value["phase"] == "native_access_verified",
            "UNINSTALL_WORK_BINDING_CHANGED",
        )?;
        immutable_copy(
            &root.join(format!("native-authorization-{attempt}.json")),
            &bytes,
        )?;
        Some(state::digest(&bytes))
    } else {
        None
    };
    let approval = json!({"schema":"app.loomex.runner.uninstall-work-approval/v1","operationId":id,"attemptId":attempt,"action":context["action"],"expectedAssessmentSha256":context["expectedAssessmentSha256"],"originalJournalSha256":context["journalSha256"],"originalJournalSchema":old["schema"],"originalJournalPhase":old["phase"],"releaseManifestSha256":work["releaseManifestSha256"],"receiptSha256":context["receiptSha256"],"identityReference":state::json_digest(&context["expectedIdentity"]),"requestSetSha256":state::digest(&request_bytes),"contextSha256":state::digest(&context_bytes),"authorizationCheckpointSha256":checkpoint});
    immutable_copy(
        &root.join(format!("approval-{attempt}.json")),
        &serde_json::to_vec(&approval)?,
    )
}
fn public_report(
    paths: &lifecycle::Paths,
    args: &Arguments,
    outcome: &str,
    reason: &str,
    next: &str,
    operation: Option<Uuid>,
) -> Value {
    let review = review_state(paths);
    let (assessment, preview) = review.unwrap_or((Value::Null, Value::Null));
    json!({"schema":"app.loomex.runner.bootstrap-uninstall-work/v1","outcome":if assessment.is_null(){"blocked"}else{outcome},"action":args.work_action,"operationId":operation,"ownerReference":work_owner_reference(paths),"assessment":assessment,"preview":preview,"reasonCode":if assessment.is_null(){"UNINSTALL_WORK_REVIEW_UNAVAILABLE"}else{reason},"nextAction":next})
}

fn require_attempt_result(
    paths: &lifecycle::Paths,
    work: &mut Value,
    result: &Value,
) -> Result<()> {
    if result["failureCode"] == "MANAGED_WORK_MIGRATION_CHANGED" {
        let attempt = result["attemptId"]
            .as_str()
            .context("invalid work attempt")?;
        for index in 0..256 {
            require(
                !paths
                    .state_dir
                    .join(format!("uninstall-work-checkpoint-{attempt}-{index}.json"))
                    .try_exists()?,
                "UNINSTALL_WORK_BINDING_CHANGED",
            )?;
        }
        // Migration changed schema before any continuation mutation. Preserve
        // its audit and require a newly reviewed assessment for the next attempt.
        work["lastAttempt"] = work["attempt"].take();
        work["attempt"] = Value::Null;
        work["phase"] = json!("review_required");
        save_work(paths, work)?;
    }
    require_result(result)
}
fn review_state(paths: &lifecycle::Paths) -> Result<(Value, Value)> {
    let before = uninstall_state::assess_state(&paths.state_dir)?;
    let values = uninstall_state::maintenance_preview(&paths.state_dir)?;
    require(values.len() <= 256, "UNINSTALL_WORK_PREVIEW_LIMIT")?;
    let dependencies = uninstall_state::maintenance_acceptance_dependencies(&paths.state_dir)?;
    let records=values.iter().map(|value| {
        let backend=&value["backendObservation"];
        let run=value["runId"].as_str().and_then(|id|Uuid::parse_str(id).ok());
        let state=value["status"].as_str().or_else(||value["lifecycle"].as_str()).filter(|state|matches!(*state,"ready"|"sending"|"unknown"|"acknowledged"|"rejected"|"active"|"handoff_pending"|"terminal"|"superseded"|"blocked"|"suspended"|"pending"|"completed"|"ambiguous"));
        json!({"recordReference":state::json_digest(&json!([value["kind"],value["organizationId"],value["accountSubject"],value["installationId"],value["recordId"]])),"scopeReference":state::json_digest(&json!([value["organizationId"],value["accountSubject"],value["installationId"]])),"kind":value["kind"],"method":if value["reconciliationSupported"]==true {value["method"].clone()} else {Value::Null},"reconciliationSupported":value["reconciliationSupported"]==true,"runId":run,"revision":value["revision"],"generation":value["generation"],"attemptReference":value["attemptId"].as_str().map(|id|state::digest(id.as_bytes())),"status":state,"recordDigest":value["recordDigest"],"resolution":value["resolution"]["state"],"canonicalObservation":backend,"retirementEligible":value["kind"]!="presentation_operation" && (value["kind"]=="follow_session" || value["retirementEligible"]==true) && backend["recordDigest"]==value["recordDigest"],"dependencies":"exact_receipt_linked_acceptance_caches_and_response_spools"})
    }).collect::<Vec<_>>();
    require(
        before.assessment_digest
            == uninstall_state::assess_state(&paths.state_dir)?.assessment_digest,
        "UNINSTALL_WORK_ASSESSMENT_CHANGED",
    )?;
    Ok((
        serde_json::to_value(before)?,
        json!({"records":records,"acceptanceDependencies":dependencies}),
    ))
}

pub(crate) async fn run_work(args: Arguments) -> Result<()> {
    let paths = paths(&args)?;
    let mut selected = None;
    let result = execute_work(&paths, &args, &mut selected).await;
    let report = match &result {
        Ok(value) => value.clone(),
        Err(error) => {
            let code = error
                .downcast_ref::<WorkRefusal>()
                .map(|e| e.0)
                .or_else(|| error.downcast_ref::<WorkNativeFailure>().map(|e| e.code))
                .unwrap_or("UNINSTALL_WORK_BLOCKED");
            let pending = code == "UNINSTALL_WORK_MAINTENANCE_PENDING";
            let mut report = public_report(
                &paths,
                &args,
                if pending { "pending" } else { "blocked" },
                code,
                if pending {
                    "resume_uninstall_work"
                } else {
                    "inspect_uninstall_work"
                },
                selected,
            );
            if let Some(failure) = error.downcast_ref::<WorkNativeFailure>() {
                report["nativeDiagnostic"] = failure.diagnostic.clone();
            }
            report
        }
    };
    println!("{}", serde_json::to_string(&report)?);
    if report["outcome"] == "pending" {
        std::process::exit(3);
    }
    if result.is_ok() && report["outcome"] == "blocked" {
        return Err(refusal("UNINSTALL_WORK_REVIEW_UNAVAILABLE"));
    }
    result.map(|_| ())
}
async fn execute_work(
    paths: &lifecycle::Paths,
    args: &Arguments,
    selected: &mut Option<Uuid>,
) -> Result<Value> {
    // Inspect never creates lifecycle files, starts native IO, or opens a store
    // mutator. All qualification scratch is disposable and outside owned state.
    let inspect = args.work_action.as_deref() == Some("inspect");
    let _lifecycle = if inspect {
        None
    } else {
        Some(lifecycle::LifecycleLock::acquire(paths)?)
    };
    let (old, old_bytes, identity) = journal_binding(paths, args)?;
    let release = fs::canonicalize(args.release.as_ref().context("work release required")?)?;
    let manifest = read_manifest(&release)?;
    bootstrap_preflight::verify_artifact(&release, &manifest, args).await?;
    let scratch = RecoveryScratch(
        std::env::temp_dir().join(format!("loomex-work-qualification-{}", Uuid::new_v4())),
    );
    let payload = bootstrap_preflight::extract_artifact(&release, &manifest, &scratch.0).await?;
    bootstrap_preflight::verify_envelope(&release, &payload, &manifest)?;
    let qualification = work_preflight(paths, args, &release, &manifest, &payload).await?;
    require(
        digest_file(&paths.state_dir.join("bootstrap-uninstall.json"))?
            == state::digest(&old_bytes),
        "UNINSTALL_WORK_BINDING_CHANGED",
    )?;
    if inspect {
        return Ok(public_report(
            paths,
            args,
            "inspected",
            "UNINSTALL_WORK_INSPECTED",
            "reconcile_managed_work",
            None,
        ));
    }
    let owner_path = paths.state_dir.join("uninstall-work.json");
    let mut work: Value = if owner_path.try_exists()? {
        work_json(&owner_path)?
    } else {
        let operation: Option<lifecycle::Operation> = if paths
            .state_dir
            .join("lifecycle-operation.json")
            .try_exists()?
        {
            Some(work_json(
                &paths.state_dir.join("lifecycle-operation.json"),
            )?)
        } else {
            None
        };
        let id = old["operationId"]
            .as_str()
            .and_then(|s| Uuid::parse_str(s).ok())
            .or_else(|| {
                operation
                    .filter(|op| op.uninstall_fence.is_some())
                    .map(|op| op.id)
            })
            .unwrap_or_else(Uuid::new_v4);
        json!({"schema":WORK_SCHEMA,"operationId":id,"journalSha256":state::digest(&old_bytes),"releasePath":release,"releaseManifestSha256":digest_file(&release.join("manifest.json"))?,"phase":"qualified","attempt":null})
    };
    let id = Uuid::parse_str(work["operationId"].as_str().context("invalid work owner")?)?;
    *selected = Some(id);
    if !work["attempt"].is_null() {
        require(
            work["attempt"]["action"].as_str() == args.work_action.as_deref(),
            "UNINSTALL_WORK_MAINTENANCE_PENDING",
        )?;
    }
    let fence_digest = old["fenceJournalSha256"]
        .as_str()
        .unwrap_or(work["journalSha256"].as_str().unwrap());
    lifecycle::begin_uninstall_work_locked(paths, id, fence_digest)?;
    save_work(paths, &work)?;
    stop_service(paths, &old, &mut work).await?;
    let guard = quiescent_singleton(paths, &old).await?;
    if !work["attempt"].is_null() {
        let attempt = Uuid::parse_str(
            work["attempt"]["id"]
                .as_str()
                .context("invalid work attempt")?,
        )?;
        let result_path = paths
            .state_dir
            .join(format!("uninstall-work-result-{attempt}.json"));
        let result: Option<Value> = if result_path.try_exists()? {
            Some(work_json(&result_path)?)
        } else {
            None
        };
        if let Some(result) = &result {
            require(
                result["operationId"] == id.to_string()
                    && result["attemptId"] == attempt.to_string(),
                "UNINSTALL_WORK_BINDING_CHANGED",
            )?;
            audit(paths, &work, &old_bytes, result)?;
            if result["ok"] == true {
                work["lastAttempt"] = work["attempt"].take();
                work["attempt"] = Value::Null;
                work["phase"] = json!("settled");
                save_work(paths, &work)?;
                return Ok(public_report(
                    paths,
                    args,
                    "completed",
                    "UNINSTALL_WORK_COMPLETED",
                    "inspect_uninstall_work",
                    Some(id),
                ));
            }
        }
        // A known exited process and the inherited singleton establish that no
        // prior child can still write. The exact immutable context/request keys
        // are resumed; a missing PID leaves the spawn gap explicitly uncertain.
        let pid = work["attempt"]["pid"]
            .as_i64()
            .and_then(|pid| i32::try_from(pid).ok())
            .filter(|pid| *pid > 1)
            .ok_or_else(|| refusal("UNINSTALL_WORK_MAINTENANCE_PENDING"))?;
        let rc = unsafe { libc::kill(pid, 0) };
        require(
            rc == -1 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH),
            "UNINSTALL_WORK_MAINTENANCE_PENDING",
        )?;
        let context_path = paths
            .state_dir
            .join(format!("uninstall-work-context-{attempt}.json"));
        require(
            digest_file(&context_path)? == work["attempt"]["contextSha256"],
            "UNINSTALL_WORK_BINDING_CHANGED",
        )?;
        let context: Value = work_json(&context_path)?;
        let binary = paths
            .state_dir
            .join(format!("uninstall-work-stage-{id}/bin/loomex-runner"));
        require(
            digest_file(&binary)? == context["binarySha256"]
                && context["action"] == args.work_action.as_deref().unwrap_or(""),
            "UNINSTALL_WORK_BINDING_CHANGED",
        )?;
        let inherited = guard.try_clone()?;
        let desired = context["singletonFd"]
            .as_i64()
            .and_then(|fd| i32::try_from(fd).ok())
            .filter(|fd| *fd >= 3)
            .ok_or_else(|| refusal("UNINSTALL_WORK_BINDING_CHANGED"))?;
        spawn_attempt(
            paths,
            &mut work,
            &binary,
            &context_path,
            inherited.as_raw_fd(),
            desired,
        )
        .await?;
        let result: Value = work_json(&result_path)?;
        audit(paths, &work, &old_bytes, &result)?;
        require(
            result["operationId"] == id.to_string() && result["attemptId"] == attempt.to_string(),
            "UNINSTALL_WORK_BINDING_CHANGED",
        )?;
        require_attempt_result(paths, &mut work, &result)?;
        work["lastAttempt"] = work["attempt"].take();
        work["attempt"] = Value::Null;
        work["phase"] = json!("settled");
        save_work(paths, &work)?;
        return Ok(public_report(
            paths,
            args,
            "completed",
            "UNINSTALL_WORK_COMPLETED",
            "inspect_uninstall_work",
            Some(id),
        ));
    }
    if args.work_action.as_deref() == Some("retire-local") {
        let assessment = uninstall_state::assess_state(&paths.state_dir)?;
        require(
            args.expected_assessment_sha256.as_deref() == Some(&assessment.assessment_digest),
            "UNINSTALL_WORK_ASSESSMENT_CHANGED",
        )?;
    }
    let stage = paths.state_dir.join(format!("uninstall-work-stage-{id}"));
    if stage.try_exists()? {
        inventory(
            &stage,
            manifest["payload"]["files"]
                .as_array()
                .context("missing work inventory")?,
        )?;
    } else {
        bootstrap_preflight::extract_artifact(&release, &manifest, &stage).await?;
    }
    let binary = stage.join("bin/loomex-runner");
    let inherited = guard.try_clone()?;
    let fd = inherited.as_raw_fd();
    let attempt = Uuid::new_v4();
    let context_path = paths
        .state_dir
        .join(format!("uninstall-work-context-{attempt}.json"));
    let context = json!({"schema":"app.loomex.runner.uninstall-work-context/v1","operationId":id,"attemptId":attempt,"stateDir":paths.state_dir,"installBase":paths.install_base,"launchAgentsDir":paths.launch_agents_dir,"journalSha256":work["journalSha256"],"receiptSha256":state::json_digest(&old["receipt"]),"binarySha256":digest_file(&binary)?,"action":args.work_action,"expectedAssessmentSha256":args.expected_assessment_sha256,"expectedIdentity":identity,"apiOrigin":old["receipt"]["developmentApiOrigin"],"singletonFd":fd,"authorizeKeychainTransition":args.authorize_keychain_transition && qualification["signingTransition"]=="needs_explicit_transition"});
    // The context and attempt intent precede spawn. A crash in the spawn gap is
    // uncertain, and cannot authorize another child under a fresh identity.
    immutable_copy(&context_path, &serde_json::to_vec(&context)?)?;
    if work["attemptIds"].is_null() {
        work["attemptIds"] = json!([]);
    }
    require(
        work["attemptIds"]
            .as_array()
            .is_some_and(|ids| ids.len() < 64),
        "UNINSTALL_WORK_AUDIT_LIMIT",
    )?;
    work["attemptIds"]
        .as_array_mut()
        .unwrap()
        .push(json!(attempt));
    work["attempt"] = json!({"id":attempt,"action":args.work_action,"expectedAssessmentSha256":args.expected_assessment_sha256,"state":"spawn_pending","contextSha256":digest_file(&context_path)?});
    save_work(paths, &work)?;
    spawn_attempt(paths, &mut work, &binary, &context_path, fd, fd).await?;
    let result: Value = work_json(
        &paths
            .state_dir
            .join(format!("uninstall-work-result-{attempt}.json")),
    )?;
    require(
        result["operationId"] == id.to_string() && result["attemptId"] == attempt.to_string(),
        "UNINSTALL_WORK_BINDING_CHANGED",
    )?;
    audit(paths, &work, &old_bytes, &result)?;
    require_attempt_result(paths, &mut work, &result)?;
    work["lastAttempt"] = work["attempt"].take();
    work["attempt"] = Value::Null;
    work["phase"] = json!("settled");
    save_work(paths, &work)?;
    // Authoritative qualification is fresh and all child stores are closed.
    // Audit and work ownership are deliberately outside the deletion inventory.
    if uninstall_state::assess_state(&paths.state_dir)?.resolved {
        work["stateEntries"] = capture_state_entries(paths)?;
        save_work(paths, &work)?;
    }
    Ok(public_report(
        paths,
        args,
        "completed",
        "UNINSTALL_WORK_COMPLETED",
        "inspect_uninstall_work",
        Some(id),
    ))
}

fn native_failure_code(result: &Value) -> &'static str {
    match result["failureCode"].as_str() {
        Some("MANAGED_WORK_OBSERVATION_INCOMPLETE") => "UNINSTALL_WORK_OBSERVATION_INCOMPLETE",
        Some("MANAGED_WORK_CHANGED") => "UNINSTALL_WORK_ASSESSMENT_CHANGED",
        Some("MANAGED_WORK_MIGRATION_CHANGED") => "UNINSTALL_WORK_ASSESSMENT_CHANGED",
        Some("MANAGED_WORK_RECONCILIATION_REQUIRED") => "UNINSTALL_WORK_RECONCILIATION_REQUIRED",
        Some("MANAGED_DOMAIN_OUTCOME_PENDING") => "UNINSTALL_WORK_DOMAIN_OUTCOME_PENDING",
        Some("MANAGED_WORK_RECEIPT_MISMATCH") => "UNINSTALL_WORK_RECEIPT_MISMATCH",
        Some("MANAGED_WORK_RECONCILIATION_UNSUPPORTED") => {
            "UNINSTALL_WORK_RECONCILIATION_UNSUPPORTED"
        }
        Some("AUTH_IDENTITY_CHANGED") => "UNINSTALL_WORK_IDENTITY_CHANGED",
        _ => "UNINSTALL_WORK_NATIVE_FAILED",
    }
}
async fn spawn_attempt(
    paths: &lifecycle::Paths,
    work: &mut Value,
    binary: &Path,
    context: &Path,
    fd: i32,
    desired: i32,
) -> Result<()> {
    let mut command = tokio::process::Command::new(binary);
    command
        .arg("--maintenance-uninstall-work")
        .arg(context)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(false);
    unsafe {
        command.pre_exec(move || {
            if fd != desired && libc::dup2(fd, desired) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            let flags = libc::fcntl(desired, libc::F_GETFD);
            if flags < 0 || libc::fcntl(desired, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = command
        .spawn()
        .map_err(|_| refusal("UNINSTALL_WORK_MAINTENANCE_PENDING"))?;
    work["attempt"]["pid"] = json!(child.id());
    work["attempt"]["state"] = json!("running");
    save_work(paths, work)?;
    let status = tokio::time::timeout(std::time::Duration::from_secs(35), child.wait())
        .await
        .map_err(|_| refusal("UNINSTALL_WORK_MAINTENANCE_PENDING"))??;
    require(status.success(), "UNINSTALL_WORK_NATIVE_FAILED")
}

pub(super) fn require_recovery_binding(
    paths: &lifecycle::Paths,
    old_digest: &str,
    release: &Path,
    manifest: &Value,
) -> Result<()> {
    let path = paths.state_dir.join("uninstall-work.json");
    if !path.try_exists()? {
        return Ok(());
    }
    let work: Value = work_json(&path)?;
    require(
        work["schema"] == WORK_SCHEMA
            && work["journalSha256"] == old_digest
            && work["releasePath"].as_str() == Some(release.to_string_lossy().as_ref())
            && work["releaseManifestSha256"] == digest_file(&release.join("manifest.json"))?
            && work["attempt"].is_null(),
        "UNINSTALL_WORK_BINDING_CHANGED",
    )?;
    let stage = paths.state_dir.join(format!(
        "uninstall-work-stage-{}",
        work["operationId"].as_str().context("invalid work owner")?
    ));
    if stage.try_exists()? {
        inventory(
            &stage,
            manifest["payload"]["files"]
                .as_array()
                .context("missing work inventory")?,
        )?;
    }
    Ok(())
}

/// Destructive uninstall has adopted the exact work owner and all native child
/// handles have closed. Remove only that owner's verified temporary resources.
pub(super) fn cleanup_resources(paths: &lifecycle::Paths, journal: &Value) -> Result<()> {
    let owner = paths.state_dir.join("uninstall-work.json");
    if !owner.try_exists()? {
        return Ok(());
    }
    let work: Value = work_json(&owner)?;
    require(
        work["schema"] == WORK_SCHEMA
            && work["operationId"] == journal["operationId"]
            && work["journalSha256"] == journal["recovery"]["oldJournalSha256"]
            && work["attempt"].is_null(),
        "UNINSTALL_WORK_BINDING_CHANGED",
    )?;
    let id = Uuid::parse_str(work["operationId"].as_str().context("invalid work owner")?)?;
    for attempt in work["attemptIds"]
        .as_array()
        .context("invalid work attempts")?
    {
        let attempt = Uuid::parse_str(attempt.as_str().context("invalid work attempt")?)?;
        let approval: Value = work_json(
            &paths
                .state_dir
                .join("recovery-evidence")
                .join(id.to_string())
                .join(format!("approval-{attempt}.json")),
        )?;
        require(
            approval["schema"] == "app.loomex.runner.uninstall-work-approval/v1"
                && approval["operationId"] == id.to_string()
                && approval["attemptId"] == attempt.to_string()
                && approval["originalJournalSha256"] == work["journalSha256"]
                && approval["releaseManifestSha256"] == work["releaseManifestSha256"]
                && approval["requestSetSha256"]
                    .as_str()
                    .is_some_and(valid_work_digest),
            "UNINSTALL_WORK_BINDING_CHANGED",
        )?;
        for index in 0..256 {
            let cache = paths
                .state_dir
                .join(format!("uninstall-work-cache-{attempt}-{index}.json"));
            if cache.try_exists()? {
                let proof_path = paths
                    .state_dir
                    .join("recovery-evidence")
                    .join(id.to_string())
                    .join(format!("cache-approval-{attempt}-{index}.json"));
                let proof: Value = work_json(&proof_path)?;
                require(
                    proof["schema"] == "app.loomex.runner.uninstall-work-cache-approval/v1"
                        && proof["operationId"] == id.to_string()
                        && proof["attemptId"] == attempt.to_string()
                        && proof["index"] == index
                        && proof["privateSha256"] == digest_file(&cache)?
                        && proof["approvalSha256"]
                            == digest_file(
                                &paths
                                    .state_dir
                                    .join("recovery-evidence")
                                    .join(id.to_string())
                                    .join(format!("approval-{attempt}.json")),
                            )?,
                    "UNINSTALL_WORK_BINDING_CHANGED",
                )?;
            }
        }
    }

    let stage = paths.state_dir.join(format!("uninstall-work-stage-{id}"));
    if stage.try_exists()? {
        let files = journal["recovery"]["files"]
            .as_array()
            .context("missing work inventory")?;
        lifecycle::prune_quarantine_inventory(&stage, files, true)?;
        fs::remove_dir_all(&stage)?;
    }
    for attempt in work["attemptIds"]
        .as_array()
        .context("invalid work attempts")?
    {
        let attempt = Uuid::parse_str(attempt.as_str().context("invalid work attempt")?)?;
        for kind in ["context", "requests", "result", "authorization"] {
            let path = paths
                .state_dir
                .join(format!("uninstall-work-{kind}-{attempt}.json"));
            if path.try_exists()? {
                regular_bytes(&path)?;
                remove_regular(&path)?;
            }
        }
        for index in 0..256 {
            for kind in ["checkpoint", "cache"] {
                let path = paths
                    .state_dir
                    .join(format!("uninstall-work-{kind}-{attempt}-{index}.json"));
                if path.try_exists()? {
                    regular_bytes(&path)?;
                    remove_regular(&path)?;
                }
            }
        }
    }
    remove_regular(&owner)?;
    File::open(&paths.state_dir)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn work_signing_requires_explicit_transition_and_inspection_never_authorizes() {
        assert!(work_signing_transition(None, Some("stable"), false, false).is_err());
        assert_eq!(
            work_signing_transition(None, Some("stable"), false, true).unwrap(),
            SigningTransition::ForegroundAuthorizationRequired
        );
        assert_eq!(
            work_signing_transition(Some("stable"), Some("stable"), true, true).unwrap(),
            SigningTransition::Ready
        );
        let mut args = Arguments {
            work_action: Some("inspect".into()),
            expected_old_journal_sha256: Some("a".repeat(64)),
            authorize_keychain_transition: true,
            ..Default::default()
        };
        assert!(!valid_recovery_arguments("uninstall-work", &args));
        assert!(!valid_recovery_arguments("preflight", &args));
        args.work_action = Some("reconcile".into());
        assert!(valid_recovery_arguments("uninstall-work", &args));
    }
    #[test]
    fn historical_binding_and_v10_owner_preserve_both_original_byte_streams() {
        let fixture = super::super::tests::historical_fixture();
        let path = fixture.paths.state_dir.join("bootstrap-uninstall.json");
        let bytes = regular_bytes(&path).unwrap();
        let operation_path = fixture.paths.state_dir.join("lifecycle-operation.json");
        let original = regular_bytes(&operation_path).unwrap();
        let args = Arguments {
            work_action: Some("inspect".into()),
            expected_old_journal_sha256: Some(state::digest(&bytes)),
            ..Default::default()
        };
        journal_binding(&fixture.paths, &args).unwrap();
        assert_eq!(regular_bytes(&path).unwrap(), bytes);
        assert_eq!(regular_bytes(&operation_path).unwrap(), original);
        assert!(!fixture.paths.state_dir.join("uninstall-work.json").exists());
        let owner = work_owner_reference(&fixture.paths);
        assert!(owner["operationId"].is_null());
        assert_eq!(owner["journalSchema"], OLD_SCHEMA);
        let id = Uuid::new_v4();
        lifecycle::begin_uninstall_work_locked(&fixture.paths, id, &state::digest(&bytes)).unwrap();
        let operation: lifecycle::Operation = work_json(&operation_path).unwrap();
        assert_eq!(
            operation.schema,
            "app.loomex.runner.lifecycle-operation/v10"
        );
        assert_eq!(operation.phase, "work_maintenance");
        assert_eq!(
            operation
                .uninstall_fence
                .unwrap()
                .original_operation_snapshot
                .unwrap()
                .as_bytes(),
            original
        );
        assert_eq!(regular_bytes(&path).unwrap(), bytes);
        journal_binding(&fixture.paths, &args).unwrap();
    }
    #[test]
    fn changed_digest_and_deletion_phase_cannot_admit_or_mutate_work() {
        let mut fixture = super::super::tests::historical_fixture();
        let path = fixture.paths.state_dir.join("bootstrap-uninstall.json");
        let bytes = regular_bytes(&path).unwrap();
        let mut args = Arguments {
            work_action: Some("retire-local".into()),
            expected_old_journal_sha256: Some("f".repeat(64)),
            expected_assessment_sha256: Some("e".repeat(64)),
            ..Default::default()
        };
        assert_eq!(
            journal_binding(&fixture.paths, &args)
                .unwrap_err()
                .to_string(),
            "UNINSTALL_WORK_BINDING_CHANGED"
        );
        assert_eq!(regular_bytes(&path).unwrap(), bytes);
        fixture.journal["cleanup"]["stateDeletingStarted"] = json!(true);
        save(&fixture.paths, &fixture.journal).unwrap();
        args.expected_old_journal_sha256 = Some(digest_file(&path).unwrap());
        assert_eq!(
            journal_binding(&fixture.paths, &args)
                .unwrap_err()
                .to_string(),
            "UNINSTALL_WORK_PHASE_UNSUPPORTED"
        );
        assert!(!fixture.paths.state_dir.join("uninstall-work.json").exists());
    }
    #[test]
    fn terminal_delivery_quiescence_is_distinct_from_destructive_resolution() {
        let fixture = super::super::tests::historical_fixture();
        let job = fixture
            .paths
            .state_dir
            .join("jobs")
            .join(Uuid::new_v4().to_string());
        state::private_dir(&job).unwrap();
        let path = job.join("journal.json");
        state::write_json(
            &path,
            &json!({"phase":"terminal_pending","identity":null,"result":{"exitCode":0}}),
        )
        .unwrap();
        jobs_quiescent(&fixture.paths).unwrap();
        assert!(reject_unresolved_work(&fixture.paths).is_err());
        state::write_json(
            &path,
            &json!({"phase":"spawn_intent","identity":null,"result":null}),
        )
        .unwrap();
        assert!(jobs_quiescent(&fixture.paths).is_err());
        state::write_json(&path,&json!({"phase":"terminal_pending","identity":{"pid":std::process::id(),"pgid":std::process::id()},"result":{"managedGroupStopped":true,"indeterminate":false,"descendantCleanup":"unknown"}})).unwrap();
        assert!(jobs_quiescent(&fixture.paths).is_err());
        state::write_json(&path,&json!({"phase":"terminal_pending","identity":{"pid":i32::MAX,"pgid":i32::MAX},"result":{"managedGroupStopped":true,"indeterminate":false,"descendantCleanup":"indeterminate: full-host processes may detach"}})).unwrap();
        assert!(jobs_quiescent(&fixture.paths).is_err());
    }
    #[test]
    fn audit_survives_owned_state_inventory_and_never_contains_arbitrary_error_text() {
        let fixture = super::super::tests::historical_fixture();
        let bytes =
            regular_bytes(&fixture.paths.state_dir.join("bootstrap-uninstall.json")).unwrap();
        let id = Uuid::new_v4();
        let attempt = Uuid::new_v4();
        let reviewed = "d".repeat(64);
        let context = json!({"schema":"app.loomex.runner.uninstall-work-context/v1","operationId":id,"attemptId":attempt,"action":"retire-local","journalSha256":state::digest(&bytes),"receiptSha256":state::json_digest(&fixture.journal["receipt"]),"expectedIdentity":prior_identity(&fixture.paths).unwrap(),"expectedAssessmentSha256":reviewed,"authorizeKeychainTransition":true});
        let context_path = fixture
            .paths
            .state_dir
            .join(format!("uninstall-work-context-{attempt}.json"));
        state::write_json(&context_path, &context).unwrap();
        let requests_path = fixture
            .paths
            .state_dir
            .join(format!("uninstall-work-requests-{attempt}.json"));
        let private_request = json!({"kind":"presentation_operation","method":"workflows.create","recordId":Uuid::new_v4(),"operationKey":Uuid::new_v4(),"organizationId":"PRIVATE ACCOUNT","params":{"prompt":"PRIVATE ANSWER"},"reconciliation":{"private":"PRIVATE PROMPT"}});
        let request_digest = state::json_digest(&private_request);
        state::write_json(
            &requests_path,
            &json!({"operationId":id,"attemptId":attempt,"requests":[private_request.clone(),private_request]}),
        )
        .unwrap();
        state::write_json(
            &fixture
                .paths
                .state_dir
                .join(format!("uninstall-work-authorization-{attempt}.json")),
            &json!({"operationId":id,"attemptId":attempt,"phase":"native_access_verified"}),
        )
        .unwrap();
        let mut work = json!({"schema":WORK_SCHEMA,"operationId":id,"journalSha256":state::digest(&bytes),"releaseManifestSha256":"b".repeat(64),"attempt":{"id":attempt,"action":"retire-local","contextSha256":digest_file(&context_path).unwrap(),"expectedAssessmentSha256":reviewed},"attemptIds":[attempt]});
        let result =
            json!({"attemptId":attempt,"operationId":id,"ok":true,"result":{"receipts":[]}});
        let cache_path = fixture
            .paths
            .state_dir
            .join(format!("uninstall-work-cache-{attempt}-0.json"));
        state::write_json(&cache_path, &json!({"schema":"app.loomex.runner.uninstall-work-cache-transition/v1","operationId":id,"attemptId":attempt,"index":0,"requestDigest":request_digest,"transition":{"schema":"app.loomex.runner.uninstall-work-cache/v1","path":"PRIVATE PATH","before":"PRIVATE BEFORE","after":"PRIVATE AFTER","canonicalReceipt":{"response":"PRIVATE RESPONSE"},"beforeSha256":"a".repeat(64),"afterSha256":"b".repeat(64)}})).unwrap();
        let cache_bytes = regular_bytes(&cache_path).unwrap();
        let journal = json!({"operationId":id,"recovery":{"oldJournalSha256":state::digest(&bytes),"files":[]}});
        let mut settled_work = work.clone();
        settled_work["attempt"] = Value::Null;
        save_work(&fixture.paths, &settled_work).unwrap();
        assert!(cleanup_resources(&fixture.paths, &journal).is_err());
        assert!(context_path.exists());
        assert!(requests_path.exists());
        audit(&fixture.paths, &work, &bytes, &result).unwrap();
        // Resume can settle another cache after a prior partial result. Its
        // proof is additive; the reviewed attempt approval stays immutable.
        let cache_later = fixture
            .paths
            .state_dir
            .join(format!("uninstall-work-cache-{attempt}-1.json"));
        state::write_json(&cache_later, &json!({"schema":"app.loomex.runner.uninstall-work-cache-transition/v1","operationId":id,"attemptId":attempt,"index":1,"requestDigest":request_digest,"transition":{"schema":"app.loomex.runner.uninstall-work-cache/v1","before":"PRIVATE LATER","beforeSha256":"d".repeat(64),"afterSha256":"c".repeat(64)}})).unwrap();
        audit(&fixture.paths, &work, &bytes, &result).unwrap();
        let approval_path = fixture
            .paths
            .state_dir
            .join("recovery-evidence")
            .join(id.to_string())
            .join(format!("approval-{attempt}.json"));
        let approval: Value = work_json(&approval_path).unwrap();
        assert_eq!(approval["action"], "retire-local");
        assert_eq!(approval["expectedAssessmentSha256"], reviewed);
        assert_eq!(
            approval["requestSetSha256"],
            digest_file(&requests_path).unwrap()
        );
        work["attempt"] = Value::Null;
        save_work(&fixture.paths, &work).unwrap();
        fs::write(&cache_path, b"changed").unwrap();
        assert!(cleanup_resources(&fixture.paths, &journal).is_err());
        assert!(context_path.exists());
        fs::write(&cache_path, &cache_bytes).unwrap();
        cleanup_resources(&fixture.paths, &journal).unwrap();
        assert!(!context_path.exists());
        assert!(!requests_path.exists());
        assert!(!cache_path.exists());
        assert!(!cache_later.exists());
        assert!(approval_path.exists());
        for entry in fs::read_dir(approval_path.parent().unwrap()).unwrap() {
            let bytes = regular_bytes(&entry.unwrap().path()).unwrap();
            assert!(!String::from_utf8_lossy(&bytes).contains("PRIVATE "));
        }
        let evidence = fixture
            .paths
            .state_dir
            .join("recovery-evidence")
            .join(id.to_string())
            .join("original-uninstall.json");
        assert_eq!(regular_bytes(&evidence).unwrap(), bytes);
        assert!(!owned_state_namespace(Path::new("recovery-evidence")));
        let unsafe_native = json!({"ok":false,"error":{"code":"STORE_ACCESS_DENIED","message":"PRIVATE TEXT","data":{"failureStage":"credential_store","failureCategory":"access_denied","nativeOsStatus":-25293,"private":"PRIVATE TEXT"}}});
        let error = require_result(&unsafe_native).unwrap_err();
        let native = error.downcast_ref::<WorkNativeFailure>().unwrap();
        assert_eq!(native.diagnostic["nativeOsStatus"], -25293);
        assert!(!native.diagnostic.to_string().contains("PRIVATE TEXT"));
    }
}
