//! Separate pre-adoption maintenance authority. Historical uninstall bytes are
//! immutable; resolving local observation obligations is not a destructive gate.
use super::*;

#[path = "work/cleanup.rs"]
mod generation_cleanup;
#[path = "work/generations.rs"]
mod generations;
pub(crate) use generations::work_maintenance_reference;

const WORK_SCHEMA: &str = "app.loomex.runner.uninstall-work/v1";
fn require_attempt_arguments(work: &Value, args: &Arguments) -> Result<()> {
    if work["attempt"].is_null() || args.work_action.as_deref() == Some("inspect") {
        return Ok(());
    }
    require(
        work["attempt"]["action"].as_str() == args.work_action.as_deref()
            && saved_scope(&work["attempt"]) == retirement_scope(args),
        "UNINSTALL_WORK_MAINTENANCE_PENDING",
    )?;
    require(
        work["attempt"]["expectedAssessmentSha256"].as_str()
            == args.expected_assessment_sha256.as_deref(),
        "UNINSTALL_WORK_ASSESSMENT_CHANGED",
    )
}
fn retirement_scope(args: &Arguments) -> &str {
    args.retirement_scope.as_deref().unwrap_or("continuations")
}
fn saved_scope(value: &Value) -> &str {
    value["retirementScope"].as_str().unwrap_or("continuations")
}
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
                | "AUTH_REQUIRED"
                | "AUTH_EXPIRED"
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
fn present(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
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
    let transition = qualify_work_candidate(paths, args, &old, release, manifest, payload).await?;
    work_state_preflight(paths, args, release, transition, &bytes)
}
async fn qualify_work_candidate(
    paths: &lifecycle::Paths,
    args: &Arguments,
    old: &Value,
    release: &Path,
    manifest: &Value,
    payload: &Path,
) -> Result<SigningTransition> {
    require(
        digest_file(&std::env::current_exe()?)? == manifest["bootstrap"]["sha256"],
        "UNINSTALL_WORK_BINDING_CHANGED",
    )?;
    let transition = validate_recovery_candidate(args, old, manifest, payload).await?;
    require_work_candidate_capabilities(paths, args, release, payload)?;
    Ok(transition)
}

/// Existing and prospective persisted meanings must be understood by this exact
/// verified payload, before publishing any proof or changing the lifecycle fence.
fn require_work_candidate_capabilities(
    paths: &lifecycle::Paths,
    args: &Arguments,
    release: &Path,
    payload: &Path,
) -> Result<()> {
    lifecycle::require_operation_observation_capability(paths, payload).map_err(
        |error| match error.to_string().as_str() {
            "UNINSTALL_WORK_GENERATION_CAPABILITY_REQUIRED" => {
                refusal("UNINSTALL_WORK_GENERATION_CAPABILITY_REQUIRED")
            }
            "OPERATION_RETIREMENT_CAPABILITY_REQUIRED" => {
                refusal("OPERATION_RETIREMENT_CAPABILITY_REQUIRED")
            }
            _ => error,
        },
    )?;
    let owner_path = paths.state_dir.join("uninstall-work.json");
    if !present(&owner_path)? {
        return Ok(());
    }
    let work: Value = work_json(&owner_path)?;
    let expected_release = args.expected_release_path.as_deref().unwrap_or(release);
    let different = work["releaseManifestSha256"] != digest_file(&release.join("manifest.json"))?
        || work["releasePath"].as_str() != Some(expected_release.to_string_lossy().as_ref());
    if different
        && !work["attempt"].is_null()
        && generations::failed_reconcile_candidate(paths, &work)?
    {
        let compatibility: Value =
            work_json(&payload.join("metadata/compatibility-manifest.json"))?;
        require(
            compatibility["capabilities"]
                .as_array()
                .is_some_and(|values| {
                    values
                        .iter()
                        .any(|value| value == "uninstall-work.inactive-failed-reconcile/v1")
                }),
            "UNINSTALL_WORK_GENERATION_CAPABILITY_REQUIRED",
        )?;
    }
    Ok(())
}
fn work_state_preflight(
    paths: &lifecycle::Paths,
    args: &Arguments,
    release: &Path,
    transition: SigningTransition,
    bytes: &[u8],
) -> Result<Value> {
    let expected_release = args.expected_release_path.as_deref().unwrap_or(release);
    let mut successor_after_original_result = false;
    if paths.state_dir.join("uninstall-work.json").try_exists()? {
        let work: Value = work_json(&paths.state_dir.join("uninstall-work.json"))?;
        require(
            generations::supported(&work) && work["journalSha256"] == state::digest(bytes),
            "UNINSTALL_WORK_BINDING_CHANGED",
        )?;
        let transition = generations::candidate_transition(
            paths,
            &work,
            &digest_file(&release.join("manifest.json"))?,
            Some(expected_release),
        )?;
        if transition == "eligible_successor" {
            require(
                args.work_action.as_deref() != Some("retire-local"),
                "UNINSTALL_WORK_RECONCILIATION_REQUIRED",
            )?;
        }
        if args.work_action.as_deref() == Some("retire-local")
            && work["attempt"].is_null()
            && work["schema"] == generations::OWNER_V2
            && (work["currentGeneration"].as_u64().unwrap_or(0) > 0
                || work["failedReconcileProofs"]
                    .as_object()
                    .is_some_and(|proofs| !proofs.is_empty()))
        {
            require(
                generations::reconciled_current(paths, &work)?,
                "UNINSTALL_WORK_RECONCILIATION_REQUIRED",
            )?;
        }
        let consuming_successor_result = (work["releaseManifestSha256"]
            != digest_file(&release.join("manifest.json"))?
            || work["releasePath"].as_str() != Some(expected_release.to_string_lossy().as_ref()))
            && !work["attempt"].is_null()
            && (generations::known_result(paths, &work)?
                || (transition == "eligible_successor"
                    && generations::failed_reconcile_candidate(paths, &work)?));
        successor_after_original_result = consuming_successor_result;
        if consuming_successor_result {
            require(
                args.work_action.as_deref() != Some("retire-local"),
                "UNINSTALL_WORK_RECONCILIATION_REQUIRED",
            )?;
            if args.work_action.as_deref() == Some("reconcile") {
                require(
                    args.expected_assessment_sha256.is_none(),
                    "UNINSTALL_WORK_ASSESSMENT_CHANGED",
                )?;
            }
        }
        if !consuming_successor_result {
            require_attempt_arguments(&work, args)?;
        }
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
                && saved_scope(&value["attempt"]) == retirement_scope(args)
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
        json!({"eligible":true,"readOnly":true,"successorAfterOriginalResult":successor_after_original_result,"action":args.work_action,"retirementScope":retirement_scope(args),"signingTransition":if transition==SigningTransition::ForegroundAuthorizationRequired {"needs_explicit_transition"}else{"eligible"},"accessAttempted":false,"nativeAccessVerified":false,"ownerReference":work_owner_reference(paths),"maintenanceReference":work_maintenance_reference(paths,Some(&digest_file(&release.join("manifest.json"))?),Some(expected_release)),"assessment":assessment}),
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
    require(
        serde_json::to_vec_pretty(value)?.len() <= 16 * 1024 * 1024,
        "UNINSTALL_WORK_AUDIT_LIMIT",
    )?;
    if value["schema"] == generations::OWNER_V2 {
        let root = paths.state_dir.join("recovery-evidence").join(
            value["operationId"]
                .as_str()
                .context("invalid work owner")?,
        );
        state::private_dir(&paths.state_dir.join("recovery-evidence"))?;
        state::private_dir(&root)?;
        for generation in generations::records(value)? {
            immutable_copy(
                &root.join(format!(
                    "generation-{}.json",
                    generation["generation"].as_u64().unwrap()
                )),
                &serde_json::to_vec(&generation)?,
            )?;
        }
    }
    fault("AFTER_WORK_GENERATION_ARCHIVES")?;
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
    if value["kind"] == "operation_cache" {
        return json!({"kind":"operation_cache","recordReference":state::json_digest(&value["legacySlot"]),"recordDigest":value["recordDigest"],"privateRecordSha256":state::json_digest(value)});
    }
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
        matches!(
            context["schema"].as_str(),
            Some(
                "app.loomex.runner.uninstall-work-context/v1"
                    | "app.loomex.runner.uninstall-work-context/v2"
            )
        ) && context["operationId"] == id
            && result["operationId"] == id
            && context["attemptId"] == attempt
            && work["attempt"]["id"] == attempt
            && context["action"] == work["attempt"]["action"]
            && saved_scope(&context) == saved_scope(&work["attempt"])
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
    if context["schema"] == "app.loomex.runner.uninstall-work-context/v2" {
        let generation = generations::attempt_release(paths, work, attempt)?;
        require(
            work["schema"] == generations::OWNER_V2
                && context["maintenanceGeneration"] == work["currentGeneration"]
                && work["attempt"]["maintenanceGeneration"] == context["maintenanceGeneration"]
                && work["attempt"]["releaseManifestSha256"] == generation["releaseManifestSha256"]
                && result["maintenanceGeneration"] == context["maintenanceGeneration"]
                && result["releaseManifestSha256"] == generation["releaseManifestSha256"]
                && result["contextSha256"] == state::digest(&context_bytes),
            "UNINSTALL_WORK_BINDING_CHANGED",
        )?;
    }
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
    let approval = json!({"schema":"app.loomex.runner.uninstall-work-approval/v1","operationId":id,"attemptId":attempt,"action":context["action"],"retirementScope":saved_scope(&context),"expectedAssessmentSha256":context["expectedAssessmentSha256"],"originalJournalSha256":context["journalSha256"],"originalJournalSchema":old["schema"],"originalJournalPhase":old["phase"],"releaseManifestSha256":if work["schema"]==generations::OWNER_V2 {generations::attempt_release(paths,work,attempt)?["releaseManifestSha256"].clone()}else{work["releaseManifestSha256"].clone()},"receiptSha256":context["receiptSha256"],"identityReference":state::json_digest(&context["expectedIdentity"]),"requestSetSha256":state::digest(&request_bytes),"contextSha256":state::digest(&context_bytes),"authorizationCheckpointSha256":checkpoint});
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
    let (assessment, mut preview) = review.unwrap_or((Value::Null, Value::Null));
    if let Some(records) = preview["records"].as_array_mut() {
        for record in records {
            record["selected"] = json!(
                record["retirementEligible"] == true
                    && record["resolution"] == "unresolved"
                    && if retirement_scope(args) == "operation-observations" {
                        record["kind"] == "operation_cache"
                    } else {
                        record["kind"] == "follow_session"
                            || record["kind"] == "presentation_delivery"
                    }
            );
        }
    }
    if preview.is_object() {
        preview["retirementScope"] = json!(retirement_scope(args));
    }
    let candidate_release = args.expected_release_path.clone().or_else(|| {
        args.release
            .as_ref()
            .and_then(|release| fs::canonicalize(release).ok())
    });
    let maintenance_reference = work_maintenance_reference(
        paths,
        args.release
            .as_ref()
            .and_then(|release| digest_file(&release.join("manifest.json")).ok())
            .as_deref(),
        candidate_release.as_deref(),
    );
    if let Some(records) = preview["records"].as_array_mut() {
        let owner_path = paths.state_dir.join("uninstall-work.json");
        let work: Option<Value> = work_json(&owner_path).ok();
        let blocked = matches!(
            reason,
            "UNINSTALL_WORK_GENERATION_CAPABILITY_REQUIRED"
                | "OPERATION_RETIREMENT_CAPABILITY_REQUIRED"
        ) || present(&owner_path).unwrap_or(true)
            && (work
                .as_ref()
                .is_none_or(|work| !generations::supported(work))
                || !matches!(
                    maintenance_reference["transition"].as_str(),
                    Some(
                        "current_release"
                            | "review_required"
                            | "eligible_successor"
                            | "resume_original_attempt"
                    )
                ));
        let retirement_ready = work.as_ref().is_some_and(|work| {
            work["attempt"].is_null()
                && matches!(
                    maintenance_reference["transition"].as_str(),
                    Some("current_release" | "review_required")
                )
                && (work["schema"] != generations::OWNER_V2
                    || (work["currentGeneration"].as_u64().unwrap_or(0) == 0
                        && work["failedReconcileProofs"]
                            .as_object()
                            .is_none_or(|proofs| proofs.is_empty()))
                    || generations::reconciled_current(paths, work).unwrap_or(false))
        });
        for record in records {
            if let Some(actions) = record["availableActions"].as_array_mut() {
                if blocked {
                    actions.clear();
                    continue;
                }
                if let Some(work) = &work {
                    actions.retain(|action| match work["attempt"]["action"].as_str() {
                        Some("reconcile") => {
                            action == "reconcile"
                                && (maintenance_reference["transition"] == "eligible_successor"
                                    || saved_scope(&work["attempt"]) == retirement_scope(args))
                                && args.expected_assessment_sha256.is_none()
                        }
                        Some("retire-local") => {
                            action == "retire-local"
                                && saved_scope(&work["attempt"]) == retirement_scope(args)
                                && work["attempt"]["expectedAssessmentSha256"].as_str()
                                    == args.expected_assessment_sha256.as_deref()
                        }
                        _ => action != "retire-local" || retirement_ready,
                    });
                }
            }
        }
    }
    let operation = operation.or_else(|| {
        maintenance_reference["operationId"]
            .as_str()
            .and_then(|id| Uuid::parse_str(id).ok())
    });
    json!({"schema":"app.loomex.runner.bootstrap-uninstall-work/v2","outcome":if assessment.is_null(){"blocked"}else{outcome},"action":args.work_action,"retirementScope":retirement_scope(args),"actionCompleted":outcome=="completed" && !assessment.is_null(),"cleanupEligible":assessment["resolved"]==true,"operationId":operation,"ownerReference":work_owner_reference(paths),"maintenanceReference":maintenance_reference,"assessment":assessment,"preview":preview,"reasonCode":if assessment.is_null(){"UNINSTALL_WORK_REVIEW_UNAVAILABLE"}else{reason},"nextAction":next})
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
        let operation = value["kind"] == "operation_cache";
        let eligible = if operation { value["retirementEligible"] == true } else { value["kind"] != "presentation_operation" && (value["kind"] == "follow_session" || value["retirementEligible"] == true) && backend["recordDigest"] == value["recordDigest"] };
        let reason = value["safeReason"].as_str().filter(|reason| matches!(*reason, "missing_binding" | "canonical_pending" | "terminal_missing" | "unsupported_family" | "response_dependency_missing"));
        let method = value["method"].as_str().filter(|method| matches!(*method, "interactions.respond" | "interactions.decide" | "interactions.draft.delete" | "interactions.draft.update" | "auth.recover" | "builder.start" | "editor.start" | "workflows.create" | "workflows.update" | "workflows.patch" | "workflows.publish" | "personas.memory.write" | "personas.memory.update" | "personas.create" | "personas.chat_context.create" | "persona.roles.create"));
        json!({"recordReference":state::json_digest(&json!([value["kind"],value["organizationId"],value["accountSubject"],value["installationId"],if operation {&value["legacySlot"]}else{&value["recordId"]}])),"scopeReference":state::json_digest(&json!([value["organizationId"],value["accountSubject"],value["installationId"]])),"kind":value["kind"],"method":if operation || value["reconciliationSupported"]==true {json!(method)} else {Value::Null},"reconciliationSupported":value["reconciliationSupported"]==true,"runId":run,"revision":value["revision"],"generation":value["generation"],"attemptReference":value["attemptId"].as_str().map(|id|state::digest(id.as_bytes())),"status":state,"recordDigest":value["recordDigest"],"resolution":value["resolution"]["state"],"canonicalObservation":if operation {Value::Null}else{backend.clone()},"safeReason":reason,"retirementEligible":eligible,"cleanupEligible":value["cleanupEligible"]==true,"availableActions":if operation {if eligible {json!(["reconcile","retire-local"])}else{json!(["reconcile"])}}else{json!([])},"dependencies":"exact_receipt_linked_acceptance_caches_and_response_spools"})
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
                } else if matches!(
                    code,
                    "UNINSTALL_WORK_GENERATION_CAPABILITY_REQUIRED"
                        | "OPERATION_RETIREMENT_CAPABILITY_REQUIRED"
                ) {
                    "select_compatible_release"
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
    if !inspect {
        require(
            args.expected_release_path
                .as_deref()
                .is_none_or(|expected| expected == release),
            "UNINSTALL_WORK_BINDING_CHANGED",
        )?;
    }
    let manifest = read_manifest(&release)?;
    bootstrap_preflight::verify_artifact(&release, &manifest, args).await?;
    let scratch = RecoveryScratch(
        std::env::temp_dir().join(format!("loomex-work-qualification-{}", Uuid::new_v4())),
    );
    let payload = bootstrap_preflight::extract_artifact(&release, &manifest, &scratch.0).await?;
    bootstrap_preflight::verify_envelope(&release, &payload, &manifest)?;
    let transition =
        qualify_before_settlement(paths, args, &old, &old_bytes, &release, &manifest, &payload)
            .await?;
    let qualification = work_state_preflight(paths, args, &release, transition, &old_bytes)?;
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
        json!({"schema":generations::OWNER_V2,"operationId":id,"journalSha256":state::digest(&old_bytes),"releasePath":release,"releaseManifestSha256":digest_file(&release.join("manifest.json"))?,"phase":"qualified","attempt":null,"currentGeneration":0,"attemptIds":[],"generations":[{"generation":0,"releasePath":release,"releaseManifestSha256":digest_file(&release.join("manifest.json"))?,"files":manifest["payload"]["files"],"stageName":format!("uninstall-work-stage-{id}-generation-0")}]})
    };
    let id = Uuid::parse_str(work["operationId"].as_str().context("invalid work owner")?)?;
    *selected = Some(id);
    require_attempt_arguments(&work, args)?;
    if work["attempt"].is_null() && work["schema"] == WORK_SCHEMA {
        generations::preserve_legacy_owner(paths, &mut work)?;
    }
    let fence_digest = old["fenceJournalSha256"]
        .as_str()
        .unwrap_or(work["journalSha256"].as_str().unwrap())
        .to_owned();
    lifecycle::begin_uninstall_work_locked(paths, id, &fence_digest)?;
    if retirement_scope(args) == "operation-observations" {
        lifecycle::fence_operation_observation_work_locked(paths, id)?;
    }
    if work["schema"] == generations::OWNER_V2 {
        lifecycle::adopt_uninstall_work_generation_locked(paths, id, &fence_digest)?;
    }
    save_work(paths, &work)?;
    stop_service(paths, &old, &mut work).await?;
    let guard = quiescent_singleton(paths, &old).await?;
    let reserved = work["attempt"]["state"] == "context_pending";
    if reserved {
        publish_reserved_context(paths, &mut work)?;
    }
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
            if consume_cached_result(paths, &mut work, &old_bytes, result)? {
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
        if !reserved {
            exited_attempt_pid(&work)?;
        }
        let context_path = paths
            .state_dir
            .join(format!("uninstall-work-context-{attempt}.json"));
        require(
            digest_file(&context_path)? == work["attempt"]["contextSha256"],
            "UNINSTALL_WORK_BINDING_CHANGED",
        )?;
        let context: Value = work_json(&context_path)?;
        let binary = generations::verified_stage(paths, &work)?.join("bin/loomex-runner");
        require(
            digest_file(&binary)? == context["binarySha256"]
                && context["action"] == args.work_action.as_deref().unwrap_or("")
                && saved_scope(&context) == retirement_scope(args)
                && context["expectedAssessmentSha256"].as_str()
                    == args.expected_assessment_sha256.as_deref(),
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
    if owner_path.try_exists()? {
        let root = paths
            .state_dir
            .join("recovery-evidence")
            .join(id.to_string());
        state::private_dir(&paths.state_dir.join("recovery-evidence"))?;
        state::private_dir(&root)?;
        generations::upgrade(paths, &mut work, &release, &manifest)?;
        lifecycle::adopt_uninstall_work_generation_locked(paths, id, &fence_digest)?;
        save_work(paths, &work)?;
    }
    let stage = generations::stage(paths, &work)?;
    publish_stage(paths, &release, &manifest, &stage).await?;
    let binary = stage.join("bin/loomex-runner");
    let inherited = guard.try_clone()?;
    let fd = inherited.as_raw_fd();
    let attempt = Uuid::new_v4();
    let context = json!({"schema":"app.loomex.runner.uninstall-work-context/v2","maintenanceGeneration":work["currentGeneration"],"releaseManifestSha256":work["releaseManifestSha256"],"operationId":id,"attemptId":attempt,"stateDir":paths.state_dir,"installBase":paths.install_base,"launchAgentsDir":paths.launch_agents_dir,"journalSha256":work["journalSha256"],"receiptSha256":state::json_digest(&old["receipt"]),"binarySha256":digest_file(&binary)?,"action":args.work_action,"retirementScope":retirement_scope(args),"expectedAssessmentSha256":args.expected_assessment_sha256,"expectedIdentity":identity,"apiOrigin":old["receipt"]["developmentApiOrigin"],"singletonFd":fd,"authorizeKeychainTransition":args.authorize_keychain_transition && qualification["signingTransition"]=="needs_explicit_transition"});
    // Reserve exact bytes and identity before publishing the external context.
    let context_path = reserve_attempt(paths, &mut work, &context)?;
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

async fn qualify_before_settlement(
    paths: &lifecycle::Paths,
    args: &Arguments,
    old: &Value,
    old_bytes: &[u8],
    release: &Path,
    manifest: &Value,
    payload: &Path,
) -> Result<SigningTransition> {
    require(
        old_bytes.len() <= 16 * 1024 * 1024,
        "UNINSTALL_WORK_AUDIT_LIMIT",
    )?;
    let transition = qualify_work_candidate(paths, args, old, release, manifest, payload).await?;
    if args.work_action.as_deref() == Some("reconcile") {
        require(
            args.expected_assessment_sha256.is_none(),
            "UNINSTALL_WORK_ASSESSMENT_CHANGED",
        )?;
    }
    if args.work_action.as_deref() != Some("inspect") {
        settle_known_successor_result(
            paths,
            old,
            old_bytes,
            release,
            args.work_action.as_deref() == Some("reconcile"),
        )
        .await?;
    }
    Ok(transition)
}

fn reserve_attempt(paths: &lifecycle::Paths, work: &mut Value, context: &Value) -> Result<PathBuf> {
    require(
        work["schema"] == generations::OWNER_V2 && work["attempt"].is_null(),
        "UNINSTALL_WORK_BINDING_CHANGED",
    )?;
    let attempt = context["attemptId"]
        .as_str()
        .context("invalid work attempt")?;
    Uuid::parse_str(attempt)?;
    let bytes = serde_json::to_vec(context)?;
    if work["attemptIds"].is_null() {
        work["attemptIds"] = json!([]);
    }
    require(
        work["attemptIds"]
            .as_array()
            .is_some_and(|ids| ids.len() < 64 && !ids.iter().any(|id| id == attempt)),
        "UNINSTALL_WORK_AUDIT_LIMIT",
    )?;
    work["attemptIds"]
        .as_array_mut()
        .unwrap()
        .push(json!(attempt));
    work["attempt"] = json!({"id":attempt,"maintenanceGeneration":work["currentGeneration"],"releaseManifestSha256":work["releaseManifestSha256"],"action":context["action"],"retirementScope":saved_scope(context),"expectedAssessmentSha256":context["expectedAssessmentSha256"],"state":"context_pending","contextSha256":state::digest(&bytes),"pendingContext":String::from_utf8(bytes)?});
    save_work(paths, work)?;
    fault("AFTER_WORK_CONTEXT_RESERVATION")?;
    publish_reserved_context(paths, work)
}
fn publish_reserved_context(paths: &lifecycle::Paths, work: &mut Value) -> Result<PathBuf> {
    require(
        work["schema"] == generations::OWNER_V2
            && work["attempt"]["state"] == "context_pending"
            && work["attempt"]["pid"].is_null(),
        "UNINSTALL_WORK_MAINTENANCE_PENDING",
    )?;
    let attempt = work["attempt"]["id"]
        .as_str()
        .context("invalid work attempt")?
        .to_owned();
    Uuid::parse_str(&attempt)?;
    let bytes = work["attempt"]["pendingContext"]
        .as_str()
        .context("missing reserved context")?
        .as_bytes()
        .to_vec();
    require(
        bytes.len() <= 262144 && state::digest(&bytes) == work["attempt"]["contextSha256"],
        "UNINSTALL_WORK_BINDING_CHANGED",
    )?;
    let context: Value = serde_json::from_slice(&bytes)?;
    let old: Value = work_json(&paths.state_dir.join("bootstrap-uninstall.json"))?;
    let identity = if old["schema"] == OLD_SCHEMA {
        prior_identity(paths)?
    } else {
        validated_current_identity(&old)?
    };
    let stage = generations::verified_stage(paths, work)?;
    require(
        context["schema"] == "app.loomex.runner.uninstall-work-context/v2"
            && context["operationId"] == work["operationId"]
            && context["attemptId"] == attempt
            && context["maintenanceGeneration"] == work["currentGeneration"]
            && context["maintenanceGeneration"] == work["attempt"]["maintenanceGeneration"]
            && context["releaseManifestSha256"] == work["releaseManifestSha256"]
            && context["releaseManifestSha256"] == work["attempt"]["releaseManifestSha256"]
            && context["journalSha256"] == work["journalSha256"]
            && context["journalSha256"]
                == digest_file(&paths.state_dir.join("bootstrap-uninstall.json"))?
            && context["receiptSha256"] == state::json_digest(&old["receipt"])
            && context["expectedIdentity"] == identity
            && context["action"] == work["attempt"]["action"]
            && saved_scope(&context) == saved_scope(&work["attempt"])
            && context["expectedAssessmentSha256"] == work["attempt"]["expectedAssessmentSha256"]
            && context["stateDir"] == json!(paths.state_dir)
            && context["installBase"] == json!(paths.install_base)
            && context["launchAgentsDir"] == json!(paths.launch_agents_dir)
            && context["binarySha256"] == digest_file(&stage.join("bin/loomex-runner"))?
            && context["singletonFd"]
                .as_i64()
                .is_some_and(|fd| fd >= 3 && fd <= i64::from(i32::MAX)),
        "UNINSTALL_WORK_BINDING_CHANGED",
    )?;
    for kind in ["requests", "result", "authorization"] {
        require(
            !present(
                &paths
                    .state_dir
                    .join(format!("uninstall-work-{kind}-{attempt}.json")),
            )?,
            "UNINSTALL_WORK_BINDING_CHANGED",
        )?;
    }
    for index in 0..256 {
        for kind in ["checkpoint", "cache"] {
            require(
                !present(
                    &paths
                        .state_dir
                        .join(format!("uninstall-work-{kind}-{attempt}-{index}.json")),
                )?,
                "UNINSTALL_WORK_BINDING_CHANGED",
            )?;
        }
    }
    let path = paths
        .state_dir
        .join(format!("uninstall-work-context-{attempt}.json"));
    immutable_copy(&path, &bytes)?;
    fault("AFTER_WORK_CONTEXT_PUBLICATION")?;
    work["attempt"]["state"] = json!("spawn_pending");
    work["attempt"]
        .as_object_mut()
        .unwrap()
        .remove("pendingContext");
    save_work(paths, work)?;
    Ok(path)
}
fn exited_attempt_pid(work: &Value) -> Result<i32> {
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
    Ok(pid)
}

/// All known migration failures cross the same review boundary before respawn.
fn consume_cached_result(
    paths: &lifecycle::Paths,
    work: &mut Value,
    old_bytes: &[u8],
    result: &Value,
) -> Result<bool> {
    require(
        result["operationId"] == work["operationId"]
            && result["attemptId"] == work["attempt"]["id"],
        "UNINSTALL_WORK_BINDING_CHANGED",
    )?;
    audit(paths, work, old_bytes, result)?;
    if result["ok"] != true {
        if result["failureCode"] == "MANAGED_WORK_MIGRATION_CHANGED" {
            require_attempt_result(paths, work, result)?;
        }
        return Ok(false);
    }
    work["lastAttempt"] = work["attempt"].take();
    work["attempt"] = Value::Null;
    work["phase"] = json!("settled");
    save_work(paths, work)?;
    Ok(true)
}

/// A completed original child is consumed without executing either release.
/// An absent/uncertain result continues to pin the original release and context.
async fn settle_known_successor_result(
    paths: &lifecycle::Paths,
    old: &Value,
    old_bytes: &[u8],
    release: &Path,
    allow_failed_reconcile: bool,
) -> Result<()> {
    let owner_path = paths.state_dir.join("uninstall-work.json");
    if !owner_path.try_exists()? {
        return Ok(());
    }
    let mut work: Value = work_json(&owner_path)?;
    if work["attempt"].is_null()
        || (work["releaseManifestSha256"] == digest_file(&release.join("manifest.json"))?
            && work["releasePath"].as_str() == Some(release.to_string_lossy().as_ref()))
    {
        return Ok(());
    }
    require(
        generations::supported(&work) && work["journalSha256"] == state::digest(old_bytes),
        "UNINSTALL_WORK_BINDING_CHANGED",
    )?;
    let attempt = work["attempt"]["id"]
        .as_str()
        .context("invalid work attempt")?
        .to_owned();
    Uuid::parse_str(&attempt)?;
    let result_path = paths
        .state_dir
        .join(format!("uninstall-work-result-{attempt}.json"));
    if !result_path.try_exists()? {
        return Ok(());
    }
    let _guard = quiescent_singleton(paths, old).await?;
    let result: Value = work_json(&result_path)?;
    require(
        result["operationId"] == work["operationId"] && result["attemptId"] == attempt,
        "UNINSTALL_WORK_BINDING_CHANGED",
    )?;
    if allow_failed_reconcile && generations::failed_reconcile_candidate(paths, &work)? {
        generations::settle_failed_reconcile(paths, &mut work, old_bytes)?;
    } else {
        consume_cached_result(paths, &mut work, old_bytes, &result)?;
    }
    Ok(())
}

/// Publish only a complete verified stage. Interrupted known-file prefixes may
/// be removed; unknown entries and modified files are preserved and refused.
async fn publish_stage(
    paths: &lifecycle::Paths,
    release: &Path,
    manifest: &Value,
    stage: &Path,
) -> Result<()> {
    let files = manifest["payload"]["files"]
        .as_array()
        .context("missing work inventory")?;
    if present(stage)? {
        let metadata = fs::symlink_metadata(stage)?;
        require(
            metadata.is_dir() && !metadata.file_type().is_symlink(),
            "UNINSTALL_WORK_BINDING_CHANGED",
        )?;
        if inventory(stage, files).is_ok() {
            return Ok(());
        }
        lifecycle::prune_quarantine_inventory(stage, files, true)?;
        fs::remove_dir_all(stage)?;
        File::open(&paths.state_dir)?.sync_all()?;
    }
    let publishing = paths.state_dir.join(format!(
        ".{}.publishing",
        stage
            .file_name()
            .context("invalid stage")?
            .to_string_lossy()
    ));
    if present(&publishing)? {
        lifecycle::prune_quarantine_inventory(&publishing, files, true)?;
        fs::remove_dir_all(&publishing)?;
        File::open(&paths.state_dir)?.sync_all()?;
    }
    bootstrap_preflight::extract_artifact(release, manifest, &publishing).await?;
    // The lifecycle and singleton owners exclude supported concurrent publishers.
    require(!present(stage)?, "UNINSTALL_WORK_BINDING_CHANGED")?;
    fs::rename(&publishing, stage)?;
    File::open(&paths.state_dir)?.sync_all()?;
    Ok(())
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
        generations::supported(&work)
            && work["journalSha256"] == old_digest
            && work["releasePath"].as_str() == Some(release.to_string_lossy().as_ref())
            && work["releaseManifestSha256"] == digest_file(&release.join("manifest.json"))?
            && work["attempt"].is_null(),
        "UNINSTALL_WORK_BINDING_CHANGED",
    )?;
    generations::prove_inactive(paths, &work)?;
    for generation in generations::records(&work)? {
        let stage = paths
            .state_dir
            .join(generation["stageName"].as_str().unwrap());
        if present(&stage)? {
            lifecycle::prune_quarantine_inventory(
                &stage,
                generation["files"]
                    .as_array()
                    .context("missing work inventory")?,
                true,
            )?;
        }
    }
    let _ = manifest; // Each retained stage belongs to its own generation inventory.
    Ok(())
}

fn validate_cleanup_approvals(paths: &lifecycle::Paths, work: &Value) -> Result<()> {
    let id = Uuid::parse_str(work["operationId"].as_str().context("invalid work owner")?)?;
    for attempt in work["attemptIds"]
        .as_array()
        .context("invalid work attempts")?
    {
        let attempt = Uuid::parse_str(attempt.as_str().context("invalid work attempt")?)?;
        if !work["failedReconcileProofs"][attempt.to_string()].is_null() {
            generations::verify_failed_proof(paths, work, &attempt.to_string())?;
            continue;
        }
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
                && approval["releaseManifestSha256"]
                    == if work["schema"] == generations::OWNER_V2 {
                        generations::attempt_release(paths,work,&attempt.to_string())?["releaseManifestSha256"].clone()
                    } else {
                        work["releaseManifestSha256"].clone()
                    }
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

    Ok(())
}

/// Destructive uninstall has adopted the exact work owner and all native child
/// handles have closed. Remove only that owner's verified temporary resources.
pub(super) fn cleanup_resources(paths: &lifecycle::Paths, journal: &Value) -> Result<()> {
    let owner = paths.state_dir.join("uninstall-work.json");
    if !present(&owner)? {
        return generation_cleanup::require_completed(paths, journal);
    }
    let work: Value = work_json(&owner)?;
    require(
        generations::supported(&work)
            && work["operationId"] == journal["operationId"]
            && work["journalSha256"] == journal["recovery"]["oldJournalSha256"]
            && work["attempt"].is_null(),
        "UNINSTALL_WORK_BINDING_CHANGED",
    )?;
    if work["schema"] == generations::OWNER_V2 {
        return generation_cleanup::cleanup(paths, &work, journal);
    }
    validate_cleanup_approvals(paths, &work)?;
    let id = Uuid::parse_str(work["operationId"].as_str().context("invalid work owner")?)?;
    let stage = paths.state_dir.join(format!("uninstall-work-stage-{id}"));
    if present(&stage)? {
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
    fn release_fixture(base: &Path, version: &str) -> (PathBuf, Value) {
        let release = base.join(format!("release-{version}"));
        let payload = base.join(format!("payload-{version}"));
        state::private_dir(&release).unwrap();
        state::private_dir(&payload).unwrap();
        state::private_dir(&payload.join("bin")).unwrap();
        state::private_dir(&payload.join("metadata")).unwrap();
        fs::write(payload.join("bin/loomex-runner"), version.as_bytes()).unwrap();
        let source =
            json!({"schema":"app.loomex.source-content/v1","sourceRevision":"a".repeat(40)});
        let mut source_bytes = serde_json::to_vec(&source).unwrap();
        source_bytes.push(b'\n');
        fs::write(
            payload.join("metadata/source-content-manifest.json"),
            &source_bytes,
        )
        .unwrap();
        let files=["bin/loomex-runner","metadata/source-content-manifest.json"].into_iter().map(|path| {
            let meta=fs::metadata(payload.join(path)).unwrap();
            json!({"path":path,"size":meta.len(),"mode":meta.mode()&0o777,"sha256":digest_file(&payload.join(path)).unwrap()})
        }).collect::<Vec<_>>();
        assert!(
            std::process::Command::new("/usr/bin/tar")
                .arg("-czf")
                .arg(release.join("payload.tar.gz"))
                .arg("-C")
                .arg(&payload)
                .arg(".")
                .status()
                .unwrap()
                .success()
        );
        let manifest = json!({"schema":"app.loomex.release/v1","project":"loomex-runner","platform":"darwin-arm64","version":version,"sourceRevision":"a".repeat(40),"sourceContent":{"file":"metadata/source-content-manifest.json","sha256":state::digest(&source_bytes)},"payload":{"file":"payload.tar.gz","sha256":digest_file(&release.join("payload.tar.gz")).unwrap(),"files":files}});
        let mut bytes = serde_json::to_vec(&manifest).unwrap();
        bytes.push(b'\n');
        fs::write(release.join("manifest.json"), bytes).unwrap();
        (release, manifest)
    }
    fn fixture_attempt(
        paths: &lifecycle::Paths,
        work: &mut Value,
        old: &Value,
        old_bytes: &[u8],
        v2: bool,
    ) -> Uuid {
        let attempt = Uuid::new_v4();
        let stage = generations::stage(paths, work).unwrap();
        let mut context = json!({"schema":"app.loomex.runner.uninstall-work-context/v1","operationId":work["operationId"],"attemptId":attempt,"action":"reconcile","retirementScope":"continuations","journalSha256":state::digest(old_bytes),"receiptSha256":state::json_digest(&old["receipt"]),"expectedIdentity":prior_identity(paths).unwrap(),"binarySha256":digest_file(&stage.join("bin/loomex-runner")).unwrap(),"expectedAssessmentSha256":null});
        if v2 {
            context["schema"] = json!("app.loomex.runner.uninstall-work-context/v2");
            context["maintenanceGeneration"] = work["currentGeneration"].clone();
            context["releaseManifestSha256"] = work["releaseManifestSha256"].clone();
        }
        let context_path = paths
            .state_dir
            .join(format!("uninstall-work-context-{attempt}.json"));
        state::write_json(&context_path, &context).unwrap();
        state::write_json(
            &paths
                .state_dir
                .join(format!("uninstall-work-requests-{attempt}.json")),
            &json!({"operationId":work["operationId"],"attemptId":attempt,"requests":[]}),
        )
        .unwrap();
        let mut result = json!({"operationId":work["operationId"],"attemptId":attempt,"ok":true,"result":{"receipts":[]}});
        work["attempt"] = json!({"id":attempt,"action":"reconcile","retirementScope":"continuations","expectedAssessmentSha256":null,"contextSha256":digest_file(&context_path).unwrap()});
        if v2 {
            for key in ["maintenanceGeneration", "releaseManifestSha256"] {
                work["attempt"][key] = context[key].clone();
                result[key] = context[key].clone();
            }
            result["contextSha256"] = work["attempt"]["contextSha256"].clone();
        }
        if work["attemptIds"].is_null() {
            work["attemptIds"] = json!([]);
        }
        work["attemptIds"]
            .as_array_mut()
            .unwrap()
            .push(json!(attempt));
        state::write_json(
            &paths
                .state_dir
                .join(format!("uninstall-work-result-{attempt}.json")),
            &result,
        )
        .unwrap();
        audit(paths, work, old_bytes, &result).unwrap();
        work["lastAttempt"] = work["attempt"].take();
        work["attempt"] = Value::Null;
        work["phase"] = json!("settled");
        save_work(paths, work).unwrap();
        attempt
    }
    fn state_bytes(root: &Path) -> std::collections::BTreeMap<PathBuf, Vec<u8>> {
        fn walk(root: &Path, dir: &Path, out: &mut std::collections::BTreeMap<PathBuf, Vec<u8>>) {
            for entry in fs::read_dir(dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    walk(root, &path, out);
                } else {
                    out.insert(
                        path.strip_prefix(root).unwrap().into(),
                        regular_bytes(&path).unwrap(),
                    );
                }
            }
        }
        let mut out = std::collections::BTreeMap::new();
        walk(root, root, &mut out);
        out
    }
    #[tokio::test]
    async fn historical_settlement_qualifies_successor_read_only_and_cleans_mixed_release_stages() {
        const CHILD: &str = "LOOMEX_TEST_WORK_CLEANUP_ROOT";
        if let Some(base) = std::env::var_os(CHILD) {
            let base = PathBuf::from(base);
            let paths = lifecycle::Paths {
                state_dir: base.join("state"),
                install_base: base.join("install"),
                launch_agents_dir: base.join("agents"),
            };
            let journal: Value = work_json(&base.join("cleanup-fixture-journal.json")).unwrap();
            let error = cleanup_resources(&paths, &journal).unwrap_err();
            assert!(
                error.to_string().contains("DURING_WORK_RESOURCE_DELETE"),
                "{error:#}"
            );
            return;
        }
        let fixture = super::super::tests::historical_fixture();
        let paths = &fixture.paths;
        let base = paths.state_dir.parent().unwrap();
        let (old_release, old_manifest) = release_fixture(base, "1.2.9");
        let (new_release, new_manifest) = release_fixture(base, "1.2.11");
        let old_bytes = regular_bytes(&paths.state_dir.join("bootstrap-uninstall.json")).unwrap();
        let id = Uuid::new_v4();
        let old_stage = paths.state_dir.join(format!("uninstall-work-stage-{id}"));
        publish_stage(paths, &old_release, &old_manifest, &old_stage)
            .await
            .unwrap();
        let mut work = json!({"schema":WORK_SCHEMA,"operationId":id,"journalSha256":state::digest(&old_bytes),"releasePath":old_release,"releaseManifestSha256":digest_file(&old_release.join("manifest.json")).unwrap(),"phase":"qualified","attempt":null});
        save_work(paths, &work).unwrap();
        let original_attempt =
            fixture_attempt(paths, &mut work, &fixture.journal, &old_bytes, false);
        let original_owner = regular_bytes(&paths.state_dir.join("uninstall-work.json")).unwrap();
        lifecycle::begin_uninstall_work_locked(paths, id, &state::digest(&old_bytes)).unwrap();
        // Retained deny evidence must keep its outer v12 fence through v13.
        let original_cache = serde_json::to_string(
            &json!({"digest":"b".repeat(64),"method":"interactions.respond","status":"pending"}),
        )
        .unwrap();
        let slot = "c".repeat(64);
        let evidence = json!({"schema":"loomex.operation-cache-retirement/v1","legacySlot":slot,"originalCache":original_cache,"originalCacheSha256":state::digest(original_cache.as_bytes()),"provenance":{"operationId":id,"attemptId":original_attempt,"journalSha256":state::digest(&old_bytes),"receiptSha256":"b".repeat(64),"expectedAssessmentSha256":"c".repeat(64),"requestSetSha256":"d".repeat(64),"contextSha256":"e".repeat(64),"installationId":"fixture-install","retirementScope":"operation-observations","canonicalObservation":{"remoteOutcome":"unknown","safeReason":"missing_binding"}},"remoteOutcome":"unknown","denyOnly":true,"retiredAt":state::now()});
        let evidence_path = paths.state_dir.join("recovery-evidence").join(format!(
            "operation-cache-{}.json",
            state::digest(slot.as_bytes())
        ));
        state::write_json(&evidence_path, &evidence).unwrap();
        lifecycle::fence_operation_observation_work_locked(paths, id).unwrap();
        state::private_dir(&paths.state_dir.join("operations")).unwrap();
        for (index, method) in [
            "interactions.respond",
            "interactions.draft.delete",
            "interactions.respond",
            "auth.recover",
            "builder.start",
            "interactions.respond",
            "interactions.respond",
        ]
        .into_iter()
        .enumerate()
        {
            let slot = if method == "auth.recover" {
                Uuid::new_v4().to_string()
            } else {
                state::digest(format!("legacy-{index}").as_bytes())
            };
            let value = if method == "builder.start" {
                json!({"digest":"a".repeat(64),"method":method,"executionId":Uuid::new_v4(),"result":{"status":"queued"},"cachedAt":1})
            } else {
                json!({"digest":"b".repeat(64),"method":method,"status":"pending"})
            };
            state::write_json(
                &paths
                    .state_dir
                    .join("operations")
                    .join(format!("{slot}.json")),
                &value,
            )
            .unwrap();
        }
        let before = state_bytes(&paths.state_dir);
        let candidate = digest_file(&new_release.join("manifest.json")).unwrap();
        assert_eq!(
            generations::candidate_transition(paths, &work, &candidate, Some(&new_release))
                .unwrap(),
            "eligible_successor"
        );
        let reference = work_maintenance_reference(paths, Some(&candidate), Some(&new_release));
        assert_eq!(reference["transition"], "eligible_successor");
        assert_eq!(reference["operationId"], id.to_string());
        let (assessment, preview) = review_state(paths).unwrap();
        assert_eq!(assessment["resolved"], false);
        assert_eq!(
            preview["records"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|record| record["kind"] == "operation_cache")
                .count(),
            7
        );
        assert_eq!(
            state_bytes(&paths.state_dir),
            before,
            "inspection must preserve every byte"
        );
        let _lock = lifecycle::LifecycleLock::acquire(paths).unwrap();
        lifecycle::adopt_uninstall_work_generation_locked(paths, id, &state::digest(&old_bytes))
            .unwrap();
        generations::upgrade(paths, &mut work, &new_release, &new_manifest).unwrap();
        save_work(paths, &work).unwrap();
        assert_eq!(work["operationId"], id.to_string());
        assert_eq!(work["currentGeneration"], 1);
        assert!(!generations::reconciled_current(paths, &work).unwrap());
        assert_eq!(
            regular_bytes(
                &paths
                    .state_dir
                    .join("recovery-evidence")
                    .join(id.to_string())
                    .join("original-work-owner-v1.json")
            )
            .unwrap(),
            original_owner
        );
        let new_stage = generations::stage(paths, &work).unwrap();
        publish_stage(paths, &new_release, &new_manifest, &new_stage)
            .await
            .unwrap();
        assert_eq!(
            fs::read(old_stage.join("bin/loomex-runner")).unwrap(),
            b"1.2.9"
        );
        fixture_attempt(paths, &mut work, &fixture.journal, &old_bytes, true);
        assert!(generations::reconciled_current(paths, &work).unwrap());
        require_recovery_binding(
            paths,
            &state::digest(&old_bytes),
            &new_release,
            &new_manifest,
        )
        .unwrap();
        let lifecycle_owner: Value =
            work_json(&paths.state_dir.join("lifecycle-operation.json")).unwrap();
        assert_eq!(
            lifecycle_owner["schema"],
            "app.loomex.runner.lifecycle-operation/v12"
        );
        assert_eq!(
            lifecycle_owner["logicalSchema"],
            lifecycle::GENERATION_UNINSTALL_WORK_SCHEMA
        );
        let journal = json!({"operationId":id,"recovery":{"oldJournalSha256":state::digest(&old_bytes),"files":new_manifest["payload"]["files"]}});
        let approval_path = paths
            .state_dir
            .join("recovery-evidence")
            .join(id.to_string())
            .join(format!("approval-{original_attempt}.json"));
        let approval_bytes = regular_bytes(&approval_path).unwrap();
        let mut changed: Value = serde_json::from_slice(&approval_bytes).unwrap();
        changed["releaseManifestSha256"] = json!(candidate);
        state::write_json(&approval_path, &changed).unwrap();
        assert!(cleanup_resources(paths, &journal).is_err());
        assert!(old_stage.exists());
        assert!(new_stage.exists());
        state::atomic_write(&approval_path, &approval_bytes).unwrap();
        let resource_before = state_bytes(&paths.state_dir);
        state::write_json(&base.join("cleanup-fixture-journal.json"), &journal).unwrap();
        let status=std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact").arg("bootstrap_uninstall::work::tests::historical_settlement_qualifies_successor_read_only_and_cleans_mixed_release_stages")
            .env(CHILD,base).env("LOOMEX_TEST_UNINSTALL_FAIL_DURING_WORK_RESOURCE_DELETE","1").status().unwrap();
        assert!(status.success());
        assert!(paths.state_dir.join("uninstall-work.json").exists());
        assert!(
            paths
                .state_dir
                .join("recovery-evidence")
                .join(id.to_string())
                .join("work-cleanup-plan.json")
                .exists()
        );
        let deleted = resource_before
            .keys()
            .filter(|path| {
                path.to_string_lossy()
                    .starts_with("uninstall-work-context-")
                    && !paths.state_dir.join(path).exists()
            })
            .collect::<Vec<_>>();
        assert_eq!(
            deleted.len(),
            1,
            "fault must occur after one context deletion"
        );
        let remaining = resource_before
            .keys()
            .find(|path| {
                path.to_string_lossy()
                    .starts_with("uninstall-work-context-")
                    && paths.state_dir.join(path).exists()
            })
            .unwrap();
        let remaining_bytes = regular_bytes(&paths.state_dir.join(remaining)).unwrap();
        fs::write(
            paths.state_dir.join(remaining),
            b"changed after cleanup checkpoint",
        )
        .unwrap();
        assert!(cleanup_resources(paths, &journal).is_err());
        state::atomic_write(&paths.state_dir.join(remaining), &remaining_bytes).unwrap();
        let unknown = paths
            .state_dir
            .join(format!("uninstall-work-result-{}.json", Uuid::new_v4()));
        state::atomic_write(&unknown, b"{}").unwrap();
        assert!(cleanup_resources(paths, &journal).is_err());
        assert!(unknown.exists());
        remove_regular(&unknown).unwrap();
        cleanup_resources(paths, &journal).unwrap();
        cleanup_resources(paths, &journal).unwrap();
        let resurrected = paths.state_dir.join(deleted[0]);
        state::atomic_write(&resurrected, resource_before.get(deleted[0]).unwrap()).unwrap();
        assert!(
            cleanup_resources(paths, &journal).is_err(),
            "absent owner must not mask surviving plan resources"
        );
        remove_regular(&resurrected).unwrap();
        cleanup_resources(paths, &journal).unwrap();
        assert!(!old_stage.exists());
        assert!(!new_stage.exists());
        assert!(!paths.state_dir.join("uninstall-work.json").exists());
        assert_eq!(
            regular_bytes(&paths.state_dir.join("bootstrap-uninstall.json")).unwrap(),
            old_bytes
        );
        assert!(evidence_path.exists());
        assert_eq!(regular_bytes(&approval_path).unwrap(), approval_bytes);
    }
    #[tokio::test]
    async fn context_reservation_recovers_both_publication_boundaries_with_one_identity() {
        const CHILD: &str = "LOOMEX_TEST_CONTEXT_RESERVATION_ROOT";
        if let Some(base) = std::env::var_os(CHILD) {
            let base = PathBuf::from(base);
            let paths = lifecycle::Paths {
                state_dir: base.join("state"),
                install_base: base.join("install"),
                launch_agents_dir: base.join("agents"),
            };
            let mut work: Value = work_json(&paths.state_dir.join("uninstall-work.json")).unwrap();
            let context: Value = work_json(&base.join("reservation-context.json")).unwrap();
            let error = reserve_attempt(&paths, &mut work, &context).unwrap_err();
            assert!(error.to_string().contains("WORK_CONTEXT_"), "{error:#}");
            return;
        }
        for point in [
            "AFTER_WORK_CONTEXT_RESERVATION",
            "AFTER_WORK_CONTEXT_PUBLICATION",
        ] {
            let fixture = super::super::tests::historical_fixture();
            let paths = &fixture.paths;
            let base = paths.state_dir.parent().unwrap();
            let (release, manifest) = release_fixture(base, "1.2.11");
            let id = Uuid::new_v4();
            let mut work = json!({"schema":WORK_SCHEMA,"operationId":id,"journalSha256":digest_file(&paths.state_dir.join("bootstrap-uninstall.json")).unwrap(),"releasePath":release,"releaseManifestSha256":digest_file(&release.join("manifest.json")).unwrap(),"phase":"qualified","attempt":null,"attemptIds":[]});
            save_work(paths, &work).unwrap();
            generations::upgrade(paths, &mut work, &release, &manifest).unwrap();
            save_work(paths, &work).unwrap();
            let stage = generations::stage(paths, &work).unwrap();
            publish_stage(paths, &release, &manifest, &stage)
                .await
                .unwrap();
            let orphan = paths
                .state_dir
                .join(format!("uninstall-work-context-{}.json", Uuid::new_v4()));
            state::atomic_write(&orphan, b"historically unbound context").unwrap();
            assert!(generations::prove_inactive(paths, &work).is_err());
            assert_eq!(
                regular_bytes(&orphan).unwrap(),
                b"historically unbound context"
            );
            remove_regular(&orphan).unwrap();
            let attempt = Uuid::new_v4();
            let context = json!({"schema":"app.loomex.runner.uninstall-work-context/v2","operationId":id,"attemptId":attempt,"maintenanceGeneration":work["currentGeneration"],"releaseManifestSha256":work["releaseManifestSha256"],"stateDir":paths.state_dir,"installBase":paths.install_base,"launchAgentsDir":paths.launch_agents_dir,"journalSha256":work["journalSha256"],"receiptSha256":state::json_digest(&fixture.journal["receipt"]),"binarySha256":digest_file(&stage.join("bin/loomex-runner")).unwrap(),"action":"reconcile","retirementScope":"continuations","expectedAssessmentSha256":null,"expectedIdentity":prior_identity(paths).unwrap(),"apiOrigin":null,"singletonFd":9,"authorizeKeychainTransition":false});
            state::write_json(&base.join("reservation-context.json"), &context).unwrap();
            assert!(std::process::Command::new(std::env::current_exe().unwrap()).arg("--exact").arg("bootstrap_uninstall::work::tests::context_reservation_recovers_both_publication_boundaries_with_one_identity").env(CHILD,base).env(format!("LOOMEX_TEST_UNINSTALL_FAIL_{point}"),"1").status().unwrap().success());
            let mut saved: Value = work_json(&paths.state_dir.join("uninstall-work.json")).unwrap();
            let path = paths
                .state_dir
                .join(format!("uninstall-work-context-{attempt}.json"));
            let exact = serde_json::to_vec(&context).unwrap();
            assert_eq!(saved["attempt"]["id"], attempt.to_string());
            assert_eq!(saved["attempt"]["state"], "context_pending");
            assert_eq!(saved["attempt"]["contextSha256"], state::digest(&exact));
            assert_eq!(saved["attemptIds"], json!([attempt]));
            assert_eq!(path.exists(), point == "AFTER_WORK_CONTEXT_PUBLICATION");
            let moved = base.join("relocated-stage");
            fs::rename(&stage, &moved).unwrap();
            std::os::unix::fs::symlink(&moved, &stage).unwrap();
            assert!(publish_reserved_context(paths, &mut saved).is_err());
            assert!(
                fs::symlink_metadata(&stage)
                    .unwrap()
                    .file_type()
                    .is_symlink()
            );
            fs::remove_file(&stage).unwrap();
            fs::rename(&moved, &stage).unwrap();
            // A conflicting published context is preserved, and cannot acquire a child.
            state::atomic_write(&path, b"different immutable context").unwrap();
            let before = regular_bytes(&paths.state_dir.join("uninstall-work.json")).unwrap();
            assert!(publish_reserved_context(paths, &mut saved).is_err());
            assert_eq!(
                regular_bytes(&path).unwrap(),
                b"different immutable context"
            );
            assert_eq!(
                regular_bytes(&paths.state_dir.join("uninstall-work.json")).unwrap(),
                before
            );
            if point == "AFTER_WORK_CONTEXT_PUBLICATION" {
                state::atomic_write(&path, &exact).unwrap();
            } else {
                remove_regular(&path).unwrap();
            }
            publish_reserved_context(paths, &mut saved).unwrap();
            assert_eq!(regular_bytes(&path).unwrap(), exact);
            assert_eq!(saved["attempt"]["id"], attempt.to_string());
            assert_eq!(saved["attempt"]["state"], "spawn_pending");
            assert_eq!(saved["attemptIds"], json!([attempt]));
            assert!(saved["attempt"].get("pendingContext").is_none());
            assert!(publish_reserved_context(paths, &mut saved).is_err());
            assert_eq!(
                exited_attempt_pid(&saved).unwrap_err().to_string(),
                "UNINSTALL_WORK_MAINTENANCE_PENDING"
            );
            assert!(
                !paths
                    .state_dir
                    .join(format!("uninstall-work-result-{attempt}.json"))
                    .exists()
            );
        }
    }
    #[tokio::test]
    async fn unqualified_candidate_cannot_consume_a_known_original_result() {
        let fixture = super::super::tests::historical_fixture();
        let paths = &fixture.paths;
        let base = paths.state_dir.parent().unwrap();
        let (release, manifest) = release_fixture(base, "1.2.9");
        let (candidate, mut candidate_manifest) = release_fixture(base, "1.2.11");
        let id = Uuid::new_v4();
        let bytes = regular_bytes(&paths.state_dir.join("bootstrap-uninstall.json")).unwrap();
        let stage = paths.state_dir.join(format!("uninstall-work-stage-{id}"));
        publish_stage(paths, &release, &manifest, &stage)
            .await
            .unwrap();
        let mut work = json!({"schema":WORK_SCHEMA,"operationId":id,"journalSha256":state::digest(&bytes),"releasePath":release,"releaseManifestSha256":digest_file(&release.join("manifest.json")).unwrap(),"phase":"qualified","attempt":null});
        save_work(paths, &work).unwrap();
        fixture_attempt(paths, &mut work, &fixture.journal, &bytes, false);
        work["attempt"] = work["lastAttempt"].take();
        work["lastAttempt"] = Value::Null;
        save_work(paths, &work).unwrap();
        let payload = base.join("qualification-payload");
        state::private_dir(&payload).unwrap();
        state::private_dir(&payload.join("metadata")).unwrap();
        state::private_dir(&payload.join("bin")).unwrap();
        state::write_json(
            &payload.join("metadata/project.json"),
            &json!({"project":"loomex-runner","version":"1.2.11","platform":"darwin-arm64"}),
        )
        .unwrap();
        let args = Arguments {
            work_action: Some("reconcile".into()),
            development_api_origin: Some("http://127.0.0.1:9".into()),
            ..Default::default()
        };
        let before = state_bytes(&paths.state_dir);
        let oversized = vec![b' '; 16 * 1024 * 1024 + 1];
        assert_eq!(
            qualify_before_settlement(
                paths,
                &args,
                &fixture.journal,
                &oversized,
                &candidate,
                &candidate_manifest,
                &payload
            )
            .await
            .unwrap_err()
            .to_string(),
            "UNINSTALL_WORK_AUDIT_LIMIT"
        );
        assert_eq!(state_bytes(&paths.state_dir), before);
        candidate_manifest["bootstrap"] = json!({"sha256":"f".repeat(64)});
        assert!(
            qualify_before_settlement(
                paths,
                &args,
                &fixture.journal,
                &bytes,
                &candidate,
                &candidate_manifest,
                &payload
            )
            .await
            .is_err()
        );
        assert_eq!(state_bytes(&paths.state_dir), before);
        candidate_manifest["bootstrap"]["sha256"] =
            json!(digest_file(&std::env::current_exe().unwrap()).unwrap());
        candidate_manifest["developmentOnly"] = json!(true);
        for name in ["loomex", "loomex-runner", "loomex-lifecycle-bootstrap"] {
            fs::write(payload.join("bin").join(name), b"invalid signature").unwrap();
        }
        assert!(
            qualify_before_settlement(
                paths,
                &args,
                &fixture.journal,
                &bytes,
                &candidate,
                &candidate_manifest,
                &payload
            )
            .await
            .is_err()
        );
        assert_eq!(state_bytes(&paths.state_dir), before);
        #[cfg(target_os = "macos")]
        {
            for name in ["loomex", "loomex-runner", "loomex-lifecycle-bootstrap"] {
                fs::copy(
                    std::env::current_exe().unwrap(),
                    payload.join("bin").join(name),
                )
                .unwrap();
            }
            let error = qualify_before_settlement(
                paths,
                &args,
                &fixture.journal,
                &bytes,
                &candidate,
                &candidate_manifest,
                &payload,
            )
            .await
            .unwrap_err();
            assert!(
                error.to_string().contains("recovery origin differs"),
                "{error:#}"
            );
            assert_eq!(state_bytes(&paths.state_dir), before);
        }
    }
    #[test]
    fn active_retirement_requires_the_saved_assessment_and_scope() {
        let work = json!({"attempt":{"id":Uuid::new_v4(),"action":"retire-local","retirementScope":"continuations","expectedAssessmentSha256":"a".repeat(64)}});
        let mut args = Arguments {
            work_action: Some("retire-local".into()),
            expected_assessment_sha256: Some("b".repeat(64)),
            ..Default::default()
        };
        assert_eq!(
            require_attempt_arguments(&work, &args)
                .unwrap_err()
                .to_string(),
            "UNINSTALL_WORK_ASSESSMENT_CHANGED"
        );
        args.expected_assessment_sha256 = Some("a".repeat(64));
        require_attempt_arguments(&work, &args).unwrap();
        args.retirement_scope = Some("operation-observations".into());
        assert_eq!(
            require_attempt_arguments(&work, &args)
                .unwrap_err()
                .to_string(),
            "UNINSTALL_WORK_MAINTENANCE_PENDING"
        );
    }
    async fn failed_owner_fixture(
        early: bool,
        partial: bool,
    ) -> (super::super::tests::Fixture, Value, PathBuf, Value, Vec<u8>) {
        failed_owner_fixture_with_install(early, partial, false).await
    }
    async fn failed_owner_fixture_with_install(
        early: bool,
        partial: bool,
        signed_install: bool,
    ) -> (super::super::tests::Fixture, Value, PathBuf, Value, Vec<u8>) {
        let mut fixture = super::super::tests::historical_fixture();
        if signed_install {
            let runner = PathBuf::from(fixture.journal["receipt"]["versionPath"].as_str().unwrap())
                .join("bin/loomex-runner");
            fs::hard_link(std::env::current_exe().unwrap(), &runner).unwrap();
            let metadata = fs::metadata(&runner).unwrap();
            fixture.journal["inventories"][0]["files"].as_array_mut().unwrap().push(json!({"path":"bin/loomex-runner","sha256":digest_file(&runner).unwrap(),"size":metadata.len(),"mode":metadata.mode()&0o777}));
            fixture.journal["receipt"]["developmentOnly"] = json!(true);
            fixture.journal["receipt"]["developmentApiOrigin"] = json!("http://127.0.0.1:9/");
            state::write_json(
                &fixture.paths.state_dir.join("install-receipt.json"),
                &fixture.journal["receipt"],
            )
            .unwrap();
            state::write_json(
                &fixture.paths.state_dir.join("owned-versions.json"),
                &journal_owned(&fixture.journal),
            )
            .unwrap();
            save(&fixture.paths, &fixture.journal).unwrap();
        }
        let paths = &fixture.paths;
        let base = paths.state_dir.parent().unwrap();
        let (prior, prior_manifest) = release_fixture(base, "1.2.9");
        let (release, manifest) = release_fixture(base, "1.2.11");
        let (candidate, candidate_manifest) = release_fixture(base, "1.2.12");
        let old_bytes = regular_bytes(&paths.state_dir.join("bootstrap-uninstall.json")).unwrap();
        let id = Uuid::new_v4();
        let mut work = json!({"schema":generations::OWNER_V2,"operationId":id,"journalSha256":state::digest(&old_bytes),"releasePath":prior,"releaseManifestSha256":digest_file(&prior.join("manifest.json")).unwrap(),"phase":"qualified","attempt":null,"currentGeneration":0,"attemptIds":[],"generations":[{"generation":0,"releasePath":prior,"releaseManifestSha256":digest_file(&prior.join("manifest.json")).unwrap(),"files":prior_manifest["payload"]["files"],"stageName":format!("uninstall-work-stage-{id}-generation-0")}]});
        save_work(paths, &work).unwrap();
        publish_stage(
            paths,
            &prior,
            &prior_manifest,
            &generations::stage(paths, &work).unwrap(),
        )
        .await
        .unwrap();
        fixture_attempt(paths, &mut work, &fixture.journal, &old_bytes, true);
        generations::upgrade(paths, &mut work, &release, &manifest).unwrap();
        save_work(paths, &work).unwrap();
        let stage = generations::stage(paths, &work).unwrap();
        publish_stage(paths, &release, &manifest, &stage)
            .await
            .unwrap();
        let attempt = Uuid::new_v4();
        let context = json!({"schema":"app.loomex.runner.uninstall-work-context/v2","operationId":id,"attemptId":attempt,"action":"reconcile","retirementScope":"continuations","journalSha256":state::digest(&old_bytes),"receiptSha256":state::json_digest(&fixture.journal["receipt"]),"expectedIdentity":prior_identity(paths).unwrap(),"binarySha256":digest_file(&stage.join("bin/loomex-runner")).unwrap(),"expectedAssessmentSha256":null,"maintenanceGeneration":work["currentGeneration"],"releaseManifestSha256":work["releaseManifestSha256"],"stateDir":paths.state_dir,"installBase":paths.install_base,"launchAgentsDir":paths.launch_agents_dir,"singletonFd":9});
        let context_path = paths
            .state_dir
            .join(format!("uninstall-work-context-{attempt}.json"));
        state::write_json(&context_path, &context).unwrap();
        let mut child = std::process::Command::new("/usr/bin/true").spawn().unwrap();
        work["attempt"] = json!({"id":attempt,"pid":child.id(),"state":"running","action":"reconcile","retirementScope":"continuations","expectedAssessmentSha256":null,"contextSha256":digest_file(&context_path).unwrap(),"maintenanceGeneration":1,"releaseManifestSha256":work["releaseManifestSha256"]});
        child.wait().unwrap();
        work["attemptIds"]
            .as_array_mut()
            .unwrap()
            .push(json!(attempt));
        work["phase"] = json!("qualified");
        if !early {
            let request = json!({"kind":"presentation_operation","operationKey":Uuid::new_v4(),"method":"interactions.respond"});
            state::write_json(
                &paths
                    .state_dir
                    .join(format!("uninstall-work-requests-{attempt}.json")),
                &json!({"operationId":id,"attemptId":attempt,"requests":[request]}),
            )
            .unwrap();
            if partial {
                state::write_json(&paths.state_dir.join(format!("uninstall-work-checkpoint-{attempt}-0.json")), &json!({"operationId":id,"attemptId":attempt,"requestDigest":state::json_digest(&request),"result":{"remoteOutcome":"unknown"}})).unwrap();
                state::write_json(&paths.state_dir.join(format!("uninstall-work-cache-{attempt}-0.json")), &json!({"schema":"app.loomex.runner.uninstall-work-cache-transition/v1","operationId":id,"attemptId":attempt,"index":0,"requestDigest":state::json_digest(&request),"transition":{"schema":"app.loomex.runner.uninstall-work-cache/v1","beforeSha256":"a".repeat(64),"afterSha256":"b".repeat(64)}})).unwrap();
            }
        }
        let result_path = paths
            .state_dir
            .join(format!("uninstall-work-result-{attempt}.json"));
        let mut result = json!({"schema":"app.loomex.runner.uninstall-work-result/v2","operationId":id,"attemptId":attempt,"ok":false,"failureCode":"UNINSTALL_WORK_NATIVE_FAILED","maintenanceGeneration":1,"releaseManifestSha256":work["releaseManifestSha256"],"contextSha256":work["attempt"]["contextSha256"],"error":{"code":"STORE_UNAVAILABLE","outcome":"unknown","recovery":"reconcile_outcome","retryable":false}});
        state::write_json(&result_path, &result).unwrap();
        audit(paths, &work, &old_bytes, &result).unwrap();
        result["error"]["code"] = json!("AUTH_REQUIRED");
        state::write_json(&result_path, &result).unwrap();
        audit(paths, &work, &old_bytes, &result).unwrap();
        save_work(paths, &work).unwrap();
        drop(singleton(paths, true).unwrap());
        (fixture, work, candidate, candidate_manifest, old_bytes)
    }

    #[tokio::test]
    async fn inactive_failed_reconcile_qualifies_successor_without_erasing_failure() {
        let (fixture, work, candidate, _, _) = failed_owner_fixture(false, true).await;
        let paths = &fixture.paths;
        let before = state_bytes(&paths.state_dir);
        let hash = digest_file(&candidate.join("manifest.json")).unwrap();
        assert_eq!(work["currentGeneration"], 1);
        assert_eq!(
            generations::candidate_transition(paths, &work, &hash, Some(&candidate)).unwrap(),
            "eligible_successor"
        );
        assert_eq!(
            before,
            state_bytes(&paths.state_dir),
            "inspection is read only"
        );
        assert!(
            !generations::known_result(paths, &work).unwrap(),
            "failure never becomes a successful settlement"
        );
        let guard = singleton(paths, false).unwrap();
        assert!(
            generations::candidate_transition(paths, &work, &hash, Some(&candidate)).is_err(),
            "blocked native IO retains inherited singleton"
        );
        drop(guard);
        for pid in [Value::Null, json!(std::process::id()), json!(1)] {
            let mut pinned = work.clone();
            pinned["attempt"]["pid"] = pid;
            assert!(
                generations::candidate_transition(paths, &pinned, &hash, Some(&candidate)).is_err(),
                "live/reused/missing PID must remain pinned"
            );
        }
        let mut retire = work.clone();
        retire["attempt"]["action"] = json!("retire-local");
        retire["attempt"]["expectedAssessmentSha256"] = json!("a".repeat(64));
        assert!(
            generations::candidate_transition(paths, &retire, &hash, Some(&candidate)).is_err(),
            "failed retirement has no generic takeover authority"
        );
        let result_path = paths.state_dir.join(format!(
            "uninstall-work-result-{}.json",
            work["attempt"]["id"].as_str().unwrap()
        ));
        let original = regular_bytes(&result_path).unwrap();
        for bytes in [b"{malformed".as_slice(), b"{}".as_slice()] {
            state::atomic_write(&result_path, bytes).unwrap();
            assert!(
                generations::candidate_transition(paths, &work, &hash, Some(&candidate)).is_err()
            );
        }
        remove_regular(&result_path).unwrap();
        assert!(generations::candidate_transition(paths, &work, &hash, Some(&candidate)).is_err());
        state::atomic_write(&result_path, &original).unwrap();
        let mut changed: Value = serde_json::from_slice(&original).unwrap();
        changed["contextSha256"] = json!("f".repeat(64));
        state::write_json(&result_path, &changed).unwrap();
        assert!(generations::candidate_transition(paths, &work, &hash, Some(&candidate)).is_err());
        state::atomic_write(&result_path, &original).unwrap();
        assert_eq!(before, state_bytes(&paths.state_dir));
        let attempt = work["attempt"]["id"].as_str().unwrap();
        let root = paths
            .state_dir
            .join("recovery-evidence")
            .join(work["operationId"].as_str().unwrap());
        for path in [
            paths
                .state_dir
                .join(format!("uninstall-work-context-{attempt}.json")),
            paths
                .state_dir
                .join(format!("uninstall-work-requests-{attempt}.json")),
            paths
                .state_dir
                .join(format!("uninstall-work-checkpoint-{attempt}-0.json")),
            paths
                .state_dir
                .join(format!("uninstall-work-cache-{attempt}-0.json")),
            root.join(format!("approval-{attempt}.json")),
            paths
                .state_dir
                .join(work["generations"][1]["stageName"].as_str().unwrap())
                .join("bin/loomex-runner"),
            PathBuf::from(work["releasePath"].as_str().unwrap()).join("manifest.json"),
        ] {
            let bytes = regular_bytes(&path).unwrap();
            state::atomic_write(&path, b"{}").unwrap();
            assert!(
                generations::candidate_transition(paths, &work, &hash, Some(&candidate)).is_err(),
                "tampered {path:?}"
            );
            state::atomic_write(&path, &bytes).unwrap();
        }
        assert_eq!(before, state_bytes(&paths.state_dir));
    }

    #[tokio::test]
    async fn failed_reconcile_proof_preserves_early_and_partial_attempts_and_retirement_boundary() {
        for early in [false, true] {
            let (fixture, mut work, candidate, manifest, old_bytes) =
                failed_owner_fixture(early, !early).await;
            let paths = &fixture.paths;
            let _lifecycle = lifecycle::LifecycleLock::acquire(paths).unwrap();
            let guard = singleton(paths, false).unwrap();
            let before = state_bytes(&paths.state_dir);
            let attempt = work["attempt"]["id"].as_str().unwrap().to_owned();
            let id = work["operationId"].clone();
            generations::settle_failed_reconcile(paths, &mut work, &old_bytes).unwrap();
            assert!(work["attempt"].is_null());
            assert_eq!(work["phase"], "qualified");
            generations::prove_inactive(paths, &work).unwrap();
            for (path, bytes) in &before {
                if path != Path::new("uninstall-work.json")
                    && path != Path::new("lifecycle-operation.json")
                {
                    assert_eq!(
                        &regular_bytes(&paths.state_dir.join(path)).unwrap(),
                        bytes,
                        "preserved {path:?}"
                    );
                }
            }
            let root = paths
                .state_dir
                .join("recovery-evidence")
                .join(id.as_str().unwrap());
            assert_eq!(
                root.join(format!("approval-{attempt}.json")).exists(),
                !early,
                "early failure cannot manufacture approval"
            );
            let raw: Value = work_json(&paths.state_dir.join("lifecycle-operation.json")).unwrap();
            assert_eq!(raw["schema"], lifecycle::FAILED_RECONCILE_WORK_SCHEMA);
            generations::upgrade(paths, &mut work, &candidate, &manifest).unwrap();
            save_work(paths, &work).unwrap();
            assert_eq!(work["operationId"], id);
            assert_eq!(work["currentGeneration"], 2);
            assert!(!generations::reconciled_current(paths, &work).unwrap());
            let mut args = Arguments {
                work_action: Some("retire-local".into()),
                expected_assessment_sha256: Some("a".repeat(64)),
                ..Arguments::default()
            };
            assert_eq!(
                work_state_preflight(
                    paths,
                    &args,
                    &candidate,
                    SigningTransition::Ready,
                    &old_bytes
                )
                .unwrap_err()
                .to_string(),
                "UNINSTALL_WORK_RECONCILIATION_REQUIRED"
            );
            let stage = generations::stage(paths, &work).unwrap();
            publish_stage(paths, &candidate, &manifest, &stage)
                .await
                .unwrap();
            let fresh = fixture_attempt(paths, &mut work, &fixture.journal, &old_bytes, true);
            assert_ne!(fresh.to_string(), attempt);
            assert!(generations::reconciled_current(paths, &work).unwrap());
            args.expected_assessment_sha256 = Some("f".repeat(64));
            assert_eq!(
                work_state_preflight(
                    paths,
                    &args,
                    &candidate,
                    SigningTransition::Ready,
                    &old_bytes
                )
                .unwrap_err()
                .to_string(),
                "UNINSTALL_WORK_ASSESSMENT_CHANGED"
            );
            // Proof resources and audit history are independently tamper evident.
            let proof = root.join(format!("inactive-failed-reconcile-{attempt}.json"));
            let proof_bytes = regular_bytes(&proof).unwrap();
            state::atomic_write(&proof, b"{}").unwrap();
            assert!(generations::prove_inactive(paths, &work).is_err());
            state::atomic_write(&proof, &proof_bytes).unwrap();
            let old_result = paths
                .state_dir
                .join(format!("uninstall-work-result-{attempt}.json"));
            let result_bytes = regular_bytes(&old_result).unwrap();
            state::atomic_write(&old_result, b"{}").unwrap();
            assert!(generations::prove_inactive(paths, &work).is_err());
            state::atomic_write(&old_result, &result_bytes).unwrap();
            drop(guard);
            let journal = json!({"operationId":id,"recovery":{"oldJournalSha256":state::digest(&old_bytes),"files":manifest["payload"]["files"]}});
            cleanup_resources(paths, &journal).unwrap();
            cleanup_resources(paths, &journal).unwrap();
            assert!(!paths.state_dir.join("uninstall-work.json").exists());
            for generation in generations::records(&work).unwrap() {
                assert!(
                    !paths
                        .state_dir
                        .join(generation["stageName"].as_str().unwrap())
                        .exists()
                );
            }
            assert!(proof.exists());
            assert_eq!(regular_bytes(&proof).unwrap(), proof_bytes);
        }
    }
    #[tokio::test]
    async fn failed_reconcile_proof_and_successor_publication_are_restartable() {
        const CHILD: &str = "LOOMEX_TEST_FAILED_PROOF_ROOT";
        if let Some(base) = std::env::var_os(CHILD) {
            let base = PathBuf::from(base);
            let paths = lifecycle::Paths {
                state_dir: base.join("state"),
                install_base: base.join("install"),
                launch_agents_dir: base.join("agents"),
            };
            let _lifecycle = lifecycle::LifecycleLock::acquire(&paths).unwrap();
            let _guard = singleton(&paths, false).unwrap();
            let mut work: Value = work_json(&paths.state_dir.join("uninstall-work.json")).unwrap();
            let old_bytes =
                regular_bytes(&paths.state_dir.join("bootstrap-uninstall.json")).unwrap();
            let mode = std::env::var("LOOMEX_TEST_FAILED_PROOF_MODE").unwrap();
            let error = match mode.as_str() {
                "settle" => {
                    generations::settle_failed_reconcile(&paths, &mut work, &old_bytes).unwrap_err()
                }
                "generation" => {
                    let candidate = base.join("release-1.2.12");
                    let manifest = read_manifest(&candidate).unwrap();
                    generations::upgrade(&paths, &mut work, &candidate, &manifest).unwrap();
                    save_work(&paths, &work).unwrap_err()
                }
                "context" => {
                    let context: Value =
                        work_json(&base.join("failed-successor-context.json")).unwrap();
                    reserve_attempt(&paths, &mut work, &context).unwrap_err()
                }
                "cleanup" => {
                    let journal: Value =
                        work_json(&base.join("failed-cleanup-journal.json")).unwrap();
                    cleanup_resources(&paths, &journal).unwrap_err()
                }
                _ => panic!("invalid fixture mode"),
            };
            assert!(
                error.to_string().contains("injected uninstall failure"),
                "{error:#}"
            );
            return;
        }
        for (point, mode) in [
            ("AFTER_WORK_FAILED_RECONCILE_PROOF", "settle"),
            ("AFTER_WORK_FAILED_RECONCILE_SETTLEMENT", "settle"),
            ("AFTER_WORK_GENERATION_ARCHIVES", "generation"),
            ("AFTER_WORK_CONTEXT_RESERVATION", "context"),
            ("AFTER_WORK_CONTEXT_PUBLICATION", "context"),
            ("DURING_WORK_STAGE_DELETE", "cleanup"),
            ("DURING_WORK_RESOURCE_DELETE", "cleanup"),
        ] {
            let (fixture, mut work, candidate, manifest, old_bytes) =
                failed_owner_fixture(true, false).await;
            let paths = &fixture.paths;
            let base = paths.state_dir.parent().unwrap();
            let failed = work["attempt"]["id"].as_str().unwrap().to_owned();
            let failed_result = paths
                .state_dir
                .join(format!("uninstall-work-result-{failed}.json"));
            let result_bytes = regular_bytes(&failed_result).unwrap();
            let id = work["operationId"].clone();
            let run_child = || {
                let output=std::process::Command::new(std::env::current_exe().unwrap())
                    .arg("--exact").arg("bootstrap_uninstall::work::tests::failed_reconcile_proof_and_successor_publication_are_restartable")
                    .env(CHILD,base).env("LOOMEX_TEST_FAILED_PROOF_MODE",mode)
                    .env(format!("LOOMEX_TEST_UNINSTALL_FAIL_{point}"),"1").output().unwrap();
                assert!(
                    output.status.success(),
                    "{point}: {} {}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
            };
            if mode == "settle" {
                run_child();
                work = work_json(&paths.state_dir.join("uninstall-work.json")).unwrap();
            }
            if !work["attempt"].is_null() {
                let _lifecycle = lifecycle::LifecycleLock::acquire(paths).unwrap();
                let _guard = singleton(paths, false).unwrap();
                generations::settle_failed_reconcile(paths, &mut work, &old_bytes).unwrap();
            }
            generations::prove_inactive(paths, &work).unwrap();
            if mode == "generation" {
                run_child();
                work = work_json(&paths.state_dir.join("uninstall-work.json")).unwrap();
                assert_eq!(work["currentGeneration"], 1);
            }
            generations::upgrade(paths, &mut work, &candidate, &manifest).unwrap();
            save_work(paths, &work).unwrap();
            let stage = generations::stage(paths, &work).unwrap();
            publish_stage(paths, &candidate, &manifest, &stage)
                .await
                .unwrap();
            if mode == "context" {
                let fresh = Uuid::new_v4();
                let context = json!({"schema":"app.loomex.runner.uninstall-work-context/v2","operationId":id,"attemptId":fresh,"maintenanceGeneration":2,"releaseManifestSha256":work["releaseManifestSha256"],"stateDir":paths.state_dir,"installBase":paths.install_base,"launchAgentsDir":paths.launch_agents_dir,"journalSha256":work["journalSha256"],"receiptSha256":state::json_digest(&fixture.journal["receipt"]),"binarySha256":digest_file(&stage.join("bin/loomex-runner")).unwrap(),"action":"reconcile","retirementScope":"continuations","expectedAssessmentSha256":null,"expectedIdentity":prior_identity(paths).unwrap(),"singletonFd":9});
                state::write_json(&base.join("failed-successor-context.json"), &context).unwrap();
                run_child();
                work = work_json(&paths.state_dir.join("uninstall-work.json")).unwrap();
                assert_eq!(work["attempt"]["id"], fresh.to_string());
                publish_reserved_context(paths, &mut work).unwrap();
                assert_eq!(work["attempt"]["state"], "spawn_pending");
                assert!(work["attempt"]["pid"].is_null());
                assert!(
                    generations::candidate_transition(paths, &work, &"f".repeat(64), None).is_err(),
                    "unrecorded successor child cannot be replaced"
                );
                let result = json!({"schema":"app.loomex.runner.uninstall-work-result/v2","operationId":id,"attemptId":fresh,"ok":true,"maintenanceGeneration":2,"releaseManifestSha256":work["releaseManifestSha256"],"contextSha256":work["attempt"]["contextSha256"],"result":{"receipts":[]}});
                state::write_json(
                    &paths
                        .state_dir
                        .join(format!("uninstall-work-result-{fresh}.json")),
                    &result,
                )
                .unwrap();
                state::write_json(
                    &paths
                        .state_dir
                        .join(format!("uninstall-work-requests-{fresh}.json")),
                    &json!({"operationId":id,"attemptId":fresh,"requests":[]}),
                )
                .unwrap();
                assert!(consume_cached_result(paths, &mut work, &old_bytes, &result).unwrap());
            } else {
                fixture_attempt(paths, &mut work, &fixture.journal, &old_bytes, true);
            }
            assert_eq!(work["operationId"], id);
            assert_eq!(work["currentGeneration"], 2);
            assert_eq!(regular_bytes(&failed_result).unwrap(), result_bytes);
            let journal = json!({"operationId":id,"recovery":{"oldJournalSha256":state::digest(&old_bytes),"files":manifest["payload"]["files"]}});
            state::write_json(&base.join("failed-cleanup-journal.json"), &journal).unwrap();
            if mode == "cleanup" {
                run_child();
            }
            cleanup_resources(paths, &journal).unwrap();
            cleanup_resources(paths, &journal).unwrap();
            assert!(!paths.state_dir.join("uninstall-work.json").exists());
            assert_eq!(
                regular_bytes(&paths.state_dir.join("bootstrap-uninstall.json")).unwrap(),
                old_bytes
            );
            assert!(
                paths
                    .state_dir
                    .join("recovery-evidence")
                    .join(id.as_str().unwrap())
                    .join(format!("inactive-failed-reconcile-{failed}.json"))
                    .exists()
            );
        }
    }

    #[tokio::test]
    async fn failed_reconcile_successor_preflight_accepts_fresh_scope_and_owner_journey() {
        let (fixture, mut work, candidate, manifest, old_bytes) =
            failed_owner_fixture(false, true).await;
        let paths = &fixture.paths;
        let mut args = Arguments {
            work_action: Some("reconcile".into()),
            retirement_scope: Some("operation-observations".into()),
            release: Some(candidate.clone()),
            ..Arguments::default()
        };
        state::private_dir(&paths.state_dir.join("operations")).unwrap();
        state::write_json(
            &paths
                .state_dir
                .join("operations")
                .join(format!("{}.json", "f".repeat(64))),
            &json!({"digest":"a".repeat(64),"method":"interactions.decide","status":"pending"}),
        )
        .unwrap();
        let report = public_report(
            paths,
            &args,
            "inspected",
            "UNINSTALL_WORK_INSPECTED",
            "reconcile_managed_work",
            None,
        );
        assert_eq!(
            report["preview"]["records"][0]["availableActions"],
            json!(["reconcile"])
        );
        assert_eq!(
            report["maintenanceReference"]["transition"],
            "eligible_successor"
        );
        let incompatible = public_report(
            paths,
            &args,
            "blocked",
            "UNINSTALL_WORK_GENERATION_CAPABILITY_REQUIRED",
            "select_compatible_release",
            None,
        );
        assert_eq!(
            incompatible["preview"]["records"][0]["availableActions"],
            json!([]),
            "incompatible candidate cannot advertise executable work"
        );
        let before = state_bytes(&paths.state_dir);
        let preflight = work_state_preflight(
            paths,
            &args,
            &candidate,
            SigningTransition::Ready,
            &old_bytes,
        )
        .unwrap();
        assert_eq!(preflight["eligible"], true);
        assert_eq!(preflight["successorAfterOriginalResult"], true);
        assert_eq!(preflight["retirementScope"], "operation-observations");
        assert_eq!(before, state_bytes(&paths.state_dir));
        let old_release = PathBuf::from(work["releasePath"].as_str().unwrap());
        assert_eq!(
            work_state_preflight(
                paths,
                &args,
                &old_release,
                SigningTransition::Ready,
                &old_bytes
            )
            .unwrap_err()
            .to_string(),
            "UNINSTALL_WORK_MAINTENANCE_PENDING",
            "same-release active scope remains exact"
        );
        let result_path = paths.state_dir.join(format!(
            "uninstall-work-result-{}.json",
            work["attempt"]["id"].as_str().unwrap()
        ));
        let result_bytes = regular_bytes(&result_path).unwrap();
        remove_regular(&result_path).unwrap();
        assert_eq!(
            work_state_preflight(
                paths,
                &args,
                &candidate,
                SigningTransition::Ready,
                &old_bytes
            )
            .unwrap_err()
            .to_string(),
            "UNINSTALL_WORK_MAINTENANCE_PENDING",
            "unknown original outcome cannot change scope"
        );
        state::atomic_write(&result_path, &result_bytes).unwrap();
        args.expected_assessment_sha256 = Some("a".repeat(64));
        assert_eq!(
            work_state_preflight(
                paths,
                &args,
                &candidate,
                SigningTransition::Ready,
                &old_bytes
            )
            .unwrap_err()
            .to_string(),
            "UNINSTALL_WORK_ASSESSMENT_CHANGED",
            "failed reconcile cannot borrow an assessment"
        );
        args.expected_assessment_sha256 = None;
        args.work_action = Some("retire-local".into());
        assert_eq!(
            work_state_preflight(
                paths,
                &args,
                &candidate,
                SigningTransition::Ready,
                &old_bytes
            )
            .unwrap_err()
            .to_string(),
            "UNINSTALL_WORK_RECONCILIATION_REQUIRED"
        );
        args.work_action = Some("reconcile".into());
        let _lifecycle = lifecycle::LifecycleLock::acquire(paths).unwrap();
        let _guard = singleton(paths, false).unwrap();
        let old_attempt = work["attempt"]["id"].clone();
        generations::settle_failed_reconcile(paths, &mut work, &old_bytes).unwrap();
        generations::upgrade(paths, &mut work, &candidate, &manifest).unwrap();
        save_work(paths, &work).unwrap();
        let stage = generations::stage(paths, &work).unwrap();
        publish_stage(paths, &candidate, &manifest, &stage)
            .await
            .unwrap();
        let fresh = Uuid::new_v4();
        let context = json!({"schema":"app.loomex.runner.uninstall-work-context/v2","operationId":work["operationId"],"attemptId":fresh,"maintenanceGeneration":2,"releaseManifestSha256":work["releaseManifestSha256"],"stateDir":paths.state_dir,"installBase":paths.install_base,"launchAgentsDir":paths.launch_agents_dir,"journalSha256":work["journalSha256"],"receiptSha256":state::json_digest(&fixture.journal["receipt"]),"binarySha256":digest_file(&stage.join("bin/loomex-runner")).unwrap(),"action":"reconcile","retirementScope":"operation-observations","expectedAssessmentSha256":null,"expectedIdentity":prior_identity(paths).unwrap(),"singletonFd":9});
        let path = reserve_attempt(paths, &mut work, &context).unwrap();
        let saved: Value = work_json(&path).unwrap();
        assert_eq!(saved, context);
        assert_ne!(work["attempt"]["id"], old_attempt);
        assert_eq!(work["attempt"]["retirementScope"], "operation-observations");
        require_attempt_arguments(&work, &args).unwrap();
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn failed_reconcile_native_qualification_requires_prospective_and_existing_v14_capability()
     {
        let (fixture, mut work, _, _, old_bytes) =
            failed_owner_fixture_with_install(true, false, true).await;
        let paths = &fixture.paths;
        let base = paths.state_dir.parent().unwrap();
        let executable = std::env::current_exe().unwrap();
        let make_candidate = |label: &str, supports: bool| {
            let release = base.join(format!("qualified-{label}"));
            let payload = base.join(format!("qualified-{label}-payload"));
            state::private_dir(&release).unwrap();
            state::private_dir(&payload).unwrap();
            state::private_dir(&payload.join("bin")).unwrap();
            state::private_dir(&payload.join("metadata")).unwrap();
            for name in ["loomex", "loomex-runner", "loomex-lifecycle-bootstrap"] {
                fs::hard_link(&executable, payload.join("bin").join(name)).unwrap();
            }
            state::write_json(&payload.join("metadata/project.json"),&json!({"project":"loomex-runner","version":env!("CARGO_PKG_VERSION"),"platform":"darwin-arm64"})).unwrap();
            let capabilities = if supports {
                json!([
                    "uninstall-work.generations/v1",
                    "uninstall-work.inactive-failed-reconcile/v1"
                ])
            } else {
                json!(["uninstall-work.generations/v1"])
            };
            state::write_json(
                &payload.join("metadata/compatibility-manifest.json"),
                &json!({"capabilities":capabilities}),
            )
            .unwrap();
            let source =
                json!({"schema":"app.loomex.source-content/v1","sourceRevision":"a".repeat(40)});
            let mut source_bytes = serde_json::to_vec(&source).unwrap();
            source_bytes.push(b'\n');
            fs::write(
                payload.join("metadata/source-content-manifest.json"),
                source_bytes,
            )
            .unwrap();
            let mut files=["bin/loomex","bin/loomex-runner","bin/loomex-lifecycle-bootstrap","metadata/project.json","metadata/compatibility-manifest.json","metadata/source-content-manifest.json"].into_iter().map(|name| {let path=payload.join(name);let metadata=fs::metadata(&path).unwrap();json!({"path":name,"sha256":digest_file(&path).unwrap(),"size":metadata.len(),"mode":metadata.mode()&0o777})}).collect::<Vec<_>>();
            files.sort_by(|a, b| a["path"].as_str().cmp(&b["path"].as_str()));
            fs::hard_link(&executable, release.join("loomex-lifecycle-bootstrap")).unwrap();
            let manifest = json!({"schema":"app.loomex.release/v1","project":"loomex-runner","version":env!("CARGO_PKG_VERSION"),"platform":"darwin-arm64","developmentOnly":true,"sourceRevision":"a".repeat(40),"sourceContent":{"file":"metadata/source-content-manifest.json","sha256":digest_file(&payload.join("metadata/source-content-manifest.json")).unwrap()},"payload":{"files":files},"bootstrap":{"file":"loomex-lifecycle-bootstrap","sha256":digest_file(&executable).unwrap(),"size":fs::metadata(&executable).unwrap().len()}});
            state::write_json(&release.join("manifest.json"), &manifest).unwrap();
            inventory(&payload, manifest["payload"]["files"].as_array().unwrap()).unwrap();
            validate_source_binding(&payload, &manifest).unwrap();
            bootstrap_preflight::verify_envelope(&release, &payload, &manifest).unwrap();
            (release, payload, manifest)
        };
        let (missing, missing_payload, missing_manifest) = make_candidate("missing", false);
        let (supported, supported_payload, supported_manifest) = make_candidate("supported", true);
        let mut args = Arguments {
            work_action: Some("inspect".into()),
            retirement_scope: Some("operation-observations".into()),
            expected_old_journal_sha256: Some(state::digest(&old_bytes)),
            development_api_origin: Some("http://127.0.0.1:9".into()),
            ..Arguments::default()
        };
        let before = state_bytes(&paths.state_dir);
        assert_eq!(
            work_preflight(paths, &args, &missing, &missing_manifest, &missing_payload)
                .await
                .unwrap_err()
                .to_string(),
            "UNINSTALL_WORK_GENERATION_CAPABILITY_REQUIRED"
        );
        assert_eq!(
            before,
            state_bytes(&paths.state_dir),
            "inspect missing prospective capability never creates v14 fence/proof"
        );
        args.work_action = Some("reconcile".into());
        assert_eq!(
            qualify_before_settlement(
                paths,
                &args,
                &fixture.journal,
                &old_bytes,
                &missing,
                &missing_manifest,
                &missing_payload
            )
            .await
            .unwrap_err()
            .to_string(),
            "UNINSTALL_WORK_GENERATION_CAPABILITY_REQUIRED"
        );
        assert_eq!(
            before,
            state_bytes(&paths.state_dir),
            "execute refuses before settlement or native service observation"
        );
        let preflight = work_preflight(
            paths,
            &args,
            &supported,
            &supported_manifest,
            &supported_payload,
        )
        .await
        .unwrap();
        assert_eq!(preflight["successorAfterOriginalResult"], true);
        assert_eq!(preflight["retirementScope"], "operation-observations");
        assert_eq!(before, state_bytes(&paths.state_dir));
        args.expected_assessment_sha256 = Some("a".repeat(64));
        assert_eq!(
            qualify_before_settlement(
                paths,
                &args,
                &fixture.journal,
                &old_bytes,
                &supported,
                &supported_manifest,
                &supported_payload
            )
            .await
            .unwrap_err()
            .to_string(),
            "UNINSTALL_WORK_ASSESSMENT_CHANGED"
        );
        assert_eq!(
            before,
            state_bytes(&paths.state_dir),
            "execute cannot consume failed owner using borrowed assessment"
        );
        args.expected_assessment_sha256 = None;
        let _lifecycle = lifecycle::LifecycleLock::acquire(paths).unwrap();
        let _guard = singleton(paths, false).unwrap();
        generations::settle_failed_reconcile(paths, &mut work, &old_bytes).unwrap();
        let fenced = state_bytes(&paths.state_dir);
        args.work_action = Some("inspect".into());
        assert_eq!(
            qualify_work_candidate(
                paths,
                &args,
                &fixture.journal,
                &missing,
                &missing_manifest,
                &missing_payload
            )
            .await
            .unwrap_err()
            .to_string(),
            "UNINSTALL_WORK_GENERATION_CAPABILITY_REQUIRED"
        );
        assert_eq!(
            fenced,
            state_bytes(&paths.state_dir),
            "direct maintenance also checks existing v14"
        );
        qualify_work_candidate(
            paths,
            &args,
            &fixture.journal,
            &supported,
            &supported_manifest,
            &supported_payload,
        )
        .await
        .unwrap();
        assert_eq!(fenced, state_bytes(&paths.state_dir));
    }

    #[tokio::test]
    async fn work_preview_preserves_canonical_methods_and_executable_actions() {
        let (fixture, work, candidate, _, _) = failed_owner_fixture(true, false).await;
        let paths = &fixture.paths;
        state::private_dir(&paths.state_dir.join("operations")).unwrap();
        let catalog: Value =
            serde_json::from_str(include_str!("../../contracts/method-catalog.json")).unwrap();
        for method in ["interactions.decide", "persona.roles.create"] {
            assert!(
                catalog["methods"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|entry| entry["name"] == method)
            );
            state::write_json(
                &paths
                    .state_dir
                    .join("operations")
                    .join(format!("{}.json", state::digest(method.as_bytes()))),
                &json!({"digest":"a".repeat(64),"method":method,"status":"pending"}),
            )
            .unwrap();
        }
        let args = Arguments {
            work_action: Some("inspect".into()),
            release: Some(candidate),
            ..Arguments::default()
        };
        let report = public_report(
            paths,
            &args,
            "inspected",
            "UNINSTALL_WORK_INSPECTED",
            "reconcile_managed_work",
            None,
        );
        let records = report["preview"]["records"].as_array().unwrap();
        assert_eq!(records.len(), 2);
        for method in ["interactions.decide", "persona.roles.create"] {
            let record = records
                .iter()
                .find(|record| record["method"] == method)
                .unwrap();
            assert_eq!(
                record["availableActions"],
                json!(["reconcile"]),
                "active reconcile only permits exact resumption or supported reconcile successor"
            );
        }
        assert_eq!(work["attempt"]["action"], "reconcile");
        for code in ["AUTH_REQUIRED", "AUTH_EXPIRED"] {
            let error=require_result(&json!({"ok":false,"failureCode":"UNINSTALL_WORK_NATIVE_FAILED","error":{"code":code,"message":"PRIVATE MESSAGE","outcome":"unknown","recovery":"reconcile_outcome","retryable":false}})).unwrap_err();
            let failure = error.downcast_ref::<WorkNativeFailure>().unwrap();
            assert_eq!(failure.diagnostic["code"], code);
            assert_eq!(failure.diagnostic["outcome"], "unknown");
            assert_eq!(failure.diagnostic["recovery"], "reconcile_outcome");
            assert!(!failure.diagnostic.to_string().contains("PRIVATE MESSAGE"));
        }
    }

    #[tokio::test]
    async fn cached_migration_failure_is_consumed_before_any_attempt_can_resume() {
        let fixture = super::super::tests::historical_fixture();
        let paths = &fixture.paths;
        let base = paths.state_dir.parent().unwrap();
        let (release, manifest) = release_fixture(base, "1.2.9");
        let (candidate, _) = release_fixture(base, "1.2.11");
        let id = Uuid::new_v4();
        let bytes = regular_bytes(&paths.state_dir.join("bootstrap-uninstall.json")).unwrap();
        let stage = paths.state_dir.join(format!("uninstall-work-stage-{id}"));
        publish_stage(paths, &release, &manifest, &stage)
            .await
            .unwrap();
        let mut work = json!({"schema":WORK_SCHEMA,"operationId":id,"journalSha256":state::digest(&bytes),"releasePath":release,"releaseManifestSha256":digest_file(&release.join("manifest.json")).unwrap(),"phase":"qualified","attempt":null});
        save_work(paths, &work).unwrap();
        let attempt = fixture_attempt(paths, &mut work, &fixture.journal, &bytes, false);
        work["attempt"] = work["lastAttempt"].take();
        work["lastAttempt"] = Value::Null;
        save_work(paths, &work).unwrap();
        let candidate_digest = digest_file(&candidate.join("manifest.json")).unwrap();
        let before = state_bytes(&paths.state_dir);
        assert_eq!(
            generations::candidate_transition(paths, &work, &candidate_digest, Some(&candidate))
                .unwrap(),
            "resume_original_attempt"
        );
        assert_eq!(state_bytes(&paths.state_dir), before);
        let result_path = paths
            .state_dir
            .join(format!("uninstall-work-result-{attempt}.json"));
        let result_bytes = regular_bytes(&result_path).unwrap();
        remove_regular(&result_path).unwrap();
        assert_eq!(
            generations::candidate_transition(paths, &work, &candidate_digest, Some(&candidate))
                .unwrap_err()
                .to_string(),
            "UNINSTALL_WORK_MAINTENANCE_PENDING"
        );
        state::atomic_write(&result_path, &result_bytes).unwrap();
        let failed = json!({"operationId":id,"attemptId":attempt,"ok":false,"failureCode":"MANAGED_WORK_MIGRATION_CHANGED","error":{"code":"MANAGED_WORK_MIGRATION_CHANGED"}});
        state::write_json(&result_path, &failed).unwrap();
        assert!(consume_cached_result(paths, &mut work, &bytes, &failed).is_err());
        assert!(work["attempt"].is_null());
        assert_eq!(work["lastAttempt"]["id"], attempt.to_string());
        assert_eq!(work["phase"], "review_required");
        generations::prove_inactive(paths, &work).unwrap();
        assert_eq!(
            generations::candidate_transition(paths, &work, &candidate_digest, Some(&candidate))
                .unwrap(),
            "eligible_successor"
        );
    }
    #[tokio::test]
    async fn never_dispatched_owner_and_interrupted_stage_are_recoverable_without_overwriting_corruption()
     {
        let fixture = super::super::tests::historical_fixture();
        let paths = &fixture.paths;
        let base = paths.state_dir.parent().unwrap();
        let (old_release, _) = release_fixture(base, "1.2.9");
        let (new_release, manifest) = release_fixture(base, "1.2.11");
        let id = Uuid::new_v4();
        let mut work = json!({"schema":WORK_SCHEMA,"operationId":id,"journalSha256":digest_file(&paths.state_dir.join("bootstrap-uninstall.json")).unwrap(),"releasePath":old_release,"releaseManifestSha256":digest_file(&old_release.join("manifest.json")).unwrap(),"phase":"qualified","attempt":null});
        save_work(paths, &work).unwrap();
        assert!(!paths.state_dir.join("recovery-evidence").exists());
        let alternate = base.join("same-manifest-another-cache");
        state::private_dir(&alternate).unwrap();
        for file in ["manifest.json", "payload.tar.gz"] {
            fs::copy(old_release.join(file), alternate.join(file)).unwrap();
        }
        let same_hash = digest_file(&alternate.join("manifest.json")).unwrap();
        let before = state_bytes(&paths.state_dir);
        let reference = work_maintenance_reference(paths, Some(&same_hash), Some(&alternate));
        assert_eq!(reference["transition"], "eligible_successor");
        assert_eq!(
            reference["releaseManifestSha256"],
            reference["candidateManifestSha256"]
        );
        assert_ne!(
            reference["releasePathSha256"],
            reference["candidateReleasePathSha256"]
        );
        assert_eq!(state_bytes(&paths.state_dir), before);
        let mut pinned = work.clone();
        pinned["attempt"] =
            json!({"id":Uuid::new_v4(),"action":"reconcile","contextSha256":"e".repeat(64)});
        assert_eq!(
            generations::candidate_transition(paths, &pinned, &same_hash, Some(&alternate))
                .unwrap_err()
                .to_string(),
            "UNINSTALL_WORK_MAINTENANCE_PENDING"
        );
        let mut same_work = work.clone();
        generations::upgrade(
            paths,
            &mut same_work,
            &alternate,
            &read_manifest(&alternate).unwrap(),
        )
        .unwrap();
        assert_eq!(same_work["currentGeneration"], 1);
        assert_eq!(
            same_work["releaseManifestSha256"],
            work["releaseManifestSha256"]
        );
        assert_ne!(same_work["releasePath"], work["releasePath"]);
        // Restore the original generation transition input after its pure candidate construction.
        work["legacyOwnerSha256"] = same_work["legacyOwnerSha256"].clone();
        generations::upgrade(paths, &mut work, &new_release, &manifest).unwrap();
        save_work(paths, &work).unwrap();
        let stage = generations::stage(paths, &work).unwrap();
        state::private_dir(&stage).unwrap();
        state::private_dir(&stage.join("bin")).unwrap();
        fs::write(stage.join("bin/loomex-runner"), b"1.2.11").unwrap();
        publish_stage(paths, &new_release, &manifest, &stage)
            .await
            .unwrap();
        inventory(&stage, manifest["payload"]["files"].as_array().unwrap()).unwrap();
        let alias = paths
            .state_dir
            .join(format!("uninstall-work-stage-{id}-generation-2"));
        std::os::unix::fs::symlink(&stage, &alias).unwrap();
        let stage_before = state_bytes(&stage);
        assert!(
            publish_stage(paths, &new_release, &manifest, &alias)
                .await
                .is_err()
        );
        assert!(
            fs::symlink_metadata(&alias)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(state_bytes(&stage), stage_before);
        fs::remove_file(&alias).unwrap();
        fs::write(stage.join("bin/loomex-runner"), b"corruption").unwrap();
        let before = fs::read(stage.join("bin/loomex-runner")).unwrap();
        assert!(
            publish_stage(paths, &new_release, &manifest, &stage)
                .await
                .is_err()
        );
        assert_eq!(fs::read(stage.join("bin/loomex-runner")).unwrap(), before);
        let mut active = work.clone();
        active["attempt"] = json!({"id":Uuid::new_v4(),"action":"retire-local","expectedAssessmentSha256":"a".repeat(64)});
        assert!(generations::candidate_transition(paths, &active, &"f".repeat(64), None).is_err());
        let mut contradictory = work;
        contradictory["phase"] = json!("settled");
        assert!(
            generations::candidate_transition(
                paths,
                &contradictory,
                contradictory["releaseManifestSha256"].as_str().unwrap(),
                None
            )
            .is_err()
        );
    }
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
    fn terminal_uninstall_retains_old_reader_fence_and_exact_history_after_cleanup() {
        let root = tempfile::tempdir().unwrap();
        let paths = lifecycle::Paths {
            state_dir: root.path().join("state"),
            install_base: root.path().join("install"),
            launch_agents_dir: root.path().join("agents"),
        };
        state::private_dir(&paths.state_dir).unwrap();
        let id = Uuid::new_v4();
        lifecycle::begin_uninstall_work_locked(&paths, id, &"a".repeat(64)).unwrap();
        let owner_path = paths.state_dir.join("lifecycle-operation.json");
        let owner_before = regular_bytes(&owner_path).unwrap();
        let original = serde_json::to_string(
            &json!({"digest":"b".repeat(64),"method":"interactions.respond","status":"pending"}),
        )
        .unwrap();
        let slot = "c".repeat(64);
        let provenance = json!({"operationId":id,"attemptId":Uuid::new_v4(),"journalSha256":"a".repeat(64),"receiptSha256":"b".repeat(64),"expectedAssessmentSha256":"c".repeat(64),"requestSetSha256":"d".repeat(64),"contextSha256":"e".repeat(64),"installationId":"fixture-install","retirementScope":"operation-observations","canonicalObservation":{"remoteOutcome":"unknown","safeReason":"missing_binding"}});
        let evidence = json!({"schema":"loomex.operation-cache-retirement/v1","legacySlot":slot,"originalCache":original,"originalCacheSha256":state::digest(original.as_bytes()),"provenance":provenance,"remoteOutcome":"unknown","denyOnly":true,"retiredAt":state::now()});
        let evidence_root = paths.state_dir.join("recovery-evidence");
        state::private_dir(&evidence_root).unwrap();
        state::write_json(
            &evidence_root.join(format!(
                "operation-cache-{}.json",
                state::digest(slot.as_bytes())
            )),
            &evidence,
        )
        .unwrap();
        let terminal = json!({"schema":SCHEMA,"operationId":id,"phase":"terminal","fenceJournalSha256":"a".repeat(64),"cleanup":{"stateDeleted":true}});
        let journal_path = paths.state_dir.join("bootstrap-uninstall.json");
        let terminal_bytes = serde_json::to_vec_pretty(&terminal).unwrap();
        state::atomic_write(&journal_path, &terminal_bytes).unwrap();
        remove_terminal_fence(&paths, &terminal).unwrap();
        let archive = evidence_root.join(id.to_string());
        assert_eq!(
            regular_bytes(&archive.join("terminal-lifecycle-owner.json")).unwrap(),
            owner_before
        );
        assert_eq!(
            regular_bytes(&archive.join("terminal-bootstrap-uninstall.json")).unwrap(),
            terminal_bytes
        );
        let raw: Value = work_json(&owner_path).unwrap();
        assert_eq!(raw["schema"], "app.loomex.runner.lifecycle-operation/v12");
        assert_eq!(raw["logicalSchema"], lifecycle::OPERATION_SCHEMA);
        remove_regular(&journal_path).unwrap();
        remove_terminal_fence(&paths, &terminal).unwrap();
        let retained: lifecycle::Operation = work_json(&owner_path).unwrap();
        assert!(lifecycle::retained_retirement_terminal(&retained, id).unwrap());
        let package = lifecycle::PackageIdentity {
            version: "1.2.10".into(),
            target: paths.install_base.join("versions/1.2.10"),
            manifest_sha256: "f".repeat(64),
        };
        assert_eq!(
            lifecycle::package_preflight(&paths, lifecycle::OperationKind::Install, &package)
                .unwrap()["ready"],
            true
        );
    }

    #[test]
    fn immutable_context_publication_keeps_partial_temporary_out_of_the_approved_path() {
        let root = tempfile::tempdir().unwrap();
        state::private_dir(root.path()).unwrap();
        let path = root.path().join("uninstall-work-context-fixture.json");
        state::atomic_write(
            &root
                .path()
                .join(".uninstall-immutable-publication-interrupted"),
            b"{",
        )
        .unwrap();
        let bytes = b"{\"schema\":\"complete-context\"}";
        immutable_copy(&path, bytes).unwrap();
        immutable_copy(&path, bytes).unwrap();
        assert!(immutable_copy(&path, b"replacement").is_err());
        assert_eq!(regular_bytes(&path).unwrap(), bytes);
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
