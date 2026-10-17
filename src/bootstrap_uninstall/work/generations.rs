//! Release generations preserve historical maintenance authority and inventories.
use super::*;

const OWNER_V1: &str = "app.loomex.runner.uninstall-work/v1";
pub(super) const OWNER_V2: &str = "app.loomex.runner.uninstall-work/v2";

pub(super) fn supported(work: &Value) -> bool {
    matches!(work["schema"].as_str(), Some(OWNER_V1 | OWNER_V2))
}
fn valid_owner(work: &Value) -> Result<()> {
    require(
        supported(work)
            && work["operationId"]
                .as_str()
                .is_some_and(|id| Uuid::parse_str(id).is_ok())
            && work["journalSha256"]
                .as_str()
                .is_some_and(valid_work_digest)
            && work["releaseManifestSha256"]
                .as_str()
                .is_some_and(valid_work_digest)
            && work["releasePath"].as_str().is_some(),
        "UNINSTALL_WORK_BINDING_CHANGED",
    )?;
    require(
        matches!(
            work["phase"].as_str(),
            Some("qualified" | "settled" | "review_required")
        ),
        "UNINSTALL_WORK_BINDING_CHANGED",
    )?;
    if !work["attempt"].is_null() {
        require(
            work["attempt"]["id"]
                .as_str()
                .is_some_and(|id| Uuid::parse_str(id).is_ok())
                && work["attempt"]["contextSha256"]
                    .as_str()
                    .is_some_and(valid_work_digest)
                && matches!(
                    work["attempt"]["action"].as_str(),
                    Some("reconcile" | "retire-local")
                )
                && matches!(
                    saved_scope(&work["attempt"]),
                    "continuations" | "operation-observations"
                )
                && (work["attempt"]["action"] != "retire-local"
                    || work["attempt"]["expectedAssessmentSha256"]
                        .as_str()
                        .is_some_and(valid_work_digest)),
            "UNINSTALL_WORK_BINDING_CHANGED",
        )?;
    }
    Ok(())
}

pub(super) fn records(work: &Value) -> Result<Vec<Value>> {
    valid_owner(work)?;
    if work["schema"] == OWNER_V1 {
        let release = PathBuf::from(work["releasePath"].as_str().unwrap());
        require(
            digest_file(&release.join("manifest.json"))? == work["releaseManifestSha256"],
            "UNINSTALL_WORK_BINDING_CHANGED",
        )?;
        let manifest = read_manifest(&release)?;
        require(
            manifest["payload"]["files"].is_array(),
            "UNINSTALL_WORK_BINDING_CHANGED",
        )?;
        return Ok(vec![
            json!({"generation":0,"releasePath":work["releasePath"],"releaseManifestSha256":work["releaseManifestSha256"],"files":manifest["payload"]["files"],"stageName":format!("uninstall-work-stage-{}",work["operationId"].as_str().unwrap())}),
        ]);
    }
    let generations = work["generations"]
        .as_array()
        .context("invalid work generations")?;
    require(
        !generations.is_empty()
            && generations.len() <= 64
            && work["currentGeneration"].as_u64() == Some((generations.len() - 1) as u64),
        "UNINSTALL_WORK_BINDING_CHANGED",
    )?;
    for (index, generation) in generations.iter().enumerate() {
        let legacy_name = format!(
            "uninstall-work-stage-{}",
            work["operationId"].as_str().unwrap()
        );
        let name = format!(
            "uninstall-work-stage-{}-generation-{index}",
            work["operationId"].as_str().unwrap()
        );
        require(
            generation["generation"].as_u64() == Some(index as u64)
                && generation["releasePath"].as_str().is_some()
                && generation["releaseManifestSha256"]
                    .as_str()
                    .is_some_and(valid_work_digest)
                && generation["files"].is_array()
                && (generation["stageName"] == name
                    || (index == 0 && generation["stageName"] == legacy_name)),
            "UNINSTALL_WORK_BINDING_CHANGED",
        )?;
    }
    let current = generations.last().unwrap();
    require(
        current["releasePath"] == work["releasePath"]
            && current["releaseManifestSha256"] == work["releaseManifestSha256"],
        "UNINSTALL_WORK_BINDING_CHANGED",
    )?;
    Ok(generations.clone())
}

pub(super) fn verify_archives(paths: &lifecycle::Paths, work: &Value) -> Result<()> {
    if work["schema"] != OWNER_V2 {
        return Ok(());
    }
    let root = paths
        .state_dir
        .join("recovery-evidence")
        .join(work["operationId"].as_str().context("invalid work owner")?);
    for generation in records(work)? {
        require(
            regular_bytes(&root.join(format!(
                "generation-{}.json",
                generation["generation"].as_u64().unwrap()
            )))? == serde_json::to_vec(&generation)?,
            "UNINSTALL_WORK_BINDING_CHANGED",
        )?;
    }
    if let Some(hash) = work["legacyOwnerSha256"].as_str() {
        require(
            valid_work_digest(hash)
                && state::digest(&regular_bytes(&root.join("original-work-owner-v1.json"))?)
                    == hash,
            "UNINSTALL_WORK_BINDING_CHANGED",
        )?;
    }
    Ok(())
}

pub(super) fn attempt_release(
    paths: &lifecycle::Paths,
    work: &Value,
    attempt: &str,
) -> Result<Value> {
    verify_archives(paths, work)?;
    let context: Value = work_json(
        &paths
            .state_dir
            .join(format!("uninstall-work-context-{attempt}.json")),
    )?;
    let generations = records(work)?;
    let index = if context["schema"] == "app.loomex.runner.uninstall-work-context/v1" {
        0
    } else {
        require(
            context["schema"] == "app.loomex.runner.uninstall-work-context/v2",
            "UNINSTALL_WORK_BINDING_CHANGED",
        )?;
        context["maintenanceGeneration"]
            .as_u64()
            .context("invalid work generation")? as usize
    };
    let generation = generations.get(index).context("invalid work generation")?;
    require(
        context["operationId"] == work["operationId"]
            && context["attemptId"] == attempt
            && context["journalSha256"] == work["journalSha256"]
            && (index == 0 && context["schema"] == "app.loomex.runner.uninstall-work-context/v1"
                || context["releaseManifestSha256"] == generation["releaseManifestSha256"]),
        "UNINSTALL_WORK_BINDING_CHANGED",
    )?;
    Ok(generation.clone())
}

/// A null attempt is insufficient: validate its complete immutable evidence.
pub(super) fn prove_inactive(paths: &lifecycle::Paths, work: &Value) -> Result<()> {
    valid_owner(work)?;
    verify_archives(paths, work)?;
    generation_cleanup::verify_known_resources(paths, work)?;
    require(
        work["attempt"].is_null(),
        "UNINSTALL_WORK_MAINTENANCE_PENDING",
    )?;
    require(
        work["attemptIds"].is_null() || work["attemptIds"].is_array(),
        "UNINSTALL_WORK_BINDING_CHANGED",
    )?;
    for generation in records(work)? {
        for name in [
            generation["stageName"].as_str().unwrap().to_owned(),
            format!(".{}.publishing", generation["stageName"].as_str().unwrap()),
        ] {
            let stage = paths.state_dir.join(name);
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
    }
    let ids = work["attemptIds"].as_array().cloned().unwrap_or_default();
    if let Some(proofs) = work["failedReconcileProofs"].as_object() {
        require(
            proofs.len() <= 64
                && proofs.iter().all(|(attempt, hash)| {
                    ids.iter().any(|id| id == attempt)
                        && hash.as_str().is_some_and(valid_work_digest)
                }),
            "UNINSTALL_WORK_BINDING_CHANGED",
        )?;
    } else {
        require(
            work["failedReconcileProofs"].is_null(),
            "UNINSTALL_WORK_BINDING_CHANGED",
        )?;
    }

    require(ids.len() <= 64, "UNINSTALL_WORK_AUDIT_LIMIT")?;
    let mut seen = std::collections::HashSet::new();
    let id = work["operationId"].as_str().unwrap();
    let root = paths.state_dir.join("recovery-evidence").join(id);
    if work["phase"] == "qualified" && ids.is_empty() {
        require(
            ids.is_empty() && work["lastAttempt"].is_null(),
            "UNINSTALL_WORK_BINDING_CHANGED",
        )?;
        return Ok(());
    }
    require(
        matches!(
            work["phase"].as_str(),
            Some("settled" | "review_required" | "qualified")
        ) && !ids.is_empty()
            && ids.last() == work["lastAttempt"].get("id"),
        "UNINSTALL_WORK_BINDING_CHANGED",
    )?;
    require(
        state::digest(&regular_bytes(&root.join("original-uninstall.json"))?)
            == work["journalSha256"],
        "UNINSTALL_WORK_BINDING_CHANGED",
    )?;
    for attempt in &ids {
        let attempt = attempt.as_str().context("invalid work attempt")?;
        require(
            Uuid::parse_str(attempt).is_ok() && seen.insert(attempt),
            "UNINSTALL_WORK_BINDING_CHANGED",
        )?;
        let generation = attempt_release(paths, work, attempt)?;
        let context_path = paths
            .state_dir
            .join(format!("uninstall-work-context-{attempt}.json"));
        let context: Value = work_json(&context_path)?;
        if !work["failedReconcileProofs"][attempt].is_null() {
            verify_failed_proof(paths, work, attempt)?;
            if work["lastAttempt"]["id"] == attempt {
                require(
                    work["lastAttempt"]
                        == work_json::<Value>(
                            &root.join(format!("inactive-failed-reconcile-{attempt}.json")),
                        )?["attempt"]
                        && work["phase"] == "qualified",
                    "UNINSTALL_WORK_BINDING_CHANGED",
                )?;
            }
            continue;
        }
        let approval: Value = work_json(&root.join(format!("approval-{attempt}.json")))?;
        let result: Value = work_json(
            &paths
                .state_dir
                .join(format!("uninstall-work-result-{attempt}.json")),
        )?;
        let encoded = serde_json::to_vec(&audit_projection(&result))?;
        require(
            regular_bytes(&root.join(format!(
                "resolution-{attempt}-{}.json",
                state::digest(&encoded)
            )))? == encoded
                && approval["schema"] == "app.loomex.runner.uninstall-work-approval/v1"
                && approval["operationId"] == id
                && approval["attemptId"] == attempt
                && approval["contextSha256"] == digest_file(&context_path)?
                && approval["originalJournalSha256"] == work["journalSha256"]
                && approval["releaseManifestSha256"] == generation["releaseManifestSha256"]
                && approval["action"] == context["action"]
                && saved_scope(&approval) == saved_scope(&context)
                && approval["expectedAssessmentSha256"] == context["expectedAssessmentSha256"]
                && approval["receiptSha256"] == context["receiptSha256"]
                && approval["identityReference"]
                    == state::json_digest(&context["expectedIdentity"])
                && approval["requestSetSha256"]
                    == digest_file(
                        &paths
                            .state_dir
                            .join(format!("uninstall-work-requests-{attempt}.json")),
                    )?
                && result["operationId"] == id
                && result["attemptId"] == attempt,
            "UNINSTALL_WORK_BINDING_CHANGED",
        )?;
        if context["schema"] == "app.loomex.runner.uninstall-work-context/v2" {
            require(
                result["maintenanceGeneration"] == context["maintenanceGeneration"]
                    && result["releaseManifestSha256"] == generation["releaseManifestSha256"]
                    && result["contextSha256"] == approval["contextSha256"],
                "UNINSTALL_WORK_BINDING_CHANGED",
            )?;
        }
        if result["ok"] != true {
            require(
                result["failureCode"] == "MANAGED_WORK_MIGRATION_CHANGED",
                "UNINSTALL_WORK_BINDING_CHANGED",
            )?;
            for index in 0..256 {
                require(
                    !paths
                        .state_dir
                        .join(format!("uninstall-work-checkpoint-{attempt}-{index}.json"))
                        .try_exists()?,
                    "UNINSTALL_WORK_BINDING_CHANGED",
                )?;
            }
        }
        if work["lastAttempt"]["id"] == attempt {
            require(
                work["lastAttempt"]["contextSha256"] == approval["contextSha256"]
                    && work["lastAttempt"]["action"] == context["action"]
                    && saved_scope(&work["lastAttempt"]) == saved_scope(&context)
                    && work["lastAttempt"]["expectedAssessmentSha256"]
                        == context["expectedAssessmentSha256"]
                    && if work["phase"] == "settled" {
                        result["ok"] == true
                    } else if work["phase"] == "review_required" {
                        result["failureCode"] == "MANAGED_WORK_MIGRATION_CHANGED"
                    } else {
                        result["ok"] == true
                            || result["failureCode"] == "MANAGED_WORK_MIGRATION_CHANGED"
                    },
                "UNINSTALL_WORK_BINDING_CHANGED",
            )?;
        }
    }
    Ok(())
}

pub(super) fn reconciled_current(paths: &lifecycle::Paths, work: &Value) -> Result<bool> {
    prove_inactive(paths, work)?;
    if work["lastAttempt"]["id"]
        .as_str()
        .is_some_and(|attempt| !work["failedReconcileProofs"][attempt].is_null())
    {
        return Ok(false);
    }

    for attempt in work["attemptIds"].as_array().into_iter().flatten() {
        let attempt = attempt.as_str().context("invalid work attempt")?;
        let context: Value = work_json(
            &paths
                .state_dir
                .join(format!("uninstall-work-context-{attempt}.json")),
        )?;
        if context["schema"] == "app.loomex.runner.uninstall-work-context/v2"
            && context["maintenanceGeneration"] == work["currentGeneration"]
            && context["action"] == "reconcile"
        {
            let result: Value = work_json(
                &paths
                    .state_dir
                    .join(format!("uninstall-work-result-{attempt}.json")),
            )?;
            if result["ok"] == true {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

pub(super) fn known_result(paths: &lifecycle::Paths, work: &Value) -> Result<bool> {
    let attempt = work["attempt"]["id"]
        .as_str()
        .context("invalid work attempt")?;
    Uuid::parse_str(attempt)?;
    let path = paths
        .state_dir
        .join(format!("uninstall-work-result-{attempt}.json"));
    if !path.try_exists()? {
        return Ok(false);
    }
    let result: Value = work_json(&path)?;
    if result["ok"] != true && result["failureCode"] != "MANAGED_WORK_MIGRATION_CHANGED" {
        return Ok(false);
    }
    let generation = attempt_release(paths, work, attempt)?;
    let context_path = paths
        .state_dir
        .join(format!("uninstall-work-context-{attempt}.json"));
    let context: Value = work_json(&context_path)?;
    let old: Value = work_json(&paths.state_dir.join("bootstrap-uninstall.json"))?;
    require(
        result["operationId"] == work["operationId"]
            && result["attemptId"] == attempt
            && digest_file(&context_path)? == work["attempt"]["contextSha256"]
            && context["action"] == work["attempt"]["action"]
            && saved_scope(&context) == saved_scope(&work["attempt"])
            && context["expectedAssessmentSha256"] == work["attempt"]["expectedAssessmentSha256"]
            && context["receiptSha256"] == state::json_digest(&old["receipt"])
            && context["binarySha256"]
                == digest_file(
                    &paths
                        .state_dir
                        .join(generation["stageName"].as_str().unwrap())
                        .join("bin/loomex-runner"),
                )?,
        "UNINSTALL_WORK_BINDING_CHANGED",
    )?;
    if context["schema"] == "app.loomex.runner.uninstall-work-context/v2" {
        require(
            result["maintenanceGeneration"] == context["maintenanceGeneration"]
                && result["releaseManifestSha256"] == generation["releaseManifestSha256"]
                && result["contextSha256"] == work["attempt"]["contextSha256"],
            "UNINSTALL_WORK_BINDING_CHANGED",
        )?;
    }
    if result["failureCode"] == "MANAGED_WORK_MIGRATION_CHANGED" {
        for index in 0..256 {
            require(
                !paths
                    .state_dir
                    .join(format!("uninstall-work-checkpoint-{attempt}-{index}.json"))
                    .try_exists()?,
                "UNINSTALL_WORK_BINDING_CHANGED",
            )?;
        }
    }
    Ok(true)
}

const FAILED_RECONCILE_PROOF: &str =
    "app.loomex.runner.uninstall-work-inactive-failed-reconcile/v1";

/// Failed is a native process result, never a domain completion/no-effects proof.
/// A missing/uncertain result or PID retains the original release ownership.
pub(super) fn failed_reconcile_candidate(paths: &lifecycle::Paths, work: &Value) -> Result<bool> {
    if work["schema"] != OWNER_V2 || work["attempt"]["action"] != "reconcile" {
        return Ok(false);
    }
    valid_owner(work)?;
    verify_archives(paths, work)?;
    verify_failed_history(paths, work)?;
    generation_cleanup::verify_known_resources(paths, work)?;
    let attempt = work["attempt"]["id"]
        .as_str()
        .context("invalid work attempt")?;
    let result_path = paths
        .state_dir
        .join(format!("uninstall-work-result-{attempt}.json"));
    if !present(&result_path)? {
        return Ok(false);
    }
    let result: Value = work_json(&result_path)?;
    if result["ok"] != false || result["failureCode"] == "MANAGED_WORK_MIGRATION_CHANGED" {
        return Ok(false);
    }
    exited_attempt_pid(work)?;
    let context_path = paths
        .state_dir
        .join(format!("uninstall-work-context-{attempt}.json"));
    let context: Value = work_json(&context_path)?;
    let generation = attempt_release(paths, work, attempt)?;
    let old_bytes = regular_bytes(&paths.state_dir.join("bootstrap-uninstall.json"))?;
    let old: Value = serde_json::from_slice(&old_bytes)?;
    let identity = if old["schema"] == OLD_SCHEMA {
        prior_identity(paths)?
    } else {
        validated_current_identity(&old)?
    };
    require(
        result["schema"] == "app.loomex.runner.uninstall-work-result/v2"
            && result["failureCode"]
                .as_str()
                .is_some_and(|code| !code.is_empty() && code.len() <= 128)
            && result["error"]["code"]
                .as_str()
                .is_some_and(|code| !code.is_empty() && code.len() <= 128)
            && work["attempt"]["state"] == "running"
            && context["schema"] == "app.loomex.runner.uninstall-work-context/v2"
            && context["stateDir"] == json!(paths.state_dir)
            && context["installBase"] == json!(paths.install_base)
            && context["launchAgentsDir"] == json!(paths.launch_agents_dir)
            && context["singletonFd"]
                .as_i64()
                .is_some_and(|fd| fd >= 3 && fd <= i64::from(i32::MAX))
            && work["attemptIds"]
                .as_array()
                .is_some_and(|ids| ids.last() == Some(&work["attempt"]["id"]))
            && digest_file(
                &PathBuf::from(generation["releasePath"].as_str().unwrap()).join("manifest.json"),
            )? == generation["releaseManifestSha256"]
            && context["action"] == "reconcile"
            && context["expectedAssessmentSha256"].is_null()
            && work["attempt"]["expectedAssessmentSha256"].is_null()
            && result["operationId"] == work["operationId"]
            && result["attemptId"] == attempt
            && context["maintenanceGeneration"] == work["currentGeneration"]
            && context["maintenanceGeneration"] == work["attempt"]["maintenanceGeneration"]
            && result["maintenanceGeneration"] == context["maintenanceGeneration"]
            && result["releaseManifestSha256"] == generation["releaseManifestSha256"]
            && work["attempt"]["releaseManifestSha256"] == generation["releaseManifestSha256"]
            && result["contextSha256"] == digest_file(&context_path)?
            && result["contextSha256"] == work["attempt"]["contextSha256"]
            && saved_scope(&context) == saved_scope(&work["attempt"])
            && state::digest(&old_bytes) == work["journalSha256"]
            && context["receiptSha256"] == state::json_digest(&old["receipt"])
            && context["expectedIdentity"] == identity
            && context["binarySha256"]
                == digest_file(
                    &paths
                        .state_dir
                        .join(generation["stageName"].as_str().unwrap())
                        .join("bin/loomex-runner"),
                )?,
        "UNINSTALL_WORK_BINDING_CHANGED",
    )?;
    inventory(
        &paths
            .state_dir
            .join(generation["stageName"].as_str().unwrap()),
        generation["files"]
            .as_array()
            .context("invalid work inventory")?,
    )?;
    // Approval absence is valid only before the request set was published.
    let requests = paths
        .state_dir
        .join(format!("uninstall-work-requests-{attempt}.json"));
    if !present(&requests)? {
        let root = paths
            .state_dir
            .join("recovery-evidence")
            .join(work["operationId"].as_str().unwrap());
        require(
            !present(&root.join(format!("approval-{attempt}.json")))?,
            "UNINSTALL_WORK_BINDING_CHANGED",
        )?;
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
    }
    verify_failed_artifacts(paths, work, &context, attempt)?;
    Ok(true)
}

fn verify_failed_artifacts(
    paths: &lifecycle::Paths,
    work: &Value,
    context: &Value,
    attempt: &str,
) -> Result<()> {
    let root = paths
        .state_dir
        .join("recovery-evidence")
        .join(work["operationId"].as_str().unwrap());
    let requests_path = paths
        .state_dir
        .join(format!("uninstall-work-requests-{attempt}.json"));
    let request_bytes = if present(&requests_path)? {
        Some(regular_bytes(&requests_path)?)
    } else {
        None
    };
    if let Some(bytes) = &request_bytes {
        let requests: Value = serde_json::from_slice(bytes)?;
        require(
            requests["operationId"] == work["operationId"]
                && requests["attemptId"] == attempt
                && requests["requests"]
                    .as_array()
                    .is_some_and(|requests| requests.len() <= 256),
            "UNINSTALL_WORK_BINDING_CHANGED",
        )?;
        let approval_path = root.join(format!("approval-{attempt}.json"));
        if present(&approval_path)? {
            let approval: Value = work_json(&approval_path)?;
            require(
                approval["schema"] == "app.loomex.runner.uninstall-work-approval/v1"
                    && approval["operationId"] == work["operationId"]
                    && approval["attemptId"] == attempt
                    && approval["action"] == "reconcile"
                    && saved_scope(&approval) == saved_scope(context)
                    && approval["contextSha256"] == work["attempt"]["contextSha256"]
                    && approval["originalJournalSha256"] == work["journalSha256"]
                    && approval["releaseManifestSha256"] == context["releaseManifestSha256"]
                    && approval["expectedAssessmentSha256"].is_null()
                    && approval["receiptSha256"] == context["receiptSha256"]
                    && approval["identityReference"]
                        == state::json_digest(&context["expectedIdentity"])
                    && approval["requestSetSha256"] == state::digest(bytes),
                "UNINSTALL_WORK_BINDING_CHANGED",
            )?;
        }
    }
    for (private, evidence, raw) in [
        (
            format!("uninstall-work-requests-{attempt}.json"),
            format!("requests-{attempt}.json"),
            false,
        ),
        (
            format!("uninstall-work-authorization-{attempt}.json"),
            format!("native-authorization-{attempt}.json"),
            true,
        ),
    ] {
        if present(&root.join(&evidence))? {
            let bytes = regular_bytes(&paths.state_dir.join(private))?;
            let expected = if raw {
                bytes
            } else {
                serde_json::to_vec(&audit_projection(&serde_json::from_slice::<Value>(&bytes)?))?
            };
            require(
                regular_bytes(&root.join(evidence))? == expected,
                "UNINSTALL_WORK_BINDING_CHANGED",
            )?;
        }
    }
    for index in 0..256 {
        let record = root.join(format!("record-{attempt}-{index}.json"));
        if present(&record)? {
            let value: Value = work_json(
                &paths
                    .state_dir
                    .join(format!("uninstall-work-checkpoint-{attempt}-{index}.json")),
            )?;
            require(
                regular_bytes(&record)? == serde_json::to_vec(&audit_projection(&value))?,
                "UNINSTALL_WORK_BINDING_CHANGED",
            )?;
        }
        let cache = root.join(format!("cache-approval-{attempt}-{index}.json"));
        if present(&cache)? {
            let proof: Value = work_json(&cache)?;
            require(
                proof["schema"] == "app.loomex.runner.uninstall-work-cache-approval/v1"
                    && proof["operationId"] == work["operationId"]
                    && proof["attemptId"] == attempt
                    && proof["index"] == index
                    && proof["privateSha256"]
                        == digest_file(
                            &paths
                                .state_dir
                                .join(format!("uninstall-work-cache-{attempt}-{index}.json")),
                        )?
                    && proof["approvalSha256"]
                        == digest_file(&root.join(format!("approval-{attempt}.json")))?,
                "UNINSTALL_WORK_BINDING_CHANGED",
            )?;
        }
    }
    attempt_audits(paths, work, attempt)?;
    Ok(())
}

fn attempt_audits(paths: &lifecycle::Paths, work: &Value, attempt: &str) -> Result<Vec<Value>> {
    let root = paths
        .state_dir
        .join("recovery-evidence")
        .join(work["operationId"].as_str().context("invalid work owner")?);
    let mut files = vec![];
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| refusal("UNINSTALL_WORK_BINDING_CHANGED"))?;
        if name.contains(attempt) && !name.starts_with("inactive-failed-reconcile-") {
            let hash = digest_file(&entry.path())?;
            if let Some(encoded) = name.strip_prefix(&format!("resolution-{attempt}-")) {
                require(
                    encoded.strip_suffix(".json") == Some(hash.as_str()),
                    "UNINSTALL_WORK_BINDING_CHANGED",
                )?;
            }
            files.push(json!({"name":name,"sha256":hash}));
        }
    }
    require(files.len() <= 1024, "UNINSTALL_WORK_AUDIT_LIMIT")?;
    files.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
    Ok(files)
}

/// Called only by the qualified lifecycle owner with the quiescent singleton.
pub(super) fn settle_failed_reconcile(
    paths: &lifecycle::Paths,
    work: &mut Value,
    old_bytes: &[u8],
) -> Result<()> {
    require(
        failed_reconcile_candidate(paths, work)?,
        "UNINSTALL_WORK_MAINTENANCE_PENDING",
    )?;
    let id = Uuid::parse_str(work["operationId"].as_str().context("invalid work owner")?)?;
    let old: Value = serde_json::from_slice(old_bytes)?;
    let fence_digest = old["fenceJournalSha256"]
        .as_str()
        .unwrap_or(work["journalSha256"].as_str().unwrap());
    lifecycle::fence_inactive_failed_reconcile_locked(paths, id, fence_digest)?;
    let attempt = work["attempt"]["id"].as_str().unwrap().to_owned();
    let result: Value = work_json(
        &paths
            .state_dir
            .join(format!("uninstall-work-result-{attempt}.json")),
    )?;
    audit(paths, work, old_bytes, &result)?;
    let proof = json!({"schema":FAILED_RECONCILE_PROOF,"operationId":id,"attempt":work["attempt"],"journalSha256":work["journalSha256"],"generation":attempt_release(paths,work,&attempt)?,"resources":generation_cleanup::attempt_resources(paths,&attempt)?,"auditFiles":attempt_audits(paths,work,&attempt)?,"disposition":"inactive_failed_reconcile","remoteOutcome":"unknown"});
    let bytes = serde_json::to_vec(&proof)?;
    let root = paths
        .state_dir
        .join("recovery-evidence")
        .join(id.to_string());
    immutable_copy(
        &root.join(format!("inactive-failed-reconcile-{attempt}.json")),
        &bytes,
    )?;
    fault("AFTER_WORK_FAILED_RECONCILE_PROOF")?;
    if work["failedReconcileProofs"].is_null() {
        work["failedReconcileProofs"] = json!({});
    }
    work["failedReconcileProofs"][&attempt] = json!(state::digest(&bytes));
    work["lastAttempt"] = work["attempt"].take();
    work["attempt"] = Value::Null;
    work["phase"] = json!("qualified");
    save_work(paths, work)?;
    fault("AFTER_WORK_FAILED_RECONCILE_SETTLEMENT")?;
    Ok(())
}

pub(super) fn verify_failed_proof(
    paths: &lifecycle::Paths,
    work: &Value,
    attempt: &str,
) -> Result<()> {
    let root = paths
        .state_dir
        .join("recovery-evidence")
        .join(work["operationId"].as_str().context("invalid work owner")?);
    let proof_bytes =
        regular_bytes(&root.join(format!("inactive-failed-reconcile-{attempt}.json")))?;
    let proof: Value = serde_json::from_slice(&proof_bytes)?;
    require(
        proof["schema"] == FAILED_RECONCILE_PROOF
            && proof["operationId"] == work["operationId"]
            && proof["attempt"]["id"] == attempt
            && proof["attempt"]["action"] == "reconcile"
            && proof["attempt"]["state"] == "running"
            && proof["attempt"]["pid"]
                .as_i64()
                .is_some_and(|pid| pid > 1 && pid <= i64::from(i32::MAX))
            && proof["journalSha256"] == work["journalSha256"]
            && proof["generation"] == attempt_release(paths, work, attempt)?
            && proof["disposition"] == "inactive_failed_reconcile"
            && proof["remoteOutcome"] == "unknown"
            && work["failedReconcileProofs"][attempt] == state::digest(&proof_bytes)
            && proof["resources"] == json!(generation_cleanup::attempt_resources(paths, attempt)?)
            && proof["auditFiles"] == json!(attempt_audits(paths, work, attempt)?),
        "UNINSTALL_WORK_BINDING_CHANGED",
    )?;
    let result: Value = work_json(
        &paths
            .state_dir
            .join(format!("uninstall-work-result-{attempt}.json")),
    )?;
    let context_path = paths
        .state_dir
        .join(format!("uninstall-work-context-{attempt}.json"));
    let context: Value = work_json(&context_path)?;
    require(
        result["ok"] == false
            && result["schema"] == "app.loomex.runner.uninstall-work-result/v2"
            && result["operationId"] == work["operationId"]
            && result["attemptId"] == attempt
            && result["contextSha256"] == digest_file(&context_path)?
            && result["contextSha256"] == proof["attempt"]["contextSha256"]
            && result["maintenanceGeneration"] == context["maintenanceGeneration"]
            && result["releaseManifestSha256"] == proof["generation"]["releaseManifestSha256"],
        "UNINSTALL_WORK_BINDING_CHANGED",
    )?;
    Ok(())
}

fn verify_failed_history(paths: &lifecycle::Paths, work: &Value) -> Result<()> {
    if let Some(proofs) = work["failedReconcileProofs"].as_object() {
        require(proofs.len() <= 64, "UNINSTALL_WORK_AUDIT_LIMIT")?;
        for (attempt, hash) in proofs {
            require(
                hash.as_str().is_some_and(valid_work_digest)
                    && work["attemptIds"]
                        .as_array()
                        .is_some_and(|ids| ids.iter().any(|id| id == attempt)),
                "UNINSTALL_WORK_BINDING_CHANGED",
            )?;
            verify_failed_proof(paths, work, attempt)?;
        }
    } else {
        require(
            work["failedReconcileProofs"].is_null(),
            "UNINSTALL_WORK_BINDING_CHANGED",
        )?;
    }
    Ok(())
}

pub(super) fn candidate_transition(
    paths: &lifecycle::Paths,
    work: &Value,
    candidate: &str,
    release: Option<&Path>,
) -> Result<&'static str> {
    valid_owner(work)?;
    verify_failed_history(paths, work)?;
    require(
        digest_file(&paths.state_dir.join("bootstrap-uninstall.json"))? == work["journalSha256"],
        "UNINSTALL_WORK_BINDING_CHANGED",
    )?;
    let same = work["releaseManifestSha256"] == candidate
        && release.is_none_or(|release| {
            work["releasePath"].as_str() == Some(release.to_string_lossy().as_ref())
        });
    if !work["attempt"].is_null() {
        if !same {
            if failed_reconcile_candidate(paths, work)? {
                // Observation only. Native work holding the inherited singleton
                // (including blocked store IO) still pins the old attempt.
                let _guard = singleton(paths, false)
                    .map_err(|_| refusal("UNINSTALL_WORK_MAINTENANCE_PENDING"))?;
                jobs_quiescent(paths)?;
                let old: Value = work_json(&paths.state_dir.join("bootstrap-uninstall.json"))?;
                verify_recorded_process_exit(&old)?;
                return Ok("eligible_successor");
            }
            require(
                known_result(paths, work)?,
                "UNINSTALL_WORK_MAINTENANCE_PENDING",
            )?;
        }
        return Ok("resume_original_attempt");
    }
    prove_inactive(paths, work)?;
    records(work)?;
    if same {
        return Ok(if work["phase"] == "review_required" {
            "review_required"
        } else {
            "current_release"
        });
    }
    Ok("eligible_successor")
}

pub(crate) fn work_maintenance_reference(
    paths: &lifecycle::Paths,
    candidate_manifest_sha256: Option<&str>,
    candidate_release_path: Option<&Path>,
) -> Value {
    let path = paths.state_dir.join("uninstall-work.json");
    let Ok(bytes) = regular_bytes(&path) else {
        return Value::Null;
    };
    let Ok(work) = serde_json::from_slice::<Value>(&bytes) else {
        return Value::Null;
    };
    if work["operationId"]
        .as_str()
        .is_none_or(|id| Uuid::parse_str(id).is_err())
        || !work["journalSha256"]
            .as_str()
            .is_some_and(valid_work_digest)
    {
        return Value::Null;
    }
    let transition = if !supported(&work) {
        "unsupported"
    } else if candidate_manifest_sha256.is_none() || candidate_release_path.is_none() {
        "blocked"
    } else if let Some(candidate) = candidate_manifest_sha256 {
        candidate_transition(paths, &work, candidate, candidate_release_path).unwrap_or("blocked")
    } else if work["phase"] == "review_required" {
        "review_required"
    } else {
        "blocked"
    };
    json!({"schema":"app.loomex.runner.uninstall-work-reference/v1","operationId":work["operationId"],"ownerSha256":state::digest(&bytes),"journalSha256":work["journalSha256"],"phase":work["phase"].as_str().filter(|phase|matches!(*phase,"qualified"|"settled"|"review_required")),"generation":work["currentGeneration"].as_u64().unwrap_or(0),"releaseManifestSha256":work["releaseManifestSha256"].as_str().filter(|hash|valid_work_digest(hash)),"candidateManifestSha256":candidate_manifest_sha256.filter(|hash|valid_work_digest(hash)),"releasePathSha256":work["releasePath"].as_str().map(|path|state::digest(path.as_bytes())),"candidateReleasePathSha256":candidate_release_path.map(|path|state::digest(path.to_string_lossy().as_bytes())),"attemptId":work["attempt"]["id"].as_str().filter(|id|Uuid::parse_str(id).is_ok()),"transition":transition})
}

pub(super) fn preserve_legacy_owner(paths: &lifecycle::Paths, work: &mut Value) -> Result<()> {
    if work["schema"] != OWNER_V1 {
        return Ok(());
    }
    let root = paths
        .state_dir
        .join("recovery-evidence")
        .join(work["operationId"].as_str().context("invalid work owner")?);
    state::private_dir(&paths.state_dir.join("recovery-evidence"))?;
    state::private_dir(&root)?;
    let original = root.join("original-work-owner-v1.json");
    if let Some(hash) = work["legacyOwnerSha256"].as_str() {
        require(
            valid_work_digest(hash) && digest_file(&original)? == hash,
            "UNINSTALL_WORK_BINDING_CHANGED",
        )?;
    } else {
        let bytes = regular_bytes(&paths.state_dir.join("uninstall-work.json"))?;
        immutable_copy(&original, &bytes)?;
        work["legacyOwnerSha256"] = json!(state::digest(&bytes));
    }
    Ok(())
}

pub(super) fn upgrade(
    paths: &lifecycle::Paths,
    work: &mut Value,
    release: &Path,
    manifest: &Value,
) -> Result<()> {
    prove_inactive(paths, work)?;
    let mut generations = records(work)?;
    preserve_legacy_owner(paths, work)?;
    let hash = digest_file(&release.join("manifest.json"))?;
    if work["releaseManifestSha256"] != hash
        || work["releasePath"].as_str() != Some(release.to_string_lossy().as_ref())
    {
        require(generations.len() < 64, "UNINSTALL_WORK_AUDIT_LIMIT")?;
        let generation = generations.len();
        generations.push(json!({"generation":generation,"releasePath":release,"releaseManifestSha256":hash,"files":manifest["payload"]["files"],"stageName":format!("uninstall-work-stage-{}-generation-{generation}",work["operationId"].as_str().unwrap())}));
        work["phase"] = json!("qualified");
    }
    work["schema"] = json!(OWNER_V2);
    work["currentGeneration"] = json!(generations.len() - 1);
    work["releasePath"] = json!(release);
    work["releaseManifestSha256"] = json!(hash);
    work["generations"] = json!(generations);
    Ok(())
}

pub(super) fn stage(paths: &lifecycle::Paths, work: &Value) -> Result<PathBuf> {
    let stage = paths.state_dir.join(
        records(work)?.last().unwrap()["stageName"]
            .as_str()
            .unwrap(),
    );
    if present(&stage)? {
        let metadata = fs::symlink_metadata(&stage)?;
        require(
            metadata.is_dir() && !metadata.file_type().is_symlink(),
            "UNINSTALL_WORK_BINDING_CHANGED",
        )?;
    }
    Ok(stage)
}
pub(super) fn verified_stage(paths: &lifecycle::Paths, work: &Value) -> Result<PathBuf> {
    verify_archives(paths, work)?;
    verify_failed_history(paths, work)?;
    let stage = stage(paths, work)?;
    let generations = records(work)?;
    inventory(
        &stage,
        generations.last().unwrap()["files"]
            .as_array()
            .context("missing work inventory")?,
    )?;
    Ok(stage)
}
