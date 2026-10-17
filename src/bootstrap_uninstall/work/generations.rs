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

pub(super) fn candidate_transition(
    paths: &lifecycle::Paths,
    work: &Value,
    candidate: &str,
    release: Option<&Path>,
) -> Result<&'static str> {
    valid_owner(work)?;
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
