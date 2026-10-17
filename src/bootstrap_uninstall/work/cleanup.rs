//! Restartable deletion of an already adopted generation owner.
use super::*;

fn resource_names(work: &Value) -> Result<(std::collections::BTreeSet<String>, Vec<Value>)> {
    let mut names = std::collections::BTreeSet::new();
    let generations = generations::records(work)?;
    for generation in &generations {
        let name = generation["stageName"]
            .as_str()
            .context("invalid work stage")?;
        names.insert(name.to_owned());
        names.insert(format!(".{name}.publishing"));
    }
    require(
        work["attemptIds"].is_null() || work["attemptIds"].is_array(),
        "UNINSTALL_WORK_BINDING_CHANGED",
    )?;
    for attempt in work["attemptIds"].as_array().into_iter().flatten() {
        let attempt = Uuid::parse_str(attempt.as_str().context("invalid work attempt")?)?;
        for kind in ["context", "requests", "result", "authorization"] {
            names.insert(format!("uninstall-work-{kind}-{attempt}.json"));
        }
        for index in 0..256 {
            for kind in ["checkpoint", "cache"] {
                names.insert(format!("uninstall-work-{kind}-{attempt}-{index}.json"));
            }
        }
    }
    Ok((names, generations))
}
fn resource_entries(
    paths: &lifecycle::Paths,
    allowed: &std::collections::BTreeSet<String>,
) -> Result<Vec<(String, PathBuf)>> {
    let mut entries = Vec::new();
    for entry in fs::read_dir(&paths.state_dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_str().context("invalid work resource")?;
        if name.starts_with("uninstall-work-") || name.starts_with(".uninstall-work-stage-") {
            require(allowed.contains(name), "UNINSTALL_WORK_BINDING_CHANGED")?;
            entries.push((name.to_owned(), entry.path()));
        }
    }
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(entries)
}

pub(super) fn verify_known_resources(paths: &lifecycle::Paths, work: &Value) -> Result<()> {
    let (allowed, _) = resource_names(work)?;
    resource_entries(paths, &allowed)?;
    Ok(())
}

pub(super) fn cleanup(paths: &lifecycle::Paths, work: &Value, journal: &Value) -> Result<()> {
    let id = work["operationId"].as_str().context("invalid work owner")?;
    let root = paths.state_dir.join("recovery-evidence").join(id);
    let plan_path = root.join("work-cleanup-plan.json");
    let owner_path = paths.state_dir.join("uninstall-work.json");
    let owner_sha = digest_file(&owner_path)?;
    let (allowed, generations) = resource_names(work)?;
    if !present(&plan_path)? {
        generations::prove_inactive(paths, work)?;
        validate_cleanup_approvals(paths, work)?;
        let mut files = Vec::new();
        for (name, path) in resource_entries(paths, &allowed)? {
            if generations.iter().any(|generation| {
                generation["stageName"] == name
                    || format!(".{}.publishing", generation["stageName"].as_str().unwrap()) == name
            }) {
                continue;
            }
            files.push(json!({"name":name,"sha256":digest_file(&path)?}));
        }
        let mut evidence = Vec::new();
        for entry in fs::read_dir(&root)? {
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_str().context("invalid work evidence")?;
            evidence.push(json!({"name":name,"sha256":digest_file(&entry.path())?}));
        }
        evidence.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
        let plan = json!({"schema":"app.loomex.runner.uninstall-work-cleanup/v1","operationId":id,"ownerSha256":owner_sha,"ownerPhase":work["phase"],"journalSha256":work["journalSha256"],"generations":generations,"attemptIds":work["attemptIds"],"resourceFiles":files,"evidenceFiles":evidence});
        immutable_copy(&plan_path, &serde_json::to_vec(&plan)?)?;
    }
    let plan: Value = work_json(&plan_path)?;
    require(
        plan["schema"] == "app.loomex.runner.uninstall-work-cleanup/v1"
            && plan["operationId"] == id
            && plan["ownerSha256"] == owner_sha
            && plan["ownerPhase"] == work["phase"]
            && plan["journalSha256"] == work["journalSha256"]
            && plan["journalSha256"] == journal["recovery"]["oldJournalSha256"]
            && plan["generations"] == json!(generations)
            && plan["attemptIds"] == work["attemptIds"],
        "UNINSTALL_WORK_BINDING_CHANGED",
    )?;
    generations::verify_archives(paths, work)?;
    let mut expected = std::collections::BTreeMap::new();
    for file in plan["resourceFiles"]
        .as_array()
        .context("invalid work cleanup files")?
    {
        let name = file["name"].as_str().context("invalid work cleanup file")?;
        require(
            allowed.contains(name)
                && file["sha256"].as_str().is_some_and(valid_work_digest)
                && expected
                    .insert(name, file["sha256"].as_str().unwrap())
                    .is_none(),
            "UNINSTALL_WORK_BINDING_CHANGED",
        )?;
    }
    for file in plan["evidenceFiles"]
        .as_array()
        .context("invalid work cleanup evidence")?
    {
        let name = file["name"]
            .as_str()
            .context("invalid work cleanup evidence")?;
        require(
            Path::new(name).components().count() == 1
                && matches!(
                    Path::new(name).components().next(),
                    Some(std::path::Component::Normal(_))
                )
                && name != "work-cleanup-plan.json"
                && file["sha256"] == digest_file(&root.join(name))?,
            "UNINSTALL_WORK_BINDING_CHANGED",
        )?;
    }
    // Verify the entire remaining subset before removing a single entry.
    let mut files = Vec::new();
    for (name, path) in resource_entries(paths, &allowed)? {
        if generations.iter().any(|generation| {
            generation["stageName"] == name
                || format!(".{}.publishing", generation["stageName"].as_str().unwrap()) == name
        }) {
            continue;
        }
        require(
            expected
                .get(name.as_str())
                .is_some_and(|hash| digest_file(&path).is_ok_and(|actual| actual == *hash)),
            "UNINSTALL_WORK_BINDING_CHANGED",
        )?;
        files.push(path);
    }
    let mut stages = Vec::new();
    for generation in &generations {
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
                        .context("invalid work inventory")?,
                    true,
                )?;
                stages.push(stage);
            }
        }
    }
    for stage in stages {
        // This helper verifies and deletes an exact surviving inventory subset.
        let generation = generations
            .iter()
            .find(|generation| {
                stage.file_name().unwrap() == generation["stageName"].as_str().unwrap()
                    || stage.file_name().unwrap()
                        == format!(".{}.publishing", generation["stageName"].as_str().unwrap())
                            .as_str()
            })
            .context("invalid work stage")?;
        lifecycle::prune_remove_quarantine_exact(&stage, generation["files"].as_array().unwrap())?;
        File::open(&paths.state_dir)?.sync_all()?;
        fault("DURING_WORK_STAGE_DELETE")?;
    }
    for path in files {
        remove_regular(&path)?;
        File::open(&paths.state_dir)?.sync_all()?;
        fault("DURING_WORK_RESOURCE_DELETE")?;
    }
    remove_regular(&owner_path)?;
    File::open(&paths.state_dir)?.sync_all()?;
    Ok(())
}

/// The owner is removed last. A retained plan therefore proves completion only
/// while every planned temporary resource remains absent.
pub(super) fn require_completed(paths: &lifecycle::Paths, journal: &Value) -> Result<()> {
    let Some(id) = journal["operationId"].as_str() else {
        return Ok(());
    };
    Uuid::parse_str(id)?;
    let root = paths.state_dir.join("recovery-evidence").join(id);
    let plan_path = root.join("work-cleanup-plan.json");
    if !present(&plan_path)? {
        return Ok(());
    }
    let plan: Value = work_json(&plan_path)?;
    require(
        plan["schema"] == "app.loomex.runner.uninstall-work-cleanup/v1"
            && plan["operationId"] == id
            && plan["journalSha256"] == journal["recovery"]["oldJournalSha256"]
            && plan["ownerSha256"].as_str().is_some_and(valid_work_digest),
        "UNINSTALL_WORK_BINDING_CHANGED",
    )?;
    let records = plan["generations"]
        .as_array()
        .context("invalid work cleanup generations")?;
    let current = records.last().context("invalid work cleanup generations")?;
    let work = json!({"schema":generations::OWNER_V2,"phase":plan["ownerPhase"],"operationId":id,"journalSha256":plan["journalSha256"],"releasePath":current["releasePath"],"releaseManifestSha256":current["releaseManifestSha256"],"currentGeneration":records.len()-1,"generations":records,"attemptIds":plan["attemptIds"]});
    generations::verify_archives(paths, &work)?;
    let (allowed, _) = resource_names(&work)?;
    require(
        resource_entries(paths, &allowed)?.is_empty(),
        "UNINSTALL_WORK_BINDING_CHANGED",
    )?;
    for file in plan["evidenceFiles"]
        .as_array()
        .context("invalid work cleanup evidence")?
    {
        let name = file["name"]
            .as_str()
            .context("invalid work cleanup evidence")?;
        require(
            Path::new(name).components().count() == 1
                && matches!(
                    Path::new(name).components().next(),
                    Some(std::path::Component::Normal(_))
                )
                && name != "work-cleanup-plan.json"
                && file["sha256"] == digest_file(&root.join(name))?,
            "UNINSTALL_WORK_BINDING_CHANGED",
        )?;
    }
    Ok(())
}
