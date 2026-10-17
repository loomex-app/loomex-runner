//! Exact local acceptance references may close with their retired continuation.
//! This never converts an active run into terminal execution evidence.
use super::*;

struct Acceptance {
    organization: String,
    account: String,
    installation: String,
    resolved: bool,
    bound: bool,
    run: String,
    receipt: String,
    trigger: String,
    request: Option<String>,
}

fn closures(dir: &Path, only_closed: bool) -> Result<Vec<Acceptance>> {
    let name = "follow.sqlite3";
    let mut family = Vec::new();
    for suffix in ["", "-wal", "-shm", "-journal"] {
        let path = dir.join(format!("{name}{suffix}"));
        if metadata(&path, false)?.is_some() {
            family.push(path);
        }
    }
    if family.is_empty() {
        return Ok(Vec::new());
    }
    ensure!(family[0] == dir.join(name), "{PENDING}");
    let snapshot = DatabaseSnapshot::capture(&family)?;
    let connection = Connection::open_with_flags(
        snapshot.directory.join(name),
        OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    assessment::schema(&connection, name)?;
    let mut result = Vec::new();
    for capability in crate::follow::maintenance_acceptance_capabilities(&connection)? {
        let field = |key: &str| {
            capability[key]
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| anyhow::anyhow!(PENDING))
        };
        let organization = field("organizationId")?;
        let account = field("accountSubject")?;
        let install = field("installationId")?;
        let run = field("runId")?;
        let receipt = field("receipt")?;
        let trigger = field("trigger")?;
        let request = capability["requestId"].as_str().map(str::to_owned);
        let resolved = capability["resolved"] == true;
        if only_closed && !resolved {
            continue;
        }
        let bindings: bool = connection.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='follow_capability_bindings')", [], |row| row.get(0))?;
        let bound = bindings && connection.query_row("SELECT EXISTS(SELECT 1 FROM follow_capability_bindings b JOIN follow_sessions s ON s.follow_session_id=b.follow_session_id AND s.generation=b.generation WHERE b.receipt=?1 AND s.organization_id=?2 AND s.account_subject=?3 AND s.installation_id=?4 AND s.run_id=?5)", rusqlite::params![receipt,organization,account,install,run], |row| row.get::<_,bool>(0))?;
        result.push(Acceptance {
            organization,
            account,
            installation: install,
            resolved,
            bound,
            run,
            receipt,
            trigger,
            request,
        });
    }
    snapshot.verify_sources()?;
    Ok(result)
}

fn accepted<'a>(method: &str, result: &Value, proofs: &'a [Acceptance]) -> Option<&'a Acceptance> {
    if result.get("error").is_some_and(|value| !value.is_null()) {
        return None;
    }
    let continuation = result.pointer("/details/followContinuation")?;
    if continuation["schemaVersion"] != "loomex.follow-session.continuation/v1" {
        return None;
    }
    let run = result
        .pointer("/execution/id")
        .or_else(|| result.get("executionId"))
        .or_else(|| result.get("runId"))?
        .as_str()?;
    if continuation["runId"] != run {
        return None;
    }
    let receipt = continuation["receipt"].as_str()?;
    let proof = proofs.iter().find(|proof| {
        proof.run == run
            && proof.receipt == receipt
            && continuation["trigger"] == proof.trigger
            && continuation["requestId"].as_str() == proof.request.as_deref()
    })?;
    match method {
        "runs.commit"
            if proof.trigger == "run_commit"
                && proof.request.is_none()
                && result["preparationId"]
                    .as_str()
                    .is_some_and(|id| uuid::Uuid::parse_str(id).is_ok()) =>
        {
            Some(proof)
        }
        "interactions.respond" | "interactions.decide"
            if proof.trigger == "accepted_interaction"
                && matches!(
                    result["requestStatus"].as_str(),
                    Some(
                        "resolved"
                            | "completed"
                            | "answered"
                            | "accepted"
                            | "approved"
                            | "rejected"
                    )
                )
                && result["requestId"].as_str() == proof.request.as_deref()
                && proof.request.is_some() =>
        {
            Some(proof)
        }
        _ => None,
    }
}

fn valid_cache(record: &Value) -> bool {
    record["method"].is_string()
        && record["digest"].as_str().is_some_and(|digest| {
            digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
        })
        && record
            .get("status")
            .is_none_or(|status| status == "completed")
}

fn spool_content(dir: &Path, reference: &Value) -> Result<(Value, Value)> {
    let id = reference["responseRef"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!(PENDING))?;
    ensure!(uuid::Uuid::parse_str(id).is_ok(), "{PENDING}");
    let root = dir.join("responses");
    let content = root.join(format!("{id}.json"));
    let size = metadata(&content, false)?
        .ok_or_else(|| anyhow::anyhow!(PENDING))?
        .len();
    // Acceptance payloads outside this budget retain their original guard.
    ensure!(size <= 16 * 1024 * 1024, "{PENDING}");
    let checksum = read_fingerprint(&content, None)?;
    let digest = checksum
        .rsplit(':')
        .next()
        .ok_or_else(|| anyhow::anyhow!(PENDING))?;
    let checksum_path = root.join(format!("{id}.sha256"));
    ensure!(metadata(&checksum_path, false)?.is_some(), "{PENDING}");
    ensure!(
        fs::read_to_string(&checksum_path)?.trim() == digest
            && reference["checksumSha256"] == digest
            && reference["sizeBytes"].as_u64() == Some(size),
        "{PENDING}"
    );
    let result = json(&content)?;
    let meta = json(&root.join(format!("{id}.meta.json")))?;
    Ok((result, meta))
}

fn matching_proof<'a>(
    dir: &Path,
    record: &Value,
    proofs: &'a [Acceptance],
) -> Result<Option<&'a Acceptance>> {
    if !valid_cache(record) {
        return Ok(None);
    }
    let mut result = record["result"].clone();
    let mut meta = None;
    if result.get("responseRef").is_some() {
        let (content, metadata) = spool_content(dir, &result)?;
        result = content;
        meta = Some(metadata);
    }
    let Some(proof) = accepted(record["method"].as_str().unwrap_or(""), &result, proofs) else {
        return Ok(None);
    };
    if record["executionId"] != proof.run {
        return Ok(None);
    }
    if let Some(meta) = meta {
        if meta["ownerScope"]["organizationId"] != proof.organization
            || meta["ownerScope"]["accountSubject"] != proof.account
            || !meta["executionId"].is_null() && meta["executionId"] != proof.run
        {
            return Ok(None);
        }
    }
    Ok(Some(proof))
}

pub(super) fn cache_resolved(dir: &Path, record: &Value) -> Result<bool> {
    Ok(matching_proof(dir, record, &closures(dir, true)?)?.is_some())
}

pub(super) fn spool_resolved(dir: &Path, id: &str) -> Result<bool> {
    let proofs = closures(dir, true)?;
    if proofs.is_empty() {
        return Ok(false);
    }
    let root = dir.join("operations");
    if metadata(&root, true)?.is_none() {
        return Ok(false);
    }
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let name = entry.file_name();
        let known = name
            .to_str()
            .and_then(|name| name.strip_suffix(".json"))
            .is_some_and(|key| {
                uuid::Uuid::parse_str(key).is_ok()
                    || key.len() == 64 && key.bytes().all(|byte| byte.is_ascii_hexdigit())
            });
        if !known {
            continue;
        }
        let record = json(&entry.path())?;
        if record
            .pointer("/result/responseRef")
            .and_then(Value::as_str)
            == Some(id)
            && matching_proof(dir, &record, &proofs)?.is_some()
        {
            return Ok(true);
        }
    }
    Ok(false)
}

pub(super) fn dependency_preview(dir: &Path) -> Result<Vec<Value>> {
    let proofs = closures(dir, false)?;
    let root = dir.join("operations");
    if proofs.is_empty() || metadata(&root, true)?.is_none() {
        return Ok(Vec::new());
    }
    let mut dependencies = Vec::new();
    for entry in fs::read_dir(&root)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let Some(key) = name.strip_suffix(".json").filter(|key| {
            uuid::Uuid::parse_str(key).is_ok()
                || key.len() == 64 && key.bytes().all(|byte| byte.is_ascii_hexdigit())
        }) else {
            continue;
        };
        let record = json(&entry.path())?;
        let Some(proof) = matching_proof(dir, &record, &proofs)? else {
            continue;
        };
        let fingerprint = read_fingerprint(&entry.path(), None)?;
        let hash = |value: &str| crate::state::digest(value.as_bytes());
        dependencies.push(serde_json::json!({
            "schemaVersion":"loomex.acceptance-dependency/v1",
            "cacheReference":hash(&format!("operations/{name}")),
            "cacheDigest":fingerprint.rsplit(':').next(),
            "idempotencyReference":hash(key),"operationDigest":record["digest"],
            "method":record["method"],"resultDigest":crate::state::json_digest(&record["result"]),
            "scopeReference":crate::state::json_digest(&serde_json::json!([proof.organization,proof.account,proof.installation])),
            "runReference":hash(&proof.run),"receiptReference":hash(&proof.receipt),"trigger":proof.trigger,
            "requestReference":proof.request.as_deref().map(hash),
            "closureResolved":proof.resolved,"retirementEligible":proof.bound,
            "responseSpoolReference":record["result"]["responseRef"].as_str().map(hash),
            "responseSpoolDigest":record["result"].get("checksumSha256")
        }));
        ensure!(dependencies.len() <= 256, "MANAGED_WORK_PREVIEW_TOO_LARGE");
    }
    dependencies.sort_by(|left, right| {
        left["cacheReference"]
            .as_str()
            .cmp(&right["cacheReference"].as_str())
    });
    Ok(dependencies)
}
