//! Private mutation observations. A pending observation never grants replay.
use crate::state;
use anyhow::{Context, Result, bail, ensure};
use serde_json::{Value, json};
use std::{
    fs,
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
};
use uuid::Uuid;

const SCHEMA: &str = "loomex.operation-cache-binding/v1";
const RETIREMENT: &str = "loomex.operation-cache-retirement/v1";
fn sha(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub(crate) fn valid_slot(slot: &str) -> bool {
    sha(slot) || Uuid::parse_str(slot).is_ok()
}
pub(crate) fn read(dir: &Path, relative: &str) -> Result<Vec<u8>> {
    let path = Path::new(relative);
    ensure!(
        path.components().count() == 2
            && matches!(
                path.parent().and_then(Path::to_str),
                Some("operations" | "responses" | "recovery-evidence")
            ),
        "UNSAFE_STATE"
    );
    let parent = dir.join(path.parent().context("UNSAFE_STATE")?);
    for directory in [dir, parent.as_path()] {
        let meta = fs::symlink_metadata(directory)?;
        ensure!(
            meta.is_dir()
                && !meta.file_type().is_symlink()
                && meta.uid() == unsafe { libc::geteuid() }
                && meta.mode() & 0o077 == 0,
            "UNSAFE_STATE"
        );
    }
    let full = dir.join(path);
    let meta = fs::symlink_metadata(&full)?;
    ensure!(
        meta.is_file()
            && !meta.file_type().is_symlink()
            && meta.uid() == unsafe { libc::geteuid() }
            && meta.nlink() == 1
            && meta.mode() & 0o077 == 0
            && meta.len() <= 16 * 1024 * 1024,
        "UNSAFE_STATE"
    );
    let mut file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&full)?;
    let actual = file.metadata()?;
    ensure!(
        meta.dev() == actual.dev() && meta.ino() == actual.ino(),
        "MANAGED_WORK_CHANGED"
    );
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    let after = fs::symlink_metadata(full)?;
    ensure!(
        after.dev() == actual.dev()
            && after.ino() == actual.ino()
            && after.len() == bytes.len() as u64
            && after.mtime() == actual.mtime()
            && after.mtime_nsec() == actual.mtime_nsec()
            && after.ctime() == actual.ctime()
            && after.ctime_nsec() == actual.ctime_nsec(),
        "MANAGED_WORK_CHANGED"
    );
    Ok(bytes)
}

/// The authority captured before dispatch, retained independently of the
/// legacy cache digest and its historical filename.
pub(crate) struct BindingOrigin<'a> {
    pub organization: Option<&'a str>,
    pub account: Option<&'a str>,
    pub installation: &'a str,
    pub control_reference: Option<&'a str>,
}

/// Only bounded identity references are duplicated; request content stays with
/// the caller or its existing method owner journal.
pub(crate) fn binding(
    method: &str,
    key: &str,
    fingerprint: &str,
    schema: &Value,
    params: &Value,
    origin: BindingOrigin<'_>,
) -> Value {
    let BindingOrigin {
        organization,
        account,
        installation,
        control_reference,
    } = origin;
    let mut references = serde_json::Map::new();
    for name in [
        "requestId",
        "expectedSchemaDigest",
        "schemaDigest",
        "expectedRevision",
        "expectedVersion",
        "expectedDefinitionChecksum",
        "preparationId",
        "bindingDigest",
        "workflowId",
        "runId",
        "deliveryId",
        "expectedContinuationDigest",
        "handoffRef",
        "expectedOperationReference",
    ] {
        if let Some(value) = params.get(name) {
            if value
                .as_str()
                .is_some_and(|s| s.len() <= 256 && !s.chars().any(char::is_control))
                || value.is_u64()
            {
                references.insert(name.into(), value.clone());
            }
        }
    }
    let receipt = if method == "runs.continuation.requeue" {
        json!({"method":"runs.continuation.receipt","params":{"runId":params["runId"],"deliveryId":params["deliveryId"],"expectedContinuationDigest":params["expectedContinuationDigest"],"idempotencyKey":key}})
    } else {
        receipt_descriptor(method, key)
    };
    json!({"schema":SCHEMA,"method":method,"operationKey":key,"organizationId":organization,"accountSubject":account,"installationId":installation,"requestFingerprint":fingerprint,"inputSchemaDigest":state::json_digest(schema),"controlReference":control_reference,"references":references,"receipt":receipt})
}
pub(crate) fn receipt_descriptor(method: &str, key: &str) -> Value {
    let (route, operation) = match method {
        "builder.start" | "editor.start" | "workflows.create" | "workflows.update"
        | "workflows.publish" => ("workflow.operations.get", method),
        "workflows.patch" => ("workflow.operations.get", "workflows.update"),
        "persona.roles.create" => ("personas.operations.get", "role.create"),
        "personas.create" => ("personas.operations.get", "person.create"),
        "personas.chat_context.create" => ("personas.operations.get", "chat_context.create"),
        "personas.memory.write" => ("personas.operations.get", "memory.write"),
        "personas.memory.update" => ("personas.operations.get", "memory.update"),
        _ => return Value::Null,
    };
    json!({"method":route,"params":{"operation":operation,"idempotencyKey":key}})
}
pub(crate) fn pending(digest: &str, method: &str, binding: Value) -> Value {
    json!({"digest":digest,"method":method,"status":"pending","stage":"not_dispatched","binding":binding})
}
pub(crate) fn completed(mut record: Value, result: Value, execution: Option<Value>) -> Value {
    record["cachedAt"] = json!(state::now());
    record["executionId"] = execution.unwrap_or(Value::Null);
    record["result"] = result;
    if record.get("binding").is_some() {
        record["stage"] = json!("accepted");
        record["status"] = json!("completed");
    } else if let Some(fields) = record.as_object_mut() {
        fields.remove("status");
    }
    record
}
pub(crate) fn known_record(record: &Value) -> bool {
    let Some(fields) = record.as_object() else {
        return false;
    };
    if !record["digest"].as_str().is_some_and(sha)
        || !record["method"]
            .as_str()
            .is_some_and(|m| !m.is_empty() && m.len() < 128)
    {
        return false;
    }
    if fields.keys().any(|key| {
        ![
            "digest",
            "method",
            "status",
            "stage",
            "binding",
            "result",
            "cachedAt",
            "executionId",
            "expired",
            "rejection",
            "expiredAt",
        ]
        .contains(&key.as_str())
    }) {
        return false;
    }
    if record.get("binding").is_some() {
        let binding = &record["binding"];
        let Some(fields) = binding.as_object() else {
            return false;
        };
        if fields.keys().any(|name| {
            ![
                "schema",
                "method",
                "operationKey",
                "organizationId",
                "accountSubject",
                "installationId",
                "requestFingerprint",
                "inputSchemaDigest",
                "controlReference",
                "references",
                "receipt",
                "backendSubmissionDigest",
            ]
            .contains(&name.as_str())
        }) {
            return false;
        }
        if ["organizationId", "accountSubject"]
            .into_iter()
            .any(|name| {
                !binding[name].is_null()
                    && !binding[name].as_str().is_some_and(|s| {
                        !s.is_empty() && s.len() <= 256 && !s.chars().any(char::is_control)
                    })
            })
        {
            return false;
        }
        if !binding["installationId"]
            .as_str()
            .is_some_and(|s| !s.is_empty() && s.len() <= 256 && !s.chars().any(char::is_control))
        {
            return false;
        }
        if !binding["controlReference"].is_null()
            && binding["controlReference"]
                .as_str()
                .is_none_or(|s| Uuid::parse_str(s).is_err())
        {
            return false;
        }
        if binding
            .get("backendSubmissionDigest")
            .is_some_and(|digest| !digest.as_str().is_some_and(sha))
        {
            return false;
        }
        if !binding["references"].as_object().is_some_and(|refs| {
            refs.len() <= 18
                && refs.values().all(|value| {
                    value.is_u64()
                        || value
                            .as_str()
                            .is_some_and(|s| s.len() <= 256 && !s.chars().any(char::is_control))
                })
        }) {
            return false;
        }
        if binding["schema"] != SCHEMA
            || binding["method"] != record["method"]
            || binding["requestFingerprint"] != record["digest"]
            || binding["operationKey"]
                .as_str()
                .is_none_or(|key| Uuid::parse_str(key).is_err())
            || !binding["inputSchemaDigest"].as_str().is_some_and(sha)
            || !binding["references"].is_object()
            || serde_json::to_vec(binding).map_or(true, |b| b.len() > 8192)
        {
            return false;
        }
        if !matches!(
            record["stage"].as_str(),
            Some(
                "not_dispatched" | "dispatch_uncertain" | "rejected_before_execution" | "accepted"
            )
        ) {
            return false;
        }
    }
    let catalog: Value =
        match serde_json::from_str(include_str!("../contracts/method-catalog.json")) {
            Ok(value) => value,
            Err(_) => return false,
        };
    if !catalog["methods"].as_array().is_some_and(|methods| {
        methods
            .iter()
            .any(|entry| entry["name"] == record["method"] && entry["mutating"] == true)
    }) {
        return false;
    }
    let bound = record.get("binding").is_some();
    if !bound && record.get("stage").is_some() {
        return false;
    }
    if record["expired"] == true && record.get("result").is_none() {
        return record
            .get("status")
            .is_none_or(|status| status == "completed")
            && (!bound || record["stage"] == "accepted");
    }
    match record["status"].as_str() {
        Some("pending") => {
            record.get("result").is_none()
                && record.get("rejection").is_none()
                && if bound {
                    matches!(
                        record["stage"].as_str(),
                        Some("not_dispatched" | "dispatch_uncertain")
                    )
                } else {
                    fields.len() == 3
                }
        }
        Some("rejected_before_execution") => {
            matches!(
                record["method"].as_str(),
                Some("builder.start" | "editor.start")
            ) && crate::control::known_start_rejection(&record["rejection"])
                && record.get("result").is_none()
                && if bound {
                    record["stage"] == "rejected_before_execution"
                } else {
                    fields.len() == 4
                }
        }
        Some("completed") | None => {
            record["result"].is_object() && (!bound || record["stage"] == "accepted")
        }
        _ => false,
    }
}
fn retirement_supported(record: &Value) -> bool {
    matches!(
        record["method"].as_str(),
        Some(
            "interactions.respond"
                | "interactions.decide"
                | "interactions.draft.delete"
                | "auth.recover"
                | "builder.start"
                | "editor.start"
        )
    ) || (record["binding"]["receipt"].is_object() && known_record(record))
}

fn raw_reconciliation_family(method: &str) -> bool {
    matches!(
        method,
        "builder.start"
            | "editor.start"
            | "interactions.respond"
            | "interactions.decide"
            | "interactions.draft.update"
            | "interactions.draft.delete"
    )
}

/// Raw observations have narrower canonical read adapters than full
/// presentation journals. A descriptor alone never adds an adapter.
pub(crate) fn raw_reconciliation_supported(
    method: &str,
    binding: &Value,
    run: Option<&str>,
) -> bool {
    let bound_authority = ["organizationId", "accountSubject", "installationId"]
        .into_iter()
        .all(|field| {
            binding[field]
                .as_str()
                .is_some_and(|value| !value.is_empty())
        });
    if matches!(method, "builder.start" | "editor.start") {
        // Historical native observations can be checked through their known
        // execution and opaque cache reference under each enrolled owner.
        return run.is_some_and(|id| Uuid::parse_str(id).is_ok())
            && (binding.is_null() || bound_authority);
    }
    let operation = match method {
        "interactions.respond" | "interactions.decide" => "interaction.resolve",
        "interactions.draft.update" => "interactions.draft.update",
        "interactions.draft.delete" => "interactions.draft.delete",
        _ => return false,
    };
    let descriptor = &binding["receipt"];
    bound_authority
        && binding["references"]["requestId"]
            .as_str()
            .is_some_and(|id| Uuid::parse_str(id).is_ok())
        && binding["backendSubmissionDigest"].as_str().is_some_and(sha)
        && descriptor["method"] == "interactions.operations.get"
        && descriptor["params"]["operation"] == operation
        && descriptor["params"]["requestId"] == binding["references"]["requestId"]
        && descriptor["params"]["idempotencyKey"] == binding["operationKey"]
        && descriptor["params"]["submissionFingerprint"] == binding["backendSubmissionDigest"]
}

pub(crate) fn retirement_relative(slot: &str) -> Result<String> {
    ensure!(valid_slot(slot), "UNSAFE_STATE");
    Ok(format!(
        "recovery-evidence/operation-cache-{}.json",
        state::digest(slot.as_bytes())
    ))
}
pub(crate) fn retirement_evidence(
    slot: &str,
    original: &[u8],
    provenance: &Value,
) -> Result<Value> {
    ensure!(
        valid_slot(slot) && provenance.is_object(),
        "MANAGED_WORK_CHANGED"
    );
    let record: Value = serde_json::from_slice(original)?;
    ensure!(
        known_record(&record) && retirement_supported(&record),
        "MANAGED_WORK_CHANGED"
    );
    let evidence = json!({"schema":RETIREMENT,"legacySlot":slot,"originalCache":String::from_utf8(original.to_vec())?,"originalCacheSha256":state::digest(original),"provenance":provenance,"remoteOutcome":"unknown","denyOnly":true,"retiredAt":state::now()});
    verify_retirement(&evidence)?;
    Ok(evidence)
}
pub(crate) fn verify_retirement(evidence: &Value) -> Result<()> {
    let fields = evidence.as_object().context("MANAGED_WORK_CHANGED")?;
    let original = evidence["originalCache"]
        .as_str()
        .context("MANAGED_WORK_CHANGED")?;
    let record: Value = serde_json::from_str(original)?;
    let provenance = &evidence["provenance"];
    for field in ["operationId", "attemptId"] {
        ensure!(
            provenance[field]
                .as_str()
                .is_some_and(|id| Uuid::parse_str(id).is_ok()),
            "MANAGED_WORK_CHANGED"
        );
    }
    for field in [
        "journalSha256",
        "receiptSha256",
        "expectedAssessmentSha256",
        "requestSetSha256",
        "contextSha256",
    ] {
        ensure!(
            provenance[field].as_str().is_some_and(sha),
            "MANAGED_WORK_CHANGED"
        );
    }
    ensure!(
        provenance["installationId"]
            .as_str()
            .is_some_and(|id| !id.is_empty() && id.len() <= 256)
            && provenance["retirementScope"] == "operation-observations"
            && provenance["canonicalObservation"]["remoteOutcome"] == "unknown"
            && provenance["canonicalObservation"]["safeReason"].is_string(),
        "MANAGED_WORK_CHANGED"
    );
    ensure!(
        fields.len() == 8
            && evidence["schema"] == RETIREMENT
            && evidence["legacySlot"].as_str().is_some_and(valid_slot)
            && evidence["originalCacheSha256"] == state::digest(original.as_bytes())
            && evidence["provenance"].is_object()
            && evidence["remoteOutcome"] == "unknown"
            && evidence["denyOnly"] == true
            && evidence["retiredAt"].is_u64()
            && known_record(&record)
            && retirement_supported(&record),
        "MANAGED_WORK_CHANGED"
    );
    Ok(())
}
pub(crate) fn verify_record_retired(dir: &Path, relative: &str, bytes: &[u8]) -> Result<bool> {
    let path = Path::new(relative);
    ensure!(
        path.parent().and_then(Path::to_str) == Some("operations"),
        "UNSAFE_STATE"
    );
    let slot = path
        .file_stem()
        .and_then(|s| s.to_str())
        .context("UNSAFE_STATE")?;
    let relative = retirement_relative(slot)?;
    if !evidence_present(dir, &relative)? {
        return Ok(false);
    }
    let evidence: Value = serde_json::from_slice(&read(dir, &relative)?)?;
    verify_retirement(&evidence)?;
    ensure!(
        evidence["legacySlot"] == slot && evidence["originalCacheSha256"] == state::digest(bytes),
        "MANAGED_WORK_CHANGED"
    );
    Ok(true)
}
pub(crate) fn deny_retired_slot(dir: &Path, slot: &str) -> Result<()> {
    let relative = retirement_relative(slot)?;
    if !evidence_present(dir, &relative)? {
        return Ok(());
    }
    let evidence: Value = serde_json::from_slice(&read(dir, &relative)?)?;
    verify_retirement(&evidence)?;
    ensure!(evidence["legacySlot"] == slot, "MANAGED_WORK_CHANGED");
    bail!("OPERATION_CACHE_RETIRED")
}
fn evidence_present(dir: &Path, relative: &str) -> Result<bool> {
    let parent = dir.join("recovery-evidence");
    match fs::symlink_metadata(&parent) {
        Ok(meta) => ensure!(
            meta.is_dir()
                && !meta.file_type().is_symlink()
                && meta.uid() == unsafe { libc::geteuid() }
                && meta.mode() & 0o077 == 0,
            "UNSAFE_STATE"
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error.into()),
    }
    match fs::symlink_metadata(dir.join(relative)) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}
pub(crate) fn retirement_fence_present(dir: &Path) -> Result<bool> {
    if !evidence_present(dir, "recovery-evidence/.presence")?
        && !dir.join("recovery-evidence").is_dir()
    {
        return Ok(false);
    }
    let mut found = false;
    for entry in fs::read_dir(dir.join("recovery-evidence"))? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if !name.starts_with("operation-cache-") {
            continue;
        }
        let evidence: Value =
            serde_json::from_slice(&read(dir, &format!("recovery-evidence/{name}"))?)?;
        verify_retirement(&evidence)?;
        ensure!(
            retirement_relative(evidence["legacySlot"].as_str().context("UNSAFE_STATE")?)?
                == format!("recovery-evidence/{name}"),
            "MANAGED_WORK_CHANGED"
        );
        found = true;
    }
    Ok(found)
}
pub(crate) fn classify(
    dir: &Path,
    path: &Path,
    terminal_runs: &std::collections::BTreeSet<String>,
) -> Result<Value> {
    let relative = path.strip_prefix(dir)?.to_str().context("UNSAFE_STATE")?;
    ensure!(
        Path::new(relative).parent().and_then(Path::to_str) == Some("operations"),
        "UNSAFE_STATE"
    );
    let slot = path
        .file_stem()
        .and_then(|s| s.to_str())
        .context("UNSAFE_STATE")?;
    ensure!(valid_slot(slot), "UNSAFE_STATE");
    let bytes = read(dir, relative)?;
    let record: Value = serde_json::from_slice(&bytes)?;
    let known = known_record(&record);
    let retired = known && verify_record_retired(dir, relative, &bytes)?;
    let completed = known
        && crate::uninstall_state::operation_cache_completion(dir, path, terminal_runs).is_ok();
    let classification = if retired {
        "local_observation_retired"
    } else if !known {
        "unknown"
    } else if record.get("result").is_some() {
        "completed"
    } else if record["status"] == "rejected_before_execution" {
        "rejected_before_execution"
    } else {
        "pending"
    };
    let dependencies = record
        .pointer("/result/responseRef")
        .and_then(Value::as_str)
        .map(|id| json!([id]))
        .unwrap_or(json!([]));
    let dependencies_valid = crate::uninstall_state::operation_response_dependencies(dir, &record)?;
    let supported = retirement_supported(&record);
    let method = record["method"].as_str().unwrap_or_default();
    let reconciliation_supported = known
        && raw_reconciliation_supported(method, &record["binding"], record["executionId"].as_str());
    let reason = if !known || !supported || !raw_reconciliation_family(method) {
        "unsupported_family"
    } else if !dependencies_valid {
        "response_dependency_missing"
    } else if !reconciliation_supported {
        "missing_binding"
    } else if record.get("result").is_none() {
        "canonical_pending"
    } else {
        "terminal_missing"
    };
    Ok(
        json!({"kind":"operation_cache","legacySlot":slot,"path":relative,"recordDigest":state::digest(&bytes),"record":record,"originalBytes":String::from_utf8(bytes)?,"classification":classification,"binding":record["binding"],"method":record["method"],"recordId":slot,"organizationId":record["binding"]["organizationId"],"accountSubject":record["binding"]["accountSubject"],"installationId":record["binding"]["installationId"],"runId":record["executionId"],"status":record.get("status").cloned().unwrap_or(json!(classification)),"reconciliationSupported":reconciliation_supported,"safeReason":reason,"retirementEligible":known && supported && dependencies_valid && !retired && !completed,"cleanupEligible":(retired && dependencies_valid) || completed,"responseDependencies":dependencies,"resolution":{"state":if retired{"local_observation_retired"}else if completed{"completed"}else{"unresolved"}}}),
    )
}
pub(crate) fn inspect(dir: &Path) -> Result<Vec<Value>> {
    let root = dir.join("operations");
    if !root.try_exists()? {
        return Ok(Vec::new());
    }
    let mut candidates = Vec::new();
    let terminal_runs = crate::uninstall_state::operation_cache_terminal_runs(dir)?;
    for entry in fs::read_dir(root)? {
        candidates.push(classify(dir, &entry?.path(), &terminal_runs)?);
    }
    candidates.sort_by(|a, b| a["path"].as_str().cmp(&b["path"].as_str()));
    Ok(candidates)
}
