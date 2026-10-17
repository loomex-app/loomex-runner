//! Safe, read-only diagnostics. This report never grants deletion authority.
use super::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fmt};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockerCategory {
    PresentationDeliveryPending,
    PresentationDeliveryUnknown,
    FollowPending,
    FollowSupersessionUnverified,
    DomainMutation,
    JobOrTerminalDelivery,
    RecoverySchedule,
    OperationCache,
    ResponseSpool,
    UnsupportedSchema,
    UnsafeState,
    UnreadableState,
    ObservationDrift,
}

/// No paths, SQL, store payloads or underlying exception text cross this boundary.
#[derive(Debug)]
pub struct ManagedStateError {
    pub category: BlockerCategory,
}
impl ManagedStateError {
    pub fn new(category: BlockerCategory) -> Self {
        Self { category }
    }
}
impl fmt::Display for ManagedStateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.category {
            BlockerCategory::UnsafeState => "UNSAFE_STATE",
            _ => PENDING,
        })
    }
}
impl std::error::Error for ManagedStateError {}

pub fn error_category(error: &anyhow::Error) -> BlockerCategory {
    if let Some(error) = error.downcast_ref::<ManagedStateError>() {
        return error.category;
    }
    if error.downcast_ref::<std::io::Error>().is_some() {
        return BlockerCategory::UnreadableState;
    }
    if let Some(error) = error.downcast_ref::<rusqlite::Error>() {
        return match error {
            rusqlite::Error::SqliteFailure(code, _)
                if matches!(
                    code.code,
                    rusqlite::ErrorCode::DatabaseCorrupt
                        | rusqlite::ErrorCode::NotADatabase
                        | rusqlite::ErrorCode::CannotOpen
                        | rusqlite::ErrorCode::SystemIoFailure
                ) =>
            {
                BlockerCategory::UnreadableState
            }
            _ => BlockerCategory::UnsupportedSchema,
        };
    }
    // Legacy internal guard errors are compared only to fixed local codes; raw
    // exceptions are never rendered or serialized by this API.
    if error.to_string() == "UNSAFE_STATE" {
        BlockerCategory::UnsafeState
    } else {
        BlockerCategory::ObservationDrift
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ManagedStateBlocker {
    pub category: BlockerCategory,
    pub count: u64,
    pub references: Vec<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ManagedStateAssessment {
    pub schema: String,
    pub assessment_digest: String,
    pub resolved: bool,
    pub blockers: Vec<ManagedStateBlocker>,
}
impl ManagedStateAssessment {
    pub(super) fn empty() -> Self {
        Self {
            schema: "app.loomex.runner.managed-state-assessment/v1".into(),
            assessment_digest: String::new(),
            resolved: false,
            blockers: Vec::new(),
        }
    }
    fn add(&mut self, category: BlockerCategory, reference: &str) {
        let digest = hex::encode(Sha256::digest(reference.as_bytes()));
        let blocker = match self
            .blockers
            .iter()
            .position(|entry| entry.category == category)
        {
            Some(index) => &mut self.blockers[index],
            None => {
                self.blockers.push(ManagedStateBlocker {
                    category,
                    count: 0,
                    references: Vec::new(),
                });
                self.blockers.last_mut().unwrap()
            }
        };
        blocker.count = blocker.count.saturating_add(1);
        if !blocker.references.contains(&digest) {
            blocker.references.push(digest);
            blocker.references.sort();
            blocker.references.truncate(32);
        }
    }
    fn failure(&mut self, error: &anyhow::Error, reference: &str) {
        self.add(error_category(error), reference);
    }
}

fn fail(category: BlockerCategory) -> anyhow::Error {
    ManagedStateError::new(category).into()
}

// This includes closure dependencies, not merely paths eligible for deletion.
// Capturing whole bytes binds revisions, delivery attempts and scoped records
// without retaining any of their contents in the public report.
pub(super) fn fingerprints(dir: &Path) -> Result<BTreeMap<PathBuf, String>> {
    fn descend(path: &Path, depth: usize, entries: &mut BTreeMap<PathBuf, String>) -> Result<()> {
        ensure!(
            depth <= 8,
            ManagedStateError::new(BlockerCategory::UnsafeState)
        );
        let info = fs::symlink_metadata(path)?;
        if info.is_dir() {
            metadata(path, true)?;
            entries.insert(
                path.into(),
                format!("directory:{}:{}:{}", info.dev(), info.ino(), info.mode()),
            );
            for entry in fs::read_dir(path)? {
                descend(&entry?.path(), depth + 1, entries)?;
            }
        } else {
            entries.insert(path.into(), read_fingerprint(path, None)?);
        }
        Ok(())
    }
    let mut entries = BTreeMap::new();
    for name in ["presentation.sqlite3", "follow.sqlite3", "recovery.sqlite3"] {
        for suffix in ["", "-wal", "-shm", "-journal"] {
            let path = dir.join(format!("{name}{suffix}"));
            if metadata(&path, false)?.is_some() {
                descend(&path, 0, &mut entries)?;
            }
        }
    }
    for name in [
        "jobs",
        "operations",
        "responses",
        "tombstones",
        "workflow-patches",
    ] {
        let path = dir.join(name);
        if metadata(&path, true)?.is_some() {
            descend(&path, 0, &mut entries)?;
        }
    }
    Ok(entries)
}

pub(super) fn schema(connection: &Connection, name: &str) -> Result<u32> {
    let version: u32 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    let tables: BTreeSet<String> = connection
        .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")?
        .query_map([], |row| row.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    let names: &[&str] = match name {
        "presentation.sqlite3" => &[
            "presentation_sessions",
            "presentation_operations",
            "presentation_receipts",
        ],
        "follow.sqlite3" => &[
            "follow_sessions",
            "follow_receipts",
            "follow_continuations",
            "follow_hook_diagnostics",
        ],
        "recovery.sqlite3" => &[
            "recovery_records",
            "recovery_operations",
            "recovery_receipts",
        ],
        _ => return Err(fail(BlockerCategory::UnsupportedSchema)),
    };
    let mut allowed = names
        .iter()
        .map(|name| (*name).to_owned())
        .collect::<BTreeSet<_>>();
    let supported = match name {
        "presentation.sqlite3" => {
            if matches!(version, 2 | 3) {
                allowed.insert("presentation_deliveries".into());
            }
            if version == 3 {
                allowed.extend([
                    "continuation_resolutions".into(),
                    "continuation_observations".into(),
                ]);
            }
            matches!(version, 1..=3)
        }
        "follow.sqlite3" => {
            if version == 2 {
                allowed.extend(
                    [
                        "continuation_resolutions",
                        "continuation_observations",
                        "follow_lineage",
                        "follow_retired_capabilities",
                        "follow_capability_bindings",
                        "follow_generation_transitions",
                    ]
                    .map(str::to_owned),
                );
            }
            matches!(version, 1 | 2)
        }
        "recovery.sqlite3" => version == 1,
        _ => false,
    };
    if !supported || tables != allowed {
        return Err(fail(BlockerCategory::UnsupportedSchema));
    }
    let executable_schema: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type IN ('trigger','view'))",
        [],
        |row| row.get(0),
    )?;
    if executable_schema {
        return Err(fail(BlockerCategory::UnsupportedSchema));
    }
    Ok(version)
}

fn query_blockers(
    connection: &Connection,
    report: &mut ManagedStateAssessment,
    category: BlockerCategory,
    query: &str,
    namespace: &str,
) -> Result<()> {
    for row in connection
        .prepare(query)?
        .query_map([], |row| row.get::<_, String>(0))?
    {
        report.add(category, &format!("{namespace}:{}", row?));
    }
    Ok(())
}

fn inspect_database(
    dir: &Path,
    name: &str,
    report: &mut ManagedStateAssessment,
    terminal_runs: &mut BTreeSet<String>,
) -> Result<()> {
    let family = ["", "-wal", "-shm", "-journal"]
        .into_iter()
        .map(|suffix| dir.join(format!("{name}{suffix}")))
        .filter_map(|path| match metadata(&path, false) {
            Ok(Some(_)) => Some(Ok(path)),
            Ok(None) => None,
            Err(error) => Some(Err(error)),
        })
        .collect::<Result<Vec<_>>>()?;
    if family.is_empty() {
        return Ok(());
    }
    if family[0] != dir.join(name) {
        return Err(fail(BlockerCategory::UnreadableState));
    }
    let snapshot = DatabaseSnapshot::capture(&family)?;
    let connection = Connection::open_with_flags(
        snapshot.directory.join(name),
        OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .map_err(|_| fail(BlockerCategory::UnreadableState))?;
    connection.pragma_update(None, "query_only", true)?;
    let version = schema(&connection, name)?;
    inspect_rows(&connection, name, version, report, terminal_runs)?;
    drop(connection);
    snapshot.verify_sources()?;
    Ok(())
}

// A malformed payload in one row must not hide other pending records. These
// fallback records can explain blockers, but lack a digest and cannot carry proof.
fn fallback_candidates(
    connection: &Connection,
    follow: bool,
    report: &mut ManagedStateAssessment,
) -> Result<Vec<Value>> {
    let query = if follow {
        "SELECT organization_id,account_subject,installation_id,follow_session_id,run_id,lifecycle FROM follow_sessions ORDER BY follow_session_id"
    } else {
        "SELECT organization_id,account_subject,'',identity,'',status FROM presentation_deliveries ORDER BY organization_id,account_subject,identity"
    };
    let mut candidates = Vec::new();
    for (index, row) in connection
        .prepare(query)?
        .query_map([], |row| {
            Ok(serde_json::json!({
                "organizationId":row.get::<_,String>(0)?, "accountSubject":row.get::<_,String>(1)?,
                "installationId":row.get::<_,String>(2)?, "recordId":row.get::<_,String>(3)?,
                "runId":row.get::<_,String>(4)?, "status":row.get::<_,String>(5)?
            }))
        })?
        .enumerate()
    {
        match row {
            Ok(candidate) => candidates.push(candidate),
            Err(_) => report.add(
                BlockerCategory::UnreadableState,
                &format!("candidate:{follow}:{index}"),
            ),
        }
    }
    Ok(candidates)
}

fn observe_terminal(
    connection: &Connection,
    candidate: &Value,
    terminal_runs: &mut BTreeSet<String>,
) -> Result<()> {
    if !candidate["recordDigest"].is_string() {
        return Ok(());
    }
    let observation = crate::continuation_resolution::observation(connection, candidate)?;
    if observation["schemaVersion"] == "loomex.continuation-observation/v1"
        && observation["terminal"] == true
        && terminal_status(&observation)
        && observation["recordDigest"] == candidate["recordDigest"]
        && observation["runId"] == candidate["runId"]
        && observation["observedAt"].as_u64().is_some()
        && observation["observationDigest"]
            .as_str()
            .is_some_and(|digest| {
                digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
            })
    {
        if let Some(run) = candidate["runId"]
            .as_str()
            .filter(|run| uuid::Uuid::parse_str(run).is_ok())
        {
            terminal_runs.insert(run.to_owned());
        }
    }
    Ok(())
}

pub(super) fn inspect_rows(
    connection: &Connection,
    name: &str,
    version: u32,
    report: &mut ManagedStateAssessment,
    terminal_runs: &mut BTreeSet<String>,
) -> Result<()> {
    match name {
        "presentation.sqlite3" => {
            query_blockers(
                connection,
                report,
                BlockerCategory::DomainMutation,
                "SELECT organization_id || ':' || account_subject || ':' || operation_id FROM presentation_operations WHERE status IS NULL OR status!='completed'",
                name,
            )?;
            if version >= 2 {
                let candidates =
                    match crate::presentation::maintenance_delivery_candidates(connection) {
                        Ok(candidates) => candidates,
                        Err(_) => {
                            report.add(
                                BlockerCategory::UnreadableState,
                                "presentation:malformed-record",
                            );
                            fallback_candidates(connection, false, report)?
                        }
                    };
                for candidate in candidates {
                    observe_terminal(connection, &candidate, terminal_runs)?;
                    if matches!(
                        candidate["status"].as_str(),
                        Some("acknowledged" | "rejected")
                    ) || candidate["recordDigest"].is_string()
                        && crate::presentation::maintenance_resolved(connection, &candidate)?
                    {
                        continue;
                    }
                    let category = if matches!(
                        candidate["status"].as_str(),
                        Some("ready" | "sending" | "not_sent")
                    ) {
                        BlockerCategory::PresentationDeliveryPending
                    } else {
                        BlockerCategory::PresentationDeliveryUnknown
                    };
                    report.add(
                        category,
                        &format!(
                            "{name}:{}:{}:{}",
                            candidate["organizationId"],
                            candidate["accountSubject"],
                            candidate["recordId"]
                        ),
                    );
                }
            }
            let mut statement = connection.prepare("SELECT view_session_id,kind,entity_type,status,organization_id,account_subject,state_json FROM presentation_sessions")?;
            for (index, row) in statement
                .query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, String>(5)?,
                        row.get::<_, Vec<u8>>(6)?,
                    ))
                })?
                .enumerate()
            {
                let (id, kind, entity, status, organization, account, bytes) = match row {
                    Ok(row) => row,
                    Err(_) => {
                        report.add(
                            BlockerCategory::UnreadableState,
                            &format!("{name}:malformed-session:{index}"),
                        );
                        continue;
                    }
                };
                let reference = format!("{name}:{organization}:{account}:{id}");
                let state: Value = match serde_json::from_slice(&bytes) {
                    Ok(state) => state,
                    Err(_) => {
                        report.add(BlockerCategory::UnreadableState, &reference);
                        continue;
                    }
                };
                if !state.is_object() {
                    report.add(BlockerCategory::UnreadableState, &reference);
                    continue;
                }
                if !matches!(status.as_str(), "active" | "inactive" | "resolved")
                    || (status == "active"
                        && (!disposable_view_kind(&kind, &entity)
                            || has_pending_view_reference(&state)))
                {
                    report.add(BlockerCategory::DomainMutation, &reference);
                }
                if let Some(delivery) = state
                    .get("continuationDelivery")
                    .filter(|value| !value.is_null())
                {
                    if delivery["schemaVersion"] == 2 {
                        let exists = if version >= 2 && present(&delivery["identity"]) {
                            connection.query_row("SELECT EXISTS(SELECT 1 FROM presentation_deliveries WHERE organization_id=?1 AND account_subject=?2 AND identity=?3)", rusqlite::params![organization, account, delivery["identity"].as_str()], |row| row.get::<_,bool>(0))?
                        } else {
                            false
                        };
                        if !exists {
                            report.add(BlockerCategory::PresentationDeliveryUnknown, &reference);
                        }
                    } else if !matches!(
                        delivery["status"].as_str(),
                        Some("acknowledged" | "rejected")
                    ) {
                        report.add(BlockerCategory::PresentationDeliveryUnknown, &reference);
                    }
                }
            }
        }
        "follow.sqlite3" => {
            let candidates = match crate::follow::maintenance_follow_candidates(connection) {
                Ok(candidates) => candidates,
                Err(_) => {
                    report.add(BlockerCategory::UnreadableState, "follow:malformed-record");
                    fallback_candidates(connection, true, report)?
                }
            };
            let mut unresolved = BTreeSet::new();
            let mut terminal_scopes = BTreeSet::new();
            for candidate in candidates {
                observe_terminal(connection, &candidate, terminal_runs)?;
                let id = candidate["recordId"]
                    .as_str()
                    .ok_or_else(|| fail(BlockerCategory::UnreadableState))?;
                let scope = (
                    candidate["organizationId"]
                        .as_str()
                        .unwrap_or("")
                        .to_owned(),
                    candidate["accountSubject"]
                        .as_str()
                        .unwrap_or("")
                        .to_owned(),
                    candidate["installationId"]
                        .as_str()
                        .unwrap_or("")
                        .to_owned(),
                    candidate["runId"].as_str().unwrap_or("").to_owned(),
                );
                let (lifecycle, action, terminal, handoff, recovery, cleanup) = match connection.query_row(
                    "SELECT lifecycle,required_action,terminal_receipt_json,pending_handoff_json,recovery_json,cleanup_json FROM follow_sessions WHERE follow_session_id=?1", [id], |row| Ok((row.get::<_,String>(0)?,row.get::<_,String>(1)?,row.get::<_,Option<Vec<u8>>>(2)?,row.get::<_,Option<Vec<u8>>>(3)?,row.get::<_,Option<Vec<u8>>>(4)?,row.get::<_,Option<Vec<u8>>>(5)?))) {
                    Ok(row) => row,
                    Err(_) => { report.add(BlockerCategory::UnreadableState, &format!("{name}:malformed-follow:{id}")); unresolved.insert(scope); continue; }
                };
                let valid_terminal = terminal.as_ref().is_some_and(|bytes| {
                    serde_json::from_slice::<Value>(bytes).is_ok_and(|value| {
                        value.is_object()
                            && value["receiptId"]
                                .as_str()
                                .is_some_and(|id| uuid::Uuid::parse_str(id).is_ok())
                            && candidate["generation"].as_u64().is_some_and(|generation| {
                                value["generation"].as_u64() == Some(generation)
                            })
                    })
                });
                let embedded_clear = [recovery, cleanup].into_iter().flatten().all(|bytes| {
                    serde_json::from_slice::<Value>(&bytes).is_ok_and(|value| value.is_null())
                });
                if lifecycle == "terminal"
                    && action == "none"
                    && valid_terminal
                    && embedded_clear
                    && handoff.is_none()
                {
                    terminal_runs.insert(scope.3.clone());
                    terminal_scopes.insert(scope);
                    continue;
                }
                if !embedded_clear {
                    report.add(
                        BlockerCategory::RecoverySchedule,
                        &format!("{name}:{id}:embedded-authority"),
                    );
                }
                if embedded_clear
                    && candidate["recordDigest"].is_string()
                    && crate::follow::maintenance_resolved(connection, &candidate)?
                {
                    continue;
                }
                unresolved.insert(scope);
                report.add(
                    if lifecycle == "superseded" {
                        BlockerCategory::FollowSupersessionUnverified
                    } else {
                        BlockerCategory::FollowPending
                    },
                    &format!("{name}:{id}"),
                );
            }
            let mut statement = connection.prepare("SELECT organization_id,account_subject,installation_id,run_id,receipt FROM follow_continuations")?;
            for row in statement.query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                ))
            })? {
                let (org, account, install, run, receipt) = match row {
                    Ok(row) => row,
                    Err(_) => {
                        report.add(
                            BlockerCategory::UnreadableState,
                            "follow:malformed-continuation",
                        );
                        continue;
                    }
                };
                let scope = (org, account, install, run);
                if terminal_scopes.contains(&scope)
                    || unresolved.contains(&scope)
                    || crate::follow::maintenance_continuation_resolved(
                        connection, &scope.0, &scope.1, &scope.2, &scope.3, &receipt,
                    )?
                {
                    continue;
                }
                report.add(
                    BlockerCategory::FollowPending,
                    &format!(
                        "follow_continuations:{}:{}:{}:{}",
                        scope.0, scope.1, scope.2, receipt
                    ),
                );
            }
        }
        "recovery.sqlite3" => {
            query_blockers(
                connection,
                report,
                BlockerCategory::RecoverySchedule,
                "SELECT recovery_id FROM recovery_records r WHERE registration_state IS NULL OR lifecycle IS NULL OR current_operation_id IS NOT NULL OR pending_request_id IS NOT NULL OR NOT ((registration_state='removed' AND lifecycle='removed') OR (registration_state='not_attempted' AND lifecycle IN ('unchecked','unavailable') AND automation_id IS NULL AND NOT EXISTS(SELECT 1 FROM recovery_operations o WHERE o.recovery_id=r.recovery_id)))",
                name,
            )?;
            query_blockers(
                connection,
                report,
                BlockerCategory::RecoverySchedule,
                "SELECT operation_id FROM recovery_operations WHERE status IS NULL OR status!='succeeded'",
                "recovery_operations",
            )?;
        }
        _ => unreachable!(),
    }
    Ok(())
}

fn native_patch_record_resolved(record: &Value, filename_key: &str) -> Result<bool> {
    let malformed = || ManagedStateError::new(BlockerCategory::UnreadableState);
    let digest = |value: &Value| {
        value.as_str().is_some_and(|value| {
            value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
        })
    };
    ensure!(
        record.is_object()
            && digest(&record["identity"])
            && record["workflowId"]
                .as_str()
                .is_some_and(|id| uuid::Uuid::parse_str(id).is_ok()),
        malformed()
    );
    let fields = record.as_object().unwrap();
    match record["status"].as_str() {
        Some("rejected") => {
            ensure!(
                fields
                    .keys()
                    .all(|key| ["identity", "workflowId", "status", "code"].contains(&key.as_str()))
                    && record["code"]
                        .as_str()
                        .is_some_and(|code| !code.is_empty() && code.len() <= 256),
                malformed()
            );
            Ok(true)
        }
        Some("submitted") => {
            ensure!(
                fields.keys().all(|key| [
                    "identity",
                    "workflowId",
                    "status",
                    "expectedVersion",
                    "expectedDefinitionChecksum",
                    "updateDigest",
                    "payloadDigest",
                    "updateBody",
                    "notesProvided",
                    "expectedNotes",
                    "maintenanceResolution",
                    "nativeAcknowledgement"
                ]
                .contains(&key.as_str())),
                malformed()
            );
            let body = &record["updateBody"];
            let notes = match (record.get("notesProvided"), record.get("expectedNotes")) {
                (None, None) => None,
                (Some(provided), Some(expected)) => Some((
                    provided.as_bool().ok_or_else(malformed)?,
                    expected.as_str().ok_or_else(malformed)?,
                )),
                _ => return Err(malformed().into()),
            };
            let with_notes = notes.is_some_and(|(provided, _)| provided);
            ensure!(
                record["expectedVersion"].as_u64().is_some()
                    && digest(&record["expectedDefinitionChecksum"])
                    && digest(&record["updateDigest"])
                    && digest(&record["payloadDigest"])
                    && body.is_object()
                    && body.as_object().unwrap().len() == if with_notes { 3 } else { 2 }
                    && body["expectedVersion"] == record["expectedVersion"]
                    && body["definition"].is_object()
                    && crate::state::json_digest(&body["definition"]) == record["updateDigest"]
                    && crate::state::json_digest(body) == record["payloadDigest"]
                    && (!with_notes
                        || body["notes"].as_str() == notes.map(|(_, expected)| expected)),
                malformed()
            );
            if crate::control::native_patch_acknowledged(record)? {
                let marker = &record["nativeAcknowledgement"];
                let expected = crate::state::json_digest(
                    &serde_json::json!({"organizationId":marker["organizationId"],"accountSubject":marker["accountSubject"],"idempotencyKey":marker["operationKey"]}),
                );
                ensure!(
                    filename_key == expected,
                    ManagedStateError::new(BlockerCategory::UnsafeState)
                );
                return Ok(true);
            }
            let resolved = crate::presentation::maintenance_native_patch_resolved(record)?;
            if resolved {
                let candidate = &record["maintenanceResolution"]["candidate"];
                let expected = crate::state::json_digest(
                    &serde_json::json!({"organizationId":candidate["organizationId"],"accountSubject":candidate["accountSubject"],"idempotencyKey":candidate["operationKey"]}),
                );
                ensure!(
                    filename_key == expected,
                    ManagedStateError::new(BlockerCategory::UnsafeState)
                );
            }
            Ok(resolved)
        }
        _ => Ok(false),
    }
}

/// Native patch intent remains independent authority even without a UI journal.
/// Only the native owner's definitive rejection or exact canonical receipt closes it.
pub(super) fn inspect_patch_journals(
    dir: &Path,
    paths: &mut Vec<PathBuf>,
    report: &mut ManagedStateAssessment,
) -> Result<()> {
    let root = dir.join("workflow-patches");
    if metadata(&root, true)?.is_none() {
        return Ok(());
    }
    let mut wholly_owned = true;
    for entry in fs::read_dir(&root)? {
        let entry = entry?;
        let name = entry.file_name();
        let known = name
            .to_str()
            .and_then(|name| name.strip_suffix(".json"))
            .is_some_and(|key| key.len() == 64 && key.bytes().all(|byte| byte.is_ascii_hexdigit()));
        if !known {
            wholly_owned = false;
            let category = match metadata(&entry.path(), false) {
                Ok(_) => BlockerCategory::UnsupportedSchema,
                Err(error) => error_category(&error),
            };
            report.add(
                category,
                &format!("workflow-patches:unexpected:{}", name.to_string_lossy()),
            );
            continue;
        }
        let reference = format!("workflow-patches:{}", name.to_string_lossy());
        let filename_key = name
            .to_str()
            .and_then(|name| name.strip_suffix(".json"))
            .ok_or_else(|| ManagedStateError::new(BlockerCategory::UnsafeState))?;
        let qualification = json(&entry.path())
            .and_then(|record| native_patch_record_resolved(&record, filename_key));
        match qualification {
            Ok(true) => paths.push(entry.path()),
            Ok(false) => {
                wholly_owned = false;
                report.add(BlockerCategory::DomainMutation, &reference);
            }
            Err(error) => {
                wholly_owned = false;
                report.add(
                    if error.downcast_ref::<std::io::Error>().is_some()
                        || error.to_string() == "UNSAFE_STATE"
                    {
                        error_category(&error)
                    } else {
                        BlockerCategory::UnreadableState
                    },
                    &reference,
                );
            }
        }
    }
    if wholly_owned {
        paths.push(root);
    }
    Ok(())
}

/// Inspect every independent managed store and dependency. This is diagnostics,
/// never permission to delete; callers still use `inventory_resolved_state`.
pub fn assess_state(dir: &Path) -> Result<ManagedStateAssessment> {
    if !dir.is_absolute()
        || metadata(dir, true)
            .map_err(|error| fail(error_category(&error)))?
            .is_none_or(|info| info.mode() & 0o077 != 0)
    {
        return Err(fail(BlockerCategory::UnsafeState));
    }
    let mut report = ManagedStateAssessment::empty();
    let before = match fingerprints(dir) {
        Ok(before) => Some(before),
        Err(error) => {
            report.failure(&error, "managed-state:initial-observation");
            None
        }
    };
    let mut terminal_runs = BTreeSet::new();
    for name in ["presentation.sqlite3", "follow.sqlite3", "recovery.sqlite3"] {
        if let Err(error) = inspect_database(dir, name, &mut report, &mut terminal_runs) {
            report.failure(&error, name);
        }
    }
    if let Err(error) = inspect_patch_journals(dir, &mut Vec::new(), &mut report) {
        report.failure(&error, "workflow-patches");
    }
    let jobs = dir.join("jobs");
    match metadata(&jobs, true) {
        Ok(Some(_)) => match fs::read_dir(&jobs) {
            Ok(entries) => {
                for entry in entries {
                    match entry {
                        Ok(entry)
                            if entry
                                .file_name()
                                .to_str()
                                .is_some_and(|name| uuid::Uuid::parse_str(name).is_ok()) =>
                        {
                            let result = metadata(&entry.path(), true)
                                .and_then(|_| job(&entry.path(), &mut Vec::new()));
                            if let Err(error) = result {
                                let category = if error.downcast_ref::<std::io::Error>().is_some()
                                    || error.to_string() == "UNSAFE_STATE"
                                {
                                    error_category(&error)
                                } else {
                                    BlockerCategory::JobOrTerminalDelivery
                                };
                                report.add(
                                    category,
                                    &format!("jobs:{}", entry.file_name().to_string_lossy()),
                                );
                            }
                        }
                        Ok(_) => {}
                        Err(error) => report.failure(&error.into(), "jobs:entry"),
                    }
                }
            }
            Err(error) => report.failure(&error.into(), "jobs"),
        },
        Ok(None) => {}
        Err(error) => report.failure(&error, "jobs"),
    }
    for (category, name) in [
        (BlockerCategory::OperationCache, "operations"),
        (BlockerCategory::ResponseSpool, "responses"),
    ] {
        let inspect = || -> Result<Vec<(String, Result<()>)>> {
            let root = dir.join(name);
            if metadata(&root, true)?.is_none() {
                return Ok(Vec::new());
            }
            let mut ids = BTreeSet::new();
            let mut observations = Vec::new();
            for entry in fs::read_dir(&root)? {
                let entry = entry?;
                let filename = entry.file_name();
                let Some(filename) = filename.to_str() else {
                    continue;
                };
                if name == "operations" {
                    if filename.strip_suffix(".json").is_some_and(|key| {
                        uuid::Uuid::parse_str(key).is_ok()
                            || key.len() == 64 && key.bytes().all(|byte| byte.is_ascii_hexdigit())
                    }) {
                        observations.push((
                            filename.into(),
                            operation_cache_record(
                                dir,
                                &entry.path(),
                                &terminal_runs,
                                &mut Vec::new(),
                            ),
                        ));
                    }
                } else if let Some(id) = filename
                    .strip_suffix(".meta.json")
                    .or_else(|| filename.strip_suffix(".sha256"))
                    .or_else(|| filename.strip_suffix(".json"))
                    .filter(|id| uuid::Uuid::parse_str(id).is_ok())
                {
                    ids.insert(id.to_owned());
                }
            }
            for id in ids {
                observations.push((
                    id.clone(),
                    response_spool_record(dir, &root, &id, &terminal_runs, &mut Vec::new()),
                ));
            }
            Ok(observations)
        };
        match inspect() {
            Ok(observations) => {
                for (id, result) in observations {
                    if let Err(error) = result {
                        report.add(
                            if error.downcast_ref::<std::io::Error>().is_some()
                                || error.to_string() == "UNSAFE_STATE"
                            {
                                error_category(&error)
                            } else {
                                category
                            },
                            &format!("{name}:{id}"),
                        );
                    }
                }
            }
            Err(error) => report.failure(&error, name),
        }
    }
    let after = match fingerprints(dir) {
        Ok(after) => Some(after),
        Err(error) => {
            report.failure(&error, "managed-state:final-observation");
            None
        }
    };
    if before != after {
        report.add(BlockerCategory::ObservationDrift, "managed-state:changed");
    }
    let mut hash = Sha256::new();
    hash.update(b"app.loomex.runner.managed-state-assessment/v1\0");
    if let Some(entries) = &before {
        for (path, fingerprint) in entries {
            let relative = path
                .strip_prefix(dir)
                .map_err(|_| fail(BlockerCategory::UnsafeState))?;
            let name = relative.as_os_str().as_encoded_bytes();
            hash.update((name.len() as u64).to_be_bytes());
            hash.update(name);
            hash.update((fingerprint.len() as u64).to_be_bytes());
            hash.update(fingerprint.as_bytes());
        }
    }
    report.blockers.sort_by_key(|entry| entry.category);
    for blocker in &mut report.blockers {
        blocker.references.sort();
    }
    hash.update(serde_json::to_vec(&report.blockers)?);
    report.assessment_digest = hex::encode(hash.finalize());
    report.resolved = report.blockers.is_empty();
    Ok(report)
}

/// Canonical private maintenance projection from exact byte snapshots. Public
/// diagnostics must project these records to bounded safe references.
pub fn maintenance_preview(dir: &Path) -> Result<Vec<Value>> {
    ensure!(
        dir.is_absolute() && metadata(dir, true)?.is_some_and(|info| info.mode() & 0o077 == 0),
        ManagedStateError::new(BlockerCategory::UnsafeState)
    );
    let before = fingerprints(dir)?;
    let mut candidates = Vec::new();
    for name in ["presentation.sqlite3", "follow.sqlite3"] {
        let mut family = Vec::new();
        for suffix in ["", "-wal", "-shm", "-journal"] {
            let path = dir.join(format!("{name}{suffix}"));
            if metadata(&path, false)?.is_some() {
                family.push(path);
            }
        }
        if family.is_empty() {
            continue;
        }
        ensure!(
            family[0] == dir.join(name),
            ManagedStateError::new(BlockerCategory::UnreadableState)
        );
        let snapshot = DatabaseSnapshot::capture(&family)?;
        let connection = Connection::open_with_flags(
            snapshot.directory.join(name),
            OpenFlags::SQLITE_OPEN_READ_ONLY,
        )?;
        let version = schema(&connection, name)?;
        if name == "follow.sqlite3" {
            candidates.extend(crate::follow::maintenance_follow_candidates(&connection)?);
        } else {
            if version >= 2 {
                candidates.extend(crate::presentation::maintenance_delivery_candidates(
                    &connection,
                )?);
            }
            candidates.extend(crate::presentation::maintenance_operation_candidates(
                &connection,
            )?);
        }
        snapshot.verify_sources()?;
    }
    ensure!(
        before == fingerprints(dir)?,
        ManagedStateError::new(BlockerCategory::ObservationDrift)
    );
    Ok(candidates)
}

/// Detect a canonical store migration separately from transient WAL/SHM files.
/// Record/content fences remain the caller's separate prerequisite.
pub fn maintenance_schema_digest(dir: &Path) -> Result<String> {
    ensure!(
        dir.is_absolute() && metadata(dir, true)?.is_some_and(|info| info.mode() & 0o077 == 0),
        ManagedStateError::new(BlockerCategory::UnsafeState)
    );
    let before = fingerprints(dir)?;
    let mut hash = Sha256::new();
    hash.update(b"loomex.managed-schema/v1\0");
    for name in ["presentation.sqlite3", "follow.sqlite3", "recovery.sqlite3"] {
        let mut family = Vec::new();
        for suffix in ["", "-wal", "-shm", "-journal"] {
            let path = dir.join(format!("{name}{suffix}"));
            if metadata(&path, false)?.is_some() {
                family.push(path);
            }
        }
        hash.update(name.as_bytes());
        if family.is_empty() {
            hash.update(b"absent\0");
            continue;
        }
        ensure!(
            family[0] == dir.join(name),
            ManagedStateError::new(BlockerCategory::UnreadableState)
        );
        let snapshot = DatabaseSnapshot::capture(&family)?;
        let connection = Connection::open_with_flags(
            snapshot.directory.join(name),
            OpenFlags::SQLITE_OPEN_READ_ONLY,
        )?;
        hash.update(schema(&connection, name)?.to_be_bytes());
        for sql in connection
            .prepare("SELECT COALESCE(sql,'') FROM sqlite_master ORDER BY type,name")?
            .query_map([], |row| row.get::<_, String>(0))?
        {
            let sql = sql?;
            hash.update((sql.len() as u64).to_be_bytes());
            hash.update(sql.as_bytes());
        }
        snapshot.verify_sources()?;
    }
    ensure!(
        before == fingerprints(dir)?,
        ManagedStateError::new(BlockerCategory::ObservationDrift)
    );
    Ok(hex::encode(hash.finalize()))
}

/// Safe exact acceptance dependencies for immutable review and audit. Payloads,
/// answers, receipt strings and account/host identities are never returned.
pub fn maintenance_acceptance_dependencies(dir: &Path) -> Result<Vec<Value>> {
    ensure!(
        dir.is_absolute() && metadata(dir, true)?.is_some_and(|info| info.mode() & 0o077 == 0),
        ManagedStateError::new(BlockerCategory::UnsafeState)
    );
    let before = fingerprints(dir)?;
    let dependencies = acceptance::dependency_preview(dir)?;
    ensure!(
        before == fingerprints(dir)?,
        ManagedStateError::new(BlockerCategory::ObservationDrift)
    );
    Ok(dependencies)
}
