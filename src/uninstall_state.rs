//! Read-only qualification of runner-owned state for bootstrap uninstall.
//! The caller owns the stopped-daemon/lifecycle guards and captures a durable
//! file inventory before removing any returned path. Unknown files are retained.
use anyhow::{Result, ensure};
use rusqlite::{Connection, OpenFlags};
use serde_json::Value;
use std::{
    collections::BTreeSet,
    fs,
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

const PENDING: &str = "LIFECYCLE_OPERATION_PENDING";

#[path = "managed_acceptance.rs"]
mod acceptance;
#[path = "managed_state_assessment.rs"]
mod assessment;
pub use assessment::{
    BlockerCategory, ManagedStateAssessment, ManagedStateBlocker, ManagedStateError, assess_state,
    error_category, maintenance_acceptance_dependencies, maintenance_preview,
    maintenance_schema_digest,
};

fn metadata(path: &Path, directory: bool) -> Result<Option<fs::Metadata>> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    ensure!(
        !metadata.file_type().is_symlink()
            && metadata.uid() == unsafe { libc::geteuid() }
            && if directory {
                metadata.is_dir() && metadata.mode() & 0o022 == 0
            } else {
                metadata.is_file() && metadata.nlink() == 1 && metadata.mode() & 0o077 == 0
            },
        "UNSAFE_STATE"
    );
    Ok(Some(metadata))
}
fn json(path: &Path) -> Result<Value> {
    ensure!(metadata(path, false)?.is_some(), "{PENDING}");
    serde_json::from_slice(&fs::read(path)?).map_err(|_| anyhow::anyhow!(PENDING))
}
fn present(value: &Value) -> bool {
    value.as_str().is_some_and(|value| !value.is_empty())
}

struct DatabaseSnapshot {
    directory: PathBuf,
    sources: Vec<(PathBuf, String)>,
}
fn read_fingerprint(path: &Path, mut output: Option<&mut fs::File>) -> Result<String> {
    use sha2::{Digest, Sha256};
    let before = metadata(path, false)?.ok_or_else(|| anyhow::anyhow!(PENDING))?;
    let mut file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let opened = file.metadata()?;
    ensure!(
        before.dev() == opened.dev() && before.ino() == opened.ino(),
        "UNSAFE_STATE"
    );
    let mut hash = Sha256::new();
    let mut buffer = vec![0; 262_144];
    loop {
        let size = file.read(&mut buffer)?;
        if size == 0 {
            break;
        }
        hash.update(&buffer[..size]);
        if let Some(output) = output.as_mut() {
            output.write_all(&buffer[..size])?;
        }
    }
    let after = metadata(path, false)?.ok_or_else(|| anyhow::anyhow!(PENDING))?;
    ensure!(
        before.dev() == after.dev()
            && before.ino() == after.ino()
            && before.len() == after.len()
            && before.mode() == after.mode()
            && before.mtime() == after.mtime()
            && before.mtime_nsec() == after.mtime_nsec(),
        "{PENDING}"
    );
    Ok(format!(
        "{}:{}:{}:{}:{}:{}:{}",
        after.dev(),
        after.ino(),
        after.len(),
        after.mode(),
        after.mtime(),
        after.mtime_nsec(),
        hex::encode(hash.finalize())
    ))
}
impl DatabaseSnapshot {
    fn capture(sources: &[PathBuf]) -> Result<Self> {
        let directory =
            std::env::temp_dir().join(format!("loomex-uninstall-read-{}", uuid::Uuid::new_v4()));
        fs::DirBuilder::new().mode(0o700).create(&directory)?;
        let mut snapshot = Self {
            directory,
            sources: Vec::new(),
        };
        for source in sources {
            let name = source
                .file_name()
                .ok_or_else(|| anyhow::anyhow!("UNSAFE_STATE"))?;
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW)
                .open(snapshot.directory.join(name))?;
            let fingerprint = read_fingerprint(source, Some(&mut file))?;
            snapshot.sources.push((source.clone(), fingerprint));
        }
        snapshot.verify_sources()?;
        Ok(snapshot)
    }
    fn verify_sources(&self) -> Result<()> {
        for (source, expected) in &self.sources {
            ensure!(&read_fingerprint(source, None)? == expected, "{PENDING}");
        }
        let main = &self.sources[0].0;
        for suffix in ["-wal", "-shm", "-journal"] {
            let path = PathBuf::from(format!("{}{suffix}", main.to_string_lossy()));
            ensure!(
                metadata(&path, false)?.is_none()
                    || self.sources.iter().any(|(source, _)| source == &path),
                "{PENDING}"
            );
        }
        Ok(())
    }
}
impl Drop for DatabaseSnapshot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

fn disposable_view_kind(kind: &str, entity: &str) -> bool {
    matches!(
        kind,
        "browser"
            | "runs"
            | "monitor"
            | "prepare"
            | "authoring"
            | "interaction"
            | "connection"
            | "organizations"
            | "personas"
            | "personaChat"
    ) && matches!(
        entity,
        "catalog" | "workflow" | "execution" | "personaRole" | "persona" | "personaConversation"
    )
}
fn has_pending_view_reference(value: &Value) -> bool {
    match value {
        Value::Object(object) => object.iter().any(|(key, value)| {
            // Qualified separately against the authoritative delivery journal.
            if key == "continuationDelivery" {
                return false;
            }
            let normalized = key
                .chars()
                .filter(|character| character.is_ascii_alphanumeric())
                .flat_map(char::to_lowercase)
                .collect::<String>();
            let reference = matches!(
                normalized.as_str(),
                "operation"
                    | "operationid"
                    | "operationref"
                    | "pendingoperation"
                    | "pendingoperationid"
                    | "reconciliation"
                    | "preparation"
                    | "preparationid"
                    | "handoffref"
                    | "starthandoff"
                    | "starthandoffref"
                    | "starthandoffticket"
                    | "starthandoffstate"
                    | "responseref"
                    | "followcontinuation"
                    | "continuation"
                    | "continuationreceipt"
                    | "requestid"
                    | "currentrequestid"
                    | "acceptedrequestid"
                    | "buildersessionid"
            );
            (reference && !value.is_null() && value.as_str() != Some(""))
                || has_pending_view_reference(value)
        }),
        Value::Array(values) => values.iter().any(has_pending_view_reference),
        _ => false,
    }
}

fn database(
    dir: &Path,
    name: &str,
    paths: &mut Vec<PathBuf>,
    terminal_runs: &mut BTreeSet<String>,
) -> Result<()> {
    let path = dir.join(name);
    let mut family = Vec::new();
    let exists = metadata(&path, false)?.is_some();
    for suffix in ["", "-wal", "-shm", "-journal"] {
        let candidate = dir.join(format!("{name}{suffix}"));
        if metadata(&candidate, false)?.is_some() {
            family.push(candidate);
        }
    }
    if !exists {
        ensure!(family.is_empty(), "{PENDING}");
        return Ok(());
    }
    // Even READ_ONLY SQLite can update/create its WAL shared-memory file.
    // Inspect a private exact-byte snapshot, including WAL, never an immutable
    // main-only view that could miss unresolved rows committed in that WAL.
    let snapshot = DatabaseSnapshot::capture(&family)?;
    let connection = Connection::open_with_flags(
        snapshot.directory.join(name),
        OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .map_err(|_| anyhow::anyhow!(PENDING))?;
    connection.pragma_update(None, "query_only", true)?;
    let version = assessment::schema(&connection, name)?;
    let mut report = ManagedStateAssessment::empty();
    assessment::inspect_rows(&connection, name, version, &mut report, terminal_runs)?;
    ensure!(report.blockers.is_empty(), "{PENDING}");
    drop(connection);
    snapshot.verify_sources()?;
    paths.extend(family);
    Ok(())
}

fn job(dir: &Path, paths: &mut Vec<PathBuf>) -> Result<bool> {
    let record = json(&dir.join("journal.json"))?;
    ensure!(
        record["phase"] == "acknowledged" && record["acknowledgedAt"].as_u64().is_some(),
        "{PENDING}"
    );
    ensure!(
        record["job"]["id"].as_str() == dir.file_name().and_then(|name| name.to_str()),
        "{PENDING}"
    );
    for field in [
        "stdoutPending",
        "stderrPending",
        "progressPending",
        "publicStatusPending",
        "publicStatusLatest",
    ] {
        ensure!(record[field].is_null(), "{PENDING}");
    }
    let result = &record["result"];
    for stream in ["stdout", "stderr"] {
        if let Some(metadata) = metadata(&dir.join(stream), false)? {
            ensure!(
                present(&result[format!("{stream}ArtifactId")])
                    && record[format!("{stream}Offset")].as_u64() == Some(metadata.len()),
                "{PENDING}"
            );
        }
    }
    if metadata(&dir.join("http-response-body"), false)?.is_some() {
        ensure!(
            result["bodyStorage"] == "artifact"
                && present(&result["bodyRef"]["artifactId"])
                && result["bodyPath"].is_null(),
            "{PENDING}"
        );
    }
    if let Some(declarations) = record["job"]["payload"]["artifactOutputs"].as_array() {
        if !declarations.is_empty() {
            let acknowledgements = result["artifacts"]
                .as_array()
                .ok_or_else(|| anyhow::anyhow!(PENDING))?;
            ensure!(
                acknowledgements.len() == declarations.len()
                    && acknowledgements
                        .iter()
                        .all(|artifact| present(&artifact["artifactId"])),
                "{PENDING}"
            );
        }
    }
    let mut wholly_owned = true;
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if matches!(
            entry.file_name().to_str(),
            Some(
                "journal.json"
                    | "stdout"
                    | "stderr"
                    | "target-status.json"
                    | "provider-schema.json"
                    | "http-response-body"
            )
        ) {
            ensure!(metadata(&path, false)?.is_some(), "UNSAFE_STATE");
            paths.push(path);
        } else {
            wholly_owned = false;
        }
    }
    if wholly_owned {
        paths.push(dir.into());
    }
    Ok(wholly_owned)
}

fn terminal(dir: &Path, run: &str, terminal_runs: &BTreeSet<String>) -> Result<bool> {
    ensure!(uuid::Uuid::parse_str(run).is_ok(), "{PENDING}");
    if terminal_runs.contains(run) {
        return Ok(true);
    }
    let path = dir.join("tombstones").join(format!("{run}.json"));
    if metadata(&path, false)?.is_none() {
        return Ok(false);
    }
    let tombstone = json(&path)?;
    Ok(tombstone["executionId"] == run && tombstone["deletedAt"].as_u64().is_some())
}
fn terminal_status(result: &Value) -> bool {
    matches!(
        result
            .pointer("/execution/status")
            .or_else(|| result.get("status"))
            .and_then(Value::as_str),
        Some("completed" | "failed" | "cancelled" | "canceled" | "deleted" | "succeeded" | "error")
    )
}
fn operation_cache_record(
    dir: &Path,
    path: &Path,
    terminal_runs: &BTreeSet<String>,
    paths: &mut Vec<PathBuf>,
) -> Result<()> {
    let record = json(path)?;
    let method = record["method"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!(PENDING))?;
    let catalog: Value = serde_json::from_str(include_str!("../contracts/method-catalog.json"))?;
    let entry = catalog["methods"]
        .as_array()
        .and_then(|methods| {
            methods
                .iter()
                .find(|entry| entry["name"] == method && entry["mutating"] == true)
        })
        .ok_or_else(|| anyhow::anyhow!(PENDING))?;
    ensure!(
        record["digest"].as_str().is_some_and(
            |digest| digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
        ),
        "{PENDING}"
    );
    ensure!(
        record
            .get("status")
            .is_none_or(|status| status == "completed"),
        "{PENDING}"
    );
    if record["expired"] != true {
        let result = record
            .get("result")
            .filter(|result| !result.is_null())
            .ok_or_else(|| anyhow::anyhow!(PENDING))?;
        let schema = &entry["outputSchema"];
        let success = schema["oneOf"]
            .as_array()
            .and_then(|schemas| schemas.first())
            .unwrap_or(schema);
        // Compatibility authoring outputs intentionally have optional fields.
        // Their empty required[] schema does not retire an active session.
        let authoring_session_method = matches!(
            method,
            "builder.start"
                | "editor.start"
                | "builder.respond"
                | "editor.respond"
                | "builder.finalize"
                | "editor.finalize"
        );
        let produces_execution = authoring_session_method
            || success["required"].as_array().is_some_and(|required| {
                required
                    .iter()
                    .any(|field| field == "execution" || field == "executionId")
            });
        if produces_execution {
            ensure!(
                record["executionId"]
                    .as_str()
                    .is_some_and(|run| uuid::Uuid::parse_str(run).is_ok()),
                "{PENDING}"
            );
        } else {
            crate::control::validate_params(result, success)
                .map_err(|_| anyhow::anyhow!(PENDING))?;
        }
        if result.get("responseRef").is_some() {
            ensure!(acceptance::cache_resolved(dir, &record)?, "{PENDING}");
        }
        if !record["executionId"].is_null() {
            let run = record["executionId"]
                .as_str()
                .filter(|run| uuid::Uuid::parse_str(run).is_ok())
                .ok_or_else(|| anyhow::anyhow!(PENDING))?;
            let result_run = result
                .pointer("/execution/id")
                .or_else(|| result.get("executionId"))
                .or_else(|| result.get("runId"));
            if let Some(identity) = result_run {
                ensure!(identity.as_str() == Some(run), "{PENDING}");
            }
            let terminal_result =
                terminal_status(result) && result_run.and_then(Value::as_str) == Some(run);
            ensure!(
                terminal_result
                    || terminal(dir, run, terminal_runs)?
                    || acceptance::cache_resolved(dir, &record)?,
                "{PENDING}"
            );
        }
    }
    paths.push(path.into());
    Ok(())
}

fn operation_caches(
    dir: &Path,
    terminal_runs: &BTreeSet<String>,
    paths: &mut Vec<PathBuf>,
) -> Result<()> {
    let root = dir.join("operations");
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
            .is_some_and(|key| {
                uuid::Uuid::parse_str(key).is_ok()
                    || (key.len() == 64 && key.bytes().all(|byte| byte.is_ascii_hexdigit()))
            });
        if !known {
            wholly_owned = false;
            continue;
        }
        operation_cache_record(dir, &entry.path(), terminal_runs, paths)?;
    }
    if wholly_owned {
        paths.push(root);
    }
    Ok(())
}
fn response_spool_record(
    dir: &Path,
    root: &Path,
    id: &str,
    terminal_runs: &BTreeSet<String>,
    paths: &mut Vec<PathBuf>,
) -> Result<()> {
    let metadata_path = root.join(format!("{id}.meta.json"));
    let record = json(&metadata_path)?;
    if let Some(run) = record["executionId"].as_str() {
        ensure!(
            terminal(dir, run, terminal_runs)? || acceptance::spool_resolved(dir, id)?,
            "{PENDING}"
        );
    } else {
        ensure!(record["executionId"].is_null(), "{PENDING}");
    }
    let content = root.join(format!("{id}.json"));
    let checksum = root.join(format!("{id}.sha256"));
    ensure!(
        metadata(&content, false)?.is_some() && metadata(&checksum, false)?.is_some(),
        "{PENDING}"
    );
    ensure!(
        read_fingerprint(&content, None)?.rsplit(':').next()
            == Some(fs::read_to_string(&checksum)?.trim()),
        "{PENDING}"
    );
    paths.extend([metadata_path, content, checksum]);
    Ok(())
}
fn response_spools(
    dir: &Path,
    terminal_runs: &BTreeSet<String>,
    paths: &mut Vec<PathBuf>,
) -> Result<()> {
    let root = dir.join("responses");
    if metadata(&root, true)?.is_none() {
        return Ok(());
    }
    let mut ids = BTreeSet::new();
    let mut wholly_owned = true;
    for entry in fs::read_dir(&root)? {
        let name = entry?.file_name();
        let id = name.to_str().and_then(|name| {
            name.strip_suffix(".meta.json")
                .or_else(|| name.strip_suffix(".sha256"))
                .or_else(|| name.strip_suffix(".json"))
        });
        match id.filter(|id| uuid::Uuid::parse_str(id).is_ok()) {
            Some(id) => {
                ids.insert(id.to_owned());
            }
            None => wholly_owned = false,
        }
    }
    for id in ids {
        response_spool_record(dir, &root, &id, terminal_runs, paths)?;
    }
    if wholly_owned {
        paths.push(root);
    }
    Ok(())
}

/// Absolute paths only. A directory is returned only if every direct child is
/// also included, so callers can preserve unknown files and remove deepest first.
pub fn inventory_resolved_state(dir: &Path) -> Result<Vec<PathBuf>> {
    let inventory = || -> Result<Vec<PathBuf>> {
        ensure!(
            dir.is_absolute()
                && metadata(dir, true)?.is_some_and(|metadata| metadata.mode() & 0o077 == 0),
            "UNSAFE_STATE"
        );
        let before = assessment::fingerprints(dir)?;
        let paths = inventory_resolved_state_inner(dir)?;
        ensure!(
            before == assessment::fingerprints(dir)?,
            ManagedStateError::new(BlockerCategory::ObservationDrift)
        );
        Ok(paths)
    };
    inventory().map_err(|error| {
        // Preserve the historical display code while making the reason available
        // without parsing or exposing a database/path exception.
        let category = assess_state(dir)
            .ok()
            .and_then(|assessment| assessment.blockers.first().map(|blocker| blocker.category))
            .unwrap_or_else(|| error_category(&error));
        ManagedStateError::new(category).into()
    })
}

fn inventory_resolved_state_inner(dir: &Path) -> Result<Vec<PathBuf>> {
    ensure!(
        dir.is_absolute()
            && metadata(dir, true)?.is_some_and(|metadata| metadata.mode() & 0o077 == 0),
        "UNSAFE_STATE"
    );
    let mut paths = Vec::new();
    let mut terminal_runs = BTreeSet::new();
    for database_name in ["presentation.sqlite3", "follow.sqlite3", "recovery.sqlite3"] {
        database(dir, database_name, &mut paths, &mut terminal_runs)?;
    }
    let mut patch_report = ManagedStateAssessment::empty();
    assessment::inspect_patch_journals(dir, &mut paths, &mut patch_report)?;
    ensure!(patch_report.blockers.is_empty(), "{PENDING}");
    let jobs = dir.join("jobs");
    if metadata(&jobs, true)?.is_some() {
        let mut wholly_owned = true;
        for entry in fs::read_dir(&jobs)? {
            let entry = entry?;
            if entry
                .file_name()
                .to_str()
                .is_some_and(|name| uuid::Uuid::parse_str(name).is_ok())
            {
                ensure!(metadata(&entry.path(), true)?.is_some(), "UNSAFE_STATE");
                wholly_owned &= job(&entry.path(), &mut paths)?;
            } else {
                wholly_owned = false;
            }
        }
        if wholly_owned {
            paths.push(jobs);
        }
    }
    operation_caches(dir, &terminal_runs, &mut paths)?;
    response_spools(dir, &terminal_runs, &mut paths)?;
    paths.sort();
    Ok(paths)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::{params_from_iter, types::Value as SqlValue};
    use serde_json::json;

    fn stores(dir: &Path) {
        drop(crate::presentation::PresentationStore::open(dir).unwrap());
        drop(crate::follow::FollowStore::open(dir).unwrap());
        drop(crate::recovery::RecoveryStore::open(dir).unwrap());
    }
    // Uses the actual production schema; only the safety-relevant values differ
    // between fixtures. Nullable fields stay NULL rather than inventing authority.
    fn row(connection: &Connection, table: &str, values: &[(&str, SqlValue)]) {
        let parent = match table {
            "presentation_operations" => Some("presentation_sessions"),
            "recovery_operations" => Some("recovery_records"),
            _ => None,
        };
        if let Some(parent) = parent {
            let count: u64 = connection
                .query_row(&format!("SELECT COUNT(*) FROM {parent}"), [], |row| {
                    row.get(0)
                })
                .unwrap();
            if count == 0 {
                if parent == "presentation_sessions" {
                    row(connection, parent, &[("status", text("resolved"))]);
                } else {
                    row(
                        connection,
                        parent,
                        &[
                            ("registration_state", text("removed")),
                            ("lifecycle", text("removed")),
                        ],
                    );
                }
            }
        }
        let columns: Vec<(String, String, bool)> = connection
            .prepare(&format!("PRAGMA table_info({table})"))
            .unwrap()
            .query_map([], |row| {
                Ok((
                    row.get(1)?,
                    row.get(2)?,
                    row.get::<_, i64>(3)? != 0 || row.get::<_, i64>(5)? != 0,
                ))
            })
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        let mut parameters = Vec::new();
        for (column, kind, required) in &columns {
            parameters.push(
                values
                    .iter()
                    .find(|(name, _)| name == column)
                    .map(|(_, value)| value.clone())
                    .unwrap_or_else(|| {
                        if !required {
                            SqlValue::Null
                        } else if kind == "INTEGER" {
                            SqlValue::Integer(0)
                        } else if kind == "BLOB" {
                            SqlValue::Blob(b"{}".to_vec())
                        } else {
                            SqlValue::Text(format!("fixture-{column}"))
                        }
                    }),
            );
        }
        let query = format!(
            "INSERT INTO {table} ({}) VALUES ({})",
            columns
                .iter()
                .map(|(name, _, _)| name.as_str())
                .collect::<Vec<_>>()
                .join(","),
            vec!["?"; columns.len()].join(",")
        );
        connection
            .execute(&query, params_from_iter(parameters))
            .unwrap();
    }
    fn text(value: &str) -> SqlValue {
        SqlValue::Text(value.into())
    }
    fn bytes(value: Value) -> SqlValue {
        SqlValue::Blob(serde_json::to_vec(&value).unwrap())
    }
    fn snapshot(dir: &Path) -> Vec<(String, String)> {
        let mut entries = fs::read_dir(dir)
            .unwrap()
            .map(|entry| {
                let path = entry.unwrap().path();
                (
                    path.file_name().unwrap().to_string_lossy().into_owned(),
                    read_fingerprint(&path, None).unwrap(),
                )
            })
            .collect::<Vec<_>>();
        entries.sort();
        entries
    }

    #[test]
    fn empty_production_databases_are_candidates_without_source_changes() {
        let root = tempfile::tempdir().unwrap();
        stores(root.path());
        let before = snapshot(root.path());
        let paths = inventory_resolved_state(root.path()).unwrap();
        assert_eq!(paths.len(), 3);
        assert_eq!(snapshot(root.path()), before);
        assert!(
            paths
                .iter()
                .all(|path| path.extension().is_some_and(|suffix| suffix == "sqlite3"))
        );
    }

    #[test]
    fn wal_snapshot_reads_pending_rows_without_changing_original_sidecars() {
        let root = tempfile::tempdir().unwrap();
        stores(root.path());
        let connection = Connection::open(root.path().join("presentation.sqlite3")).unwrap();
        connection
            .pragma_update(None, "wal_autocheckpoint", 0)
            .unwrap();
        row(
            &connection,
            "presentation_operations",
            &[("status", text("pending"))],
        );
        let before = snapshot(root.path());
        assert!(before.iter().any(|(name, _)| name.ends_with("-wal")));
        assert_eq!(
            inventory_resolved_state(root.path())
                .unwrap_err()
                .to_string(),
            PENDING
        );
        assert_eq!(snapshot(root.path()), before);
        connection
            .execute("UPDATE presentation_operations SET status='completed'", [])
            .unwrap();
        let before = snapshot(root.path());
        let candidates = inventory_resolved_state(root.path()).unwrap();
        assert!(
            candidates
                .iter()
                .any(|path| path.file_name().unwrap() == "presentation.sqlite3-wal")
        );
        assert_eq!(snapshot(root.path()), before);
    }

    fn browser_view(
        root: &Path,
        entity_type: &str,
        state: Value,
    ) -> (crate::presentation::PresentationStore, Value) {
        let store = crate::presentation::PresentationStore::open(root).unwrap();
        let session = store.dispatch("org", "account", "presentation.sessions.create", &json!({
            "kind":"browser", "entityType":entity_type,
            "entityId":if entity_type == "catalog" { uuid::Uuid::nil() } else { uuid::Uuid::new_v4() },
            "state":state, "idempotencyKey":uuid::Uuid::new_v4(),
        })).unwrap();
        (store, session)
    }

    #[test]
    fn active_browser_views_are_disposable_without_execution_authority() {
        for (entity_type, state) in [
            ("catalog", json!({})),
            (
                "catalog",
                json!({"schemaVersion":1,"screen":"browser","browser":{"arguments":{"limit":20},"history":[],"searchDraft":"search","selectedWorkflowId":null,"selectedVersion":null}}),
            ),
            (
                "workflow",
                json!({"schemaVersion":1,"screen":"detail","display":{"workflowName":"Ordinary detail","version":1},"browser":{"arguments":{"limit":20},"history":[],"searchDraft":"","selectedWorkflowId":uuid::Uuid::new_v4(),"selectedVersion":1},"readingPosition":{"top":10,"left":0},"disclosures":{}}),
            ),
        ] {
            let root = tempfile::tempdir().unwrap();
            let (store, session) = browser_view(root.path(), entity_type, state);
            assert_eq!(session["status"], "active");
            assert!(session["expiresAt"].is_null());
            drop(store);
            let before = snapshot(root.path());
            assert!(
                inventory_resolved_state(root.path())
                    .unwrap()
                    .contains(&root.path().join("presentation.sqlite3"))
            );
            assert_eq!(snapshot(root.path()), before);
        }
    }

    #[test]
    fn active_browser_views_still_block_pending_mutations_and_deliveries() {
        for pending in ["operation", "delivery"] {
            let root = tempfile::tempdir().unwrap();
            let (store, session) = browser_view(root.path(), "catalog", json!({}));
            if pending == "operation" {
                store.dispatch("org", "account", "presentation.sessions.update", &json!({
                    "viewSessionId":session["viewSessionId"],"expectedRevision":0,"state":{},
                    "operation":{"method":"runs.commit","params":{"preparationId":uuid::Uuid::new_v4(),"bindingDigest":"a".repeat(64),"confirmationKey":"fixture-only"},"idempotencyKey":uuid::Uuid::new_v4()},
                    "idempotencyKey":uuid::Uuid::new_v4(),
                })).unwrap();
            } else {
                store.register_delivery("org", "account", &format!("start:{}", uuid::Uuid::new_v4()),
                    &json!({"kind":"start","schemaVersion":"loomex.start-continuation/v1","handoffRef":uuid::Uuid::new_v4()})).unwrap();
            }
            drop(store);
            assert_eq!(
                inventory_resolved_state(root.path())
                    .unwrap_err()
                    .to_string(),
                PENDING
            );
        }
    }

    #[test]
    fn current_delivery_references_use_the_matching_scoped_journal_result() {
        for delivery_org in ["org", "other-org"] {
            let root = tempfile::tempdir().unwrap();
            let handoff = uuid::Uuid::new_v4();
            let identity = format!("start:{handoff}");
            let (store, _) = browser_view(
                root.path(),
                "catalog",
                json!({"continuationDelivery":{
                    "schemaVersion":2,"identity":identity,"purpose":"reviewed_start",
                }}),
            );
            store.register_delivery(delivery_org, "account", &identity,
                &json!({"kind":"start","schemaVersion":"loomex.start-continuation/v1","handoffRef":handoff})).unwrap();
            let attempt = uuid::Uuid::new_v4();
            store.dispatch(delivery_org, "account", "presentation.delivery.begin", &json!({
                "identity":identity,"expectedRevision":0,"attemptId":attempt,"idempotencyKey":uuid::Uuid::new_v4(),
            })).unwrap();
            assert!(inventory_resolved_state(root.path()).is_err());
            store.dispatch(delivery_org, "account", "presentation.delivery.settle", &json!({
                "identity":identity,"expectedRevision":1,"attemptId":attempt,"status":"acknowledged","idempotencyKey":uuid::Uuid::new_v4(),
            })).unwrap();
            drop(store);
            assert_eq!(
                inventory_resolved_state(root.path()).is_ok(),
                delivery_org == "org"
            );
        }
    }

    #[test]
    fn active_browser_views_keep_unqualified_authorizing_references() {
        for state in [
            json!({"preparationId":uuid::Uuid::new_v4()}),
            json!({"startHandoff":{"handoffRef":uuid::Uuid::new_v4(),"lifecycle":"approved"}}),
            json!({"resultPage":{"responseRef":uuid::Uuid::new_v4()}}),
            json!({"operation":{"operationId":uuid::Uuid::new_v4(),"status":"pending"}}),
        ] {
            let root = tempfile::tempdir().unwrap();
            let (store, _) = browser_view(root.path(), "catalog", state);
            drop(store);
            assert!(inventory_resolved_state(root.path()).is_err());
        }
    }

    #[test]
    fn presentation_pending_ambiguous_and_delivery_authority_block_cleanup() {
        for status in ["pending", "ambiguous", "future_status"] {
            let root = tempfile::tempdir().unwrap();
            stores(root.path());
            let connection = Connection::open(root.path().join("presentation.sqlite3")).unwrap();
            row(
                &connection,
                "presentation_operations",
                &[("status", text(status))],
            );
            drop(connection);
            assert_eq!(
                inventory_resolved_state(root.path())
                    .unwrap_err()
                    .to_string(),
                PENDING
            );
        }
        for status in ["ready", "sending", "unknown", "not_sent"] {
            let root = tempfile::tempdir().unwrap();
            stores(root.path());
            let connection = Connection::open(root.path().join("presentation.sqlite3")).unwrap();
            row(
                &connection,
                "presentation_deliveries",
                &[("status", text(status))],
            );
            drop(connection);
            assert_eq!(
                inventory_resolved_state(root.path())
                    .unwrap_err()
                    .to_string(),
                PENDING
            );
        }
    }

    #[test]
    fn retired_views_cannot_hide_legacy_ambiguous_delivery() {
        let root = tempfile::tempdir().unwrap();
        stores(root.path());
        let connection = Connection::open(root.path().join("presentation.sqlite3")).unwrap();
        row(
            &connection,
            "presentation_sessions",
            &[
                ("status", text("resolved")),
                (
                    "state_json",
                    bytes(json!({"continuationDelivery":{"status":"unknown"}})),
                ),
            ],
        );
        drop(connection);
        assert_eq!(
            inventory_resolved_state(root.path())
                .unwrap_err()
                .to_string(),
            PENDING
        );
    }

    #[test]
    fn follow_requires_terminal_receipt_and_no_unobserved_continuations() {
        for lifecycle in [
            "active",
            "suspended",
            "handoff_pending",
            "superseded",
            "terminal",
        ] {
            let root = tempfile::tempdir().unwrap();
            stores(root.path());
            let connection = Connection::open(root.path().join("follow.sqlite3")).unwrap();
            row(
                &connection,
                "follow_sessions",
                &[
                    ("lifecycle", text(lifecycle)),
                    ("required_action", text("none")),
                ],
            );
            drop(connection);
            assert!(inventory_resolved_state(root.path()).is_err());
        }
        let root = tempfile::tempdir().unwrap();
        stores(root.path());
        let connection = Connection::open(root.path().join("follow.sqlite3")).unwrap();
        row(&connection, "follow_continuations", &[]);
        drop(connection);
        assert!(inventory_resolved_state(root.path()).is_err());
    }

    #[test]
    fn terminal_follow_and_removed_schedule_are_resolved() {
        let root = tempfile::tempdir().unwrap();
        stores(root.path());
        let connection = Connection::open(root.path().join("follow.sqlite3")).unwrap();
        row(
            &connection,
            "follow_sessions",
            &[
                ("lifecycle", text("terminal")),
                ("required_action", text("none")),
                (
                    "terminal_receipt_json",
                    bytes(json!({"receiptId":uuid::Uuid::new_v4(),"generation":0})),
                ),
            ],
        );
        drop(connection);
        let connection = Connection::open(root.path().join("recovery.sqlite3")).unwrap();
        row(
            &connection,
            "recovery_records",
            &[
                ("registration_state", text("removed")),
                ("lifecycle", text("removed")),
                ("automation_id", text("removed-host-record")),
            ],
        );
        row(
            &connection,
            "recovery_operations",
            &[("status", text("succeeded"))],
        );
        drop(connection);
        assert_eq!(inventory_resolved_state(root.path()).unwrap().len(), 3);
    }

    #[test]
    fn live_paused_ambiguous_and_inflight_host_bindings_block_cleanup() {
        for (registration, lifecycle) in [
            ("registered", "verified"),
            ("registered", "paused"),
            ("ambiguous", "ambiguous"),
            ("attempt_in_flight", "unchecked"),
        ] {
            let root = tempfile::tempdir().unwrap();
            stores(root.path());
            let connection = Connection::open(root.path().join("recovery.sqlite3")).unwrap();
            row(
                &connection,
                "recovery_records",
                &[
                    ("registration_state", text(registration)),
                    ("lifecycle", text(lifecycle)),
                    ("automation_id", text("exact-host-record")),
                ],
            );
            drop(connection);
            assert!(inventory_resolved_state(root.path()).is_err());
        }
        for status in ["in_flight", "ambiguous"] {
            let root = tempfile::tempdir().unwrap();
            stores(root.path());
            let connection = Connection::open(root.path().join("recovery.sqlite3")).unwrap();
            row(
                &connection,
                "recovery_operations",
                &[("status", text(status))],
            );
            drop(connection);
            assert!(inventory_resolved_state(root.path()).is_err());
        }
    }

    fn job_fixture(root: &Path) -> PathBuf {
        crate::state::private_dir(root).unwrap();
        let id = uuid::Uuid::new_v4().to_string();
        let dir = root.join("jobs").join(&id);
        crate::state::write_json(
            &dir.join("journal.json"),
            &json!({"job":{"id":id,"kind":"command.run","payload":{}},
            "phase":"acknowledged","acknowledgedAt":1,"stdoutOffset":3,"stderrOffset":0,
            "result":{"stdoutArtifactId":"stdout-artifact","stderrArtifactId":"stderr-artifact"}}),
        )
        .unwrap();
        crate::state::atomic_write(&dir.join("stdout"), b"abc").unwrap();
        crate::state::atomic_write(&dir.join("stderr"), b"").unwrap();
        dir
    }
    #[test]
    fn acknowledged_job_candidates_preserve_unknown_children_and_workspace_paths() {
        let root = tempfile::tempdir().unwrap();
        let dir = job_fixture(root.path());
        let resolved = inventory_resolved_state(root.path()).unwrap();
        assert!(resolved.contains(&dir) && resolved.contains(&root.path().join("jobs")));
        crate::state::atomic_write(&dir.join("user-owned-note"), b"preserve").unwrap();
        let preserved = inventory_resolved_state(root.path()).unwrap();
        assert!(!preserved.contains(&dir) && !preserved.contains(&root.path().join("jobs")));
        assert!(
            !preserved
                .iter()
                .any(|path| path.file_name().unwrap() == "user-owned-note")
        );
        assert_eq!(fs::read(dir.join("user-owned-note")).unwrap(), b"preserve");
    }

    #[test]
    fn job_phase_and_pending_artifact_delivery_are_never_discarded() {
        for phase in ["running", "terminal_pending", "delivery_blocked"] {
            let root = tempfile::tempdir().unwrap();
            let dir = job_fixture(root.path());
            let mut record = json(&dir.join("journal.json")).unwrap();
            record["phase"] = json!(phase);
            crate::state::write_json(&dir.join("journal.json"), &record).unwrap();
            assert!(inventory_resolved_state(root.path()).is_err());
        }
        for change in ["pending", "artifact", "offset", "declaration"] {
            let root = tempfile::tempdir().unwrap();
            let dir = job_fixture(root.path());
            let mut record = json(&dir.join("journal.json")).unwrap();
            match change {
                "pending" => record["stdoutPending"] = json!(3),
                "artifact" => record["result"]["stdoutArtifactId"] = Value::Null,
                "offset" => record["stdoutOffset"] = json!(0),
                "declaration" => {
                    record["job"]["payload"]["artifactOutputs"] = json!([{"path":"workspace.txt"}])
                }
                _ => unreachable!(),
            }
            crate::state::write_json(&dir.join("journal.json"), &record).unwrap();
            assert!(inventory_resolved_state(root.path()).is_err());
        }
    }

    #[test]
    fn unresolved_operation_refs_and_response_spools_block() {
        let root = tempfile::tempdir().unwrap();
        crate::state::private_dir(root.path()).unwrap();
        let key = uuid::Uuid::new_v4();
        let path = root.path().join("operations").join(format!("{key}.json"));
        let run = uuid::Uuid::new_v4().to_string();
        crate::state::write_json(&path, &json!({"method":"runs.commit","digest":"a".repeat(64),"executionId":run,"result":{"execution":{"status":"queued"}}})).unwrap();
        assert!(inventory_resolved_state(root.path()).is_err());
        crate::state::write_json(&path, &json!({"method":"runs.commit","digest":"a".repeat(64),"executionId":run,"result":{"execution":{"id":run,"status":"completed"}}})).unwrap();
        assert!(
            inventory_resolved_state(root.path())
                .unwrap()
                .contains(&path)
        );
        let response = uuid::Uuid::new_v4();
        let spool = root.path().join("responses");
        crate::state::write_json(
            &spool.join(format!("{response}.meta.json")),
            &json!({"executionId":run}),
        )
        .unwrap();
        crate::state::atomic_write(&spool.join(format!("{response}.json")), b"{}").unwrap();
        crate::state::atomic_write(
            &spool.join(format!("{response}.sha256")),
            crate::state::digest(b"{}").as_bytes(),
        )
        .unwrap();
        assert!(inventory_resolved_state(root.path()).is_err());
        crate::state::write_json(
            &root.path().join("tombstones").join(format!("{run}.json")),
            &json!({"executionId":run,"deletedAt":1}),
        )
        .unwrap();
        assert!(
            inventory_resolved_state(root.path())
                .unwrap()
                .contains(&spool)
        );
    }

    #[test]
    fn snapshot_rejects_source_drift_and_removes_only_its_private_copy() {
        let root = tempfile::tempdir().unwrap();
        stores(root.path());
        let source = root.path().join("presentation.sqlite3");
        let snapshot = DatabaseSnapshot::capture(std::slice::from_ref(&source)).unwrap();
        let scratch = snapshot.directory.clone();
        assert!(scratch.exists());
        assert_eq!(fs::metadata(&scratch).unwrap().mode() & 0o777, 0o700);
        let connection = Connection::open(&source).unwrap();
        row(
            &connection,
            "presentation_sessions",
            &[("status", text("resolved"))],
        );
        drop(connection);
        assert!(snapshot.verify_sources().is_err());
        drop(snapshot);
        assert!(!scratch.exists());
        assert!(source.exists());
    }

    #[test]
    fn unknown_schemas_and_symlinked_owned_evidence_fail_closed() {
        let root = tempfile::tempdir().unwrap();
        stores(root.path());
        let connection = Connection::open(root.path().join("follow.sqlite3")).unwrap();
        connection
            .execute("CREATE TABLE future_authority (value BLOB)", [])
            .unwrap();
        drop(connection);
        assert!(inventory_resolved_state(root.path()).is_err());
        let root = tempfile::tempdir().unwrap();
        let dir = job_fixture(root.path());
        fs::remove_file(dir.join("stdout")).unwrap();
        std::os::unix::fs::symlink(root.path().join("outside"), dir.join("stdout")).unwrap();
        assert!(inventory_resolved_state(root.path()).is_err());
    }
    fn blocker_count(report: &ManagedStateAssessment, category: BlockerCategory) -> u64 {
        report
            .blockers
            .iter()
            .find(|entry| entry.category == category)
            .map(|entry| entry.count)
            .unwrap_or(0)
    }

    #[test]
    fn assessment_reports_13_ready_and_14_pending_without_stopping_at_first_store() {
        let root = tempfile::tempdir().unwrap();
        stores(root.path());
        let connection = Connection::open(root.path().join("presentation.sqlite3")).unwrap();
        for index in 0..13 {
            row(
                &connection,
                "presentation_deliveries",
                &[
                    ("identity", text(&format!("start:{index}"))),
                    ("status", text("ready")),
                ],
            );
        }
        row(
            &connection,
            "presentation_operations",
            &[("status", text("pending"))],
        );
        drop(connection);
        let connection = Connection::open(root.path().join("follow.sqlite3")).unwrap();
        for index in 0..14 {
            let run = uuid::Uuid::new_v4().to_string();
            row(
                &connection,
                "follow_sessions",
                &[
                    ("follow_session_id", text(&format!("follow-{index}"))),
                    ("host_task_id", text(&format!("private-task-{index}"))),
                    ("run_id", text(&run)),
                    ("lifecycle", text("handoff_pending")),
                    ("required_action", text("none")),
                ],
            );
            row(
                &connection,
                "follow_continuations",
                &[
                    ("receipt", text(&format!("receipt-{index}"))),
                    ("run_id", text(&run)),
                ],
            );
        }
        drop(connection);
        let before = snapshot(root.path());
        let report = assess_state(root.path()).unwrap();
        assert!(!report.resolved);
        assert_eq!(
            blocker_count(&report, BlockerCategory::PresentationDeliveryPending),
            13
        );
        assert_eq!(blocker_count(&report, BlockerCategory::FollowPending), 14);
        assert_eq!(blocker_count(&report, BlockerCategory::DomainMutation), 1);
        assert_eq!(snapshot(root.path()), before);
        assert_eq!(
            report.assessment_digest,
            assess_state(root.path()).unwrap().assessment_digest
        );
        let safe = serde_json::to_string(&report).unwrap();
        for sensitive in [
            "private-task",
            "receipt-",
            "fixture-account",
            "handoff_pending",
            "SELECT",
            root.path().to_str().unwrap(),
        ] {
            assert!(!safe.contains(sensitive));
        }
        assert!(report.blockers.iter().all(|entry| {
            entry.references.len() <= 32
                && entry
                    .references
                    .iter()
                    .all(|reference| reference.len() == 64)
        }));
    }

    #[test]
    fn assessment_collects_all_independent_authority_categories_and_cache_records() {
        let root = tempfile::tempdir().unwrap();
        stores(root.path());
        let connection = Connection::open(root.path().join("presentation.sqlite3")).unwrap();
        row(
            &connection,
            "presentation_deliveries",
            &[("status", text("unknown"))],
        );
        drop(connection);
        let connection = Connection::open(root.path().join("follow.sqlite3")).unwrap();
        row(
            &connection,
            "follow_sessions",
            &[("lifecycle", text("superseded"))],
        );
        drop(connection);
        let connection = Connection::open(root.path().join("recovery.sqlite3")).unwrap();
        row(
            &connection,
            "recovery_records",
            &[
                ("registration_state", text("registered")),
                ("lifecycle", text("paused")),
                ("automation_id", text("secret-host-record")),
            ],
        );
        drop(connection);
        let job = job_fixture(root.path());
        let mut journal = json(&job.join("journal.json")).unwrap();
        journal["phase"] = json!("terminal_pending");
        crate::state::write_json(&job.join("journal.json"), &journal).unwrap();
        for _ in 0..2 {
            crate::state::write_json(&root.path().join("operations").join(format!("{}.json", uuid::Uuid::new_v4())), &json!({"method":"interactions.respond","digest":"a".repeat(64),"executionId":uuid::Uuid::new_v4(),"result":{"answer":"private answer","status":"queued"}})).unwrap();
            crate::state::write_json(
                &root
                    .path()
                    .join("responses")
                    .join(format!("{}.meta.json", uuid::Uuid::new_v4())),
                &json!({"executionId":uuid::Uuid::new_v4()}),
            )
            .unwrap();
        }
        let report = assess_state(root.path()).unwrap();
        for category in [
            BlockerCategory::PresentationDeliveryUnknown,
            BlockerCategory::FollowSupersessionUnverified,
            BlockerCategory::RecoverySchedule,
            BlockerCategory::JobOrTerminalDelivery,
        ] {
            assert_eq!(blocker_count(&report, category), 1, "{category:?}");
        }
        assert_eq!(blocker_count(&report, BlockerCategory::OperationCache), 2);
        assert_eq!(blocker_count(&report, BlockerCategory::ResponseSpool), 2);
        let safe = serde_json::to_string(&report).unwrap();
        assert!(!safe.contains("private answer") && !safe.contains("secret-host-record"));
    }

    #[test]
    fn assessment_wal_is_preserved_and_digest_binds_delivery_fences_and_dependencies() {
        let root = tempfile::tempdir().unwrap();
        stores(root.path());
        let connection = Connection::open(root.path().join("presentation.sqlite3")).unwrap();
        connection
            .pragma_update(None, "wal_autocheckpoint", 0)
            .unwrap();
        row(
            &connection,
            "presentation_deliveries",
            &[("status", text("ready"))],
        );
        let before = snapshot(root.path());
        let first = assess_state(root.path()).unwrap();
        assert_eq!(snapshot(root.path()), before);
        connection.execute("UPDATE presentation_deliveries SET revision=revision+1,attempt_id='second-attempt'", []).unwrap();
        let second = assess_state(root.path()).unwrap();
        assert_ne!(first.assessment_digest, second.assessment_digest);
        connection
            .execute(
                "UPDATE presentation_deliveries SET organization_id='changed-scope'",
                [],
            )
            .unwrap();
        let third = assess_state(root.path()).unwrap();
        assert_ne!(second.assessment_digest, third.assessment_digest);
        let run = uuid::Uuid::new_v4();
        crate::state::write_json(
            &root.path().join("tombstones").join(format!("{run}.json")),
            &json!({"executionId":run,"deletedAt":1}),
        )
        .unwrap();
        assert_ne!(
            third.assessment_digest,
            assess_state(root.path()).unwrap().assessment_digest
        );
    }

    #[test]
    fn assessment_unknown_schema_unsafe_state_and_io_failures_are_typed() {
        let root = tempfile::tempdir().unwrap();
        stores(root.path());
        let connection = Connection::open(root.path().join("follow.sqlite3")).unwrap();
        connection
            .execute("CREATE TABLE future_authority(value BLOB)", [])
            .unwrap();
        drop(connection);
        let report = assess_state(root.path()).unwrap();
        assert_eq!(
            blocker_count(&report, BlockerCategory::UnsupportedSchema),
            1
        );
        let error = inventory_resolved_state(root.path()).unwrap_err();
        assert_eq!(
            error.downcast_ref::<ManagedStateError>().unwrap().category,
            BlockerCategory::UnsupportedSchema
        );
        let root = tempfile::tempdir().unwrap();
        crate::state::private_dir(root.path()).unwrap();
        std::os::unix::fs::symlink(
            root.path().join("outside"),
            root.path().join("follow.sqlite3"),
        )
        .unwrap();
        assert!(
            blocker_count(
                &assess_state(root.path()).unwrap(),
                BlockerCategory::UnsafeState
            ) > 0
        );
        let root = tempfile::tempdir().unwrap();
        crate::state::atomic_write(&root.path().join("follow.sqlite3"), b"not a database").unwrap();
        assert_eq!(
            blocker_count(
                &assess_state(root.path()).unwrap(),
                BlockerCategory::UnreadableState
            ),
            1
        );
    }

    #[test]
    fn assessment_reference_budget_does_not_truncate_blocker_counts() {
        let root = tempfile::tempdir().unwrap();
        crate::state::private_dir(root.path()).unwrap();
        for _ in 0..40 {
            crate::state::write_json(&root.path().join("operations").join(format!("{}.json", uuid::Uuid::new_v4())), &json!({"method":"runs.commit","digest":"a".repeat(64),"executionId":uuid::Uuid::new_v4(),"result":{"status":"queued"}})).unwrap();
        }
        let report = assess_state(root.path()).unwrap();
        let blocker = report
            .blockers
            .iter()
            .find(|entry| entry.category == BlockerCategory::OperationCache)
            .unwrap();
        assert_eq!(blocker.count, 40);
        assert_eq!(blocker.references.len(), 32);
    }
    fn observation_fixture(run: &str, status: &str) -> Value {
        json!({"snapshot":{"execution":{"id":run,"status":status},"hasMoreEvents":false},"terminalResult":{"execution":{"id":run,"status":status},"hasMoreEvents":false}})
    }
    fn request_fixture(candidate: &Value) -> Value {
        let mut request = candidate.clone();
        request["idempotencyKey"] = json!(uuid::Uuid::new_v4());
        request
    }
    fn cache_and_spool_fixture(root: &Path, run: &str) {
        crate::state::write_json(&root.join("operations").join(format!("{}.json", uuid::Uuid::new_v4())), &json!({"method":"interactions.respond","digest":"a".repeat(64),"executionId":run,"result":{"status":"queued"}})).unwrap();
        let id = uuid::Uuid::new_v4();
        let responses = root.join("responses");
        crate::state::write_json(
            &responses.join(format!("{id}.meta.json")),
            &json!({"executionId":run}),
        )
        .unwrap();
        crate::state::atomic_write(&responses.join(format!("{id}.json")), b"{}").unwrap();
        crate::state::atomic_write(
            &responses.join(format!("{id}.sha256")),
            crate::state::digest(b"{}").as_bytes(),
        )
        .unwrap();
    }

    #[test]
    fn canonical_retirement_does_not_grant_cache_or_spool_terminality() {
        let root = tempfile::tempdir().unwrap();
        let store = crate::presentation::PresentationStore::open(root.path()).unwrap();
        let run = uuid::Uuid::new_v4().to_string();
        let identity = format!("follow:{run}:run_started");
        store.register_delivery("org", "account", &identity, &json!({"kind":"follow","schemaVersion":"loomex.follow-session.continuation/v1","runId":run,"receipt":"fixture-receipt-authority","trigger":"run_commit"})).unwrap();
        let candidate = store.maintenance_candidates().unwrap().remove(0);
        store
            .maintenance_reconcile(
                &request_fixture(&candidate),
                &observation_fixture(&run, "running"),
            )
            .unwrap();
        store
            .maintenance_retire(&request_fixture(&candidate))
            .unwrap();
        cache_and_spool_fixture(root.path(), &run);
        let running = assess_state(root.path()).unwrap();
        assert_eq!(
            blocker_count(&running, BlockerCategory::PresentationDeliveryPending),
            0
        );
        assert_eq!(blocker_count(&running, BlockerCategory::OperationCache), 1);
        assert_eq!(blocker_count(&running, BlockerCategory::ResponseSpool), 1);
        assert!(inventory_resolved_state(root.path()).is_err());
        store
            .maintenance_reconcile(
                &request_fixture(&candidate),
                &observation_fixture(&run, "completed"),
            )
            .unwrap();
        let terminal = assess_state(root.path()).unwrap();
        assert!(terminal.resolved, "{:?}", terminal.blockers);
        assert!(inventory_resolved_state(root.path()).is_ok());
        assert_ne!(running.assessment_digest, terminal.assessment_digest);
        drop(store);
        let connection = Connection::open(root.path().join("presentation.sqlite3")).unwrap();
        connection
            .execute("UPDATE presentation_deliveries SET revision=revision+1", [])
            .unwrap();
        drop(connection);
        let changed = assess_state(root.path()).unwrap();
        assert_eq!(
            blocker_count(&changed, BlockerCategory::PresentationDeliveryPending),
            1
        );
        assert_eq!(blocker_count(&changed, BlockerCategory::OperationCache), 1);
        assert_eq!(blocker_count(&changed, BlockerCategory::ResponseSpool), 1);
    }

    #[test]
    fn follow_retirement_requires_exact_capability_closure_for_continuation_rows() {
        let root = tempfile::tempdir().unwrap();
        let store = crate::follow::FollowStore::open(root.path()).unwrap();
        let run = uuid::Uuid::new_v4().to_string();
        let receipt = store
            .issue_continuation("org", "account", "install", &run, "run_commit", None)
            .unwrap();
        store
            .activate_ui_handoff("org", "account", "install", &run, &receipt, None)
            .unwrap();
        let candidate = store.maintenance_candidates().unwrap().remove(0);
        store
            .maintenance_reconcile(
                &request_fixture(&candidate),
                &observation_fixture(&run, "running"),
            )
            .unwrap();
        store
            .maintenance_retire(&request_fixture(&candidate))
            .unwrap();
        assert!(assess_state(root.path()).unwrap().resolved);
        assert!(inventory_resolved_state(root.path()).is_ok());
        drop(store);
        let connection = Connection::open(root.path().join("follow.sqlite3")).unwrap();
        connection
            .execute(
                "UPDATE follow_retired_capabilities SET receipt='different-capability'",
                [],
            )
            .unwrap();
        drop(connection);
        assert_eq!(
            blocker_count(
                &assess_state(root.path()).unwrap(),
                BlockerCategory::FollowPending
            ),
            1
        );
        assert!(inventory_resolved_state(root.path()).is_err());
    }

    #[test]
    fn supersession_requires_canonical_lineage_generation_and_exact_terminal_receipt() {
        let root = tempfile::tempdir().unwrap();
        stores(root.path());
        let connection = Connection::open(root.path().join("follow.sqlite3")).unwrap();
        let predecessor = uuid::Uuid::new_v4().to_string();
        let successor = uuid::Uuid::new_v4().to_string();
        let run = uuid::Uuid::new_v4().to_string();
        let terminal = json!({"kind":"terminal","receiptId":uuid::Uuid::new_v4(),"generation":2});
        row(
            &connection,
            "follow_sessions",
            &[
                ("follow_session_id", text(&predecessor)),
                ("host_task_id", text("predecessor-task")),
                ("run_id", text(&run)),
                ("generation", SqlValue::Integer(1)),
                ("lifecycle", text("superseded")),
                ("required_action", text("none")),
            ],
        );
        row(
            &connection,
            "follow_sessions",
            &[
                ("follow_session_id", text(&successor)),
                ("host_task_id", text("successor-task")),
                ("run_id", text(&run)),
                ("generation", SqlValue::Integer(2)),
                ("lifecycle", text("terminal")),
                ("required_action", text("none")),
                ("terminal_receipt_json", bytes(terminal.clone())),
            ],
        );
        connection
            .execute(
                "INSERT INTO follow_lineage VALUES(?1,?2,?3,?4,1,?5,2)",
                rusqlite::params![
                    "fixture-organization_id",
                    "fixture-account_subject",
                    "fixture-installation_id",
                    predecessor,
                    successor
                ],
            )
            .unwrap();
        let candidate = crate::follow::maintenance_follow_candidates(&connection)
            .unwrap()
            .into_iter()
            .find(|value| value["recordId"] == predecessor)
            .unwrap();
        // A fixture receipt issued through the canonical closure writer remains
        // usable only while its exact independently stored successor proof exists.
        crate::continuation_resolution::close(
            &connection,
            &candidate,
            &request_fixture(&candidate),
            "superseded_by_verified_successor",
            json!({"successorId":successor,"successorGeneration":2,"terminalReceipt":terminal}),
        )
        .unwrap();
        assert!(assess_state(root.path()).unwrap().resolved);
        assert!(inventory_resolved_state(root.path()).is_ok());
        connection
            .execute("UPDATE follow_lineage SET successor_generation=3", [])
            .unwrap();
        assert_eq!(
            blocker_count(
                &assess_state(root.path()).unwrap(),
                BlockerCategory::FollowSupersessionUnverified
            ),
            1
        );
        assert!(inventory_resolved_state(root.path()).is_err());
    }

    #[test]
    fn malformed_record_does_not_hide_other_blockers_in_the_same_store() {
        let root = tempfile::tempdir().unwrap();
        stores(root.path());
        let connection = Connection::open(root.path().join("presentation.sqlite3")).unwrap();
        row(
            &connection,
            "presentation_deliveries",
            &[
                ("identity", text("malformed")),
                ("status", text("ready")),
                ("continuation_json", SqlValue::Blob(b"{".to_vec())),
            ],
        );
        row(
            &connection,
            "presentation_deliveries",
            &[("identity", text("unknown")), ("status", text("unknown"))],
        );
        drop(connection);
        let report = assess_state(root.path()).unwrap();
        assert_eq!(blocker_count(&report, BlockerCategory::UnreadableState), 1);
        assert_eq!(
            blocker_count(&report, BlockerCategory::PresentationDeliveryPending),
            1
        );
        assert_eq!(
            blocker_count(&report, BlockerCategory::PresentationDeliveryUnknown),
            1
        );
        assert!(inventory_resolved_state(root.path()).is_err());
    }

    #[test]
    fn dependency_fingerprints_detect_added_sidecars_and_changed_tombstones() {
        let root = tempfile::tempdir().unwrap();
        stores(root.path());
        let before = assessment::fingerprints(root.path()).unwrap();
        crate::state::atomic_write(
            &root.path().join("presentation.sqlite3-journal"),
            b"new journal",
        )
        .unwrap();
        assert_ne!(before, assessment::fingerprints(root.path()).unwrap());
        fs::remove_file(root.path().join("presentation.sqlite3-journal")).unwrap();
        let run = uuid::Uuid::new_v4().to_string();
        let tombstone = root.path().join("tombstones").join(format!("{run}.json"));
        crate::state::write_json(&tombstone, &json!({"executionId":run,"deletedAt":1})).unwrap();
        let first = assessment::fingerprints(root.path()).unwrap();
        crate::state::write_json(&tombstone, &json!({"executionId":run,"deletedAt":2})).unwrap();
        assert_ne!(first, assessment::fingerprints(root.path()).unwrap());
    }
    #[test]
    fn exact_retired_acceptance_closes_only_its_known_cache_and_spool_dependencies() {
        let root = tempfile::tempdir().unwrap();
        let store = crate::follow::FollowStore::open(root.path()).unwrap();
        let run = uuid::Uuid::new_v4().to_string();
        let request = uuid::Uuid::new_v4().to_string();
        let receipt = store
            .issue_continuation(
                "org",
                "account",
                "install",
                &run,
                "accepted_interaction",
                Some(&request),
            )
            .unwrap();
        store
            .activate_ui_handoff("org", "account", "install", &run, &receipt, Some(&request))
            .unwrap();
        let result = json!({"executionId":run,"executionStatus":"running","requestId":request,"requestStatus":"resolved","error":null,"details":{"followContinuation":{"schemaVersion":"loomex.follow-session.continuation/v1","runId":run,"receipt":receipt,"trigger":"accepted_interaction","requestId":request}}});
        let operation = root
            .path()
            .join("operations")
            .join(format!("{}.json", uuid::Uuid::new_v4()));
        crate::state::write_json(&operation, &json!({"method":"interactions.respond","digest":"a".repeat(64),"executionId":run,"result":result})).unwrap();
        let spool = uuid::Uuid::new_v4().to_string();
        let content = serde_json::to_vec(&result).unwrap();
        let responses = root.path().join("responses");
        crate::state::atomic_write(&responses.join(format!("{spool}.json")), &content).unwrap();
        crate::state::atomic_write(
            &responses.join(format!("{spool}.sha256")),
            crate::state::digest(&content).as_bytes(),
        )
        .unwrap();
        crate::state::write_json(&responses.join(format!("{spool}.meta.json")), &json!({"executionId":run,"ownerScope":{"organizationId":"org","accountSubject":"account"}})).unwrap();
        let spooled_operation = root
            .path()
            .join("operations")
            .join(format!("{}.json", uuid::Uuid::new_v4()));
        crate::state::write_json(&spooled_operation, &json!({"method":"interactions.respond","digest":"b".repeat(64),"executionId":run,"result":{"responseRef":spool,"sizeBytes":content.len(),"checksumSha256":crate::state::digest(&content)}})).unwrap();
        let before = assess_state(root.path()).unwrap();
        assert_eq!(blocker_count(&before, BlockerCategory::OperationCache), 2);
        assert_eq!(blocker_count(&before, BlockerCategory::ResponseSpool), 1);
        // Expire the actual issuance before invoking production sweep.
        let connection = Connection::open(root.path().join("follow.sqlite3")).unwrap();
        connection
            .execute("UPDATE follow_continuations SET expires_at=0", [])
            .unwrap();
        drop(connection);
        store.sweep(crate::state::now()).unwrap();
        let connection = Connection::open(root.path().join("follow.sqlite3")).unwrap();
        let surviving: u64 = connection
            .query_row("SELECT COUNT(*) FROM follow_continuations", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(surviving, 1); // Exact identity survives while consumption is expired.
        drop(connection);
        assert!(
            store
                .issued_continuation(
                    "org",
                    "account",
                    "install",
                    &run,
                    "accepted_interaction",
                    Some(&request)
                )
                .unwrap()
                .is_none()
        );
        let dependencies_before = maintenance_acceptance_dependencies(root.path()).unwrap();
        assert_eq!(dependencies_before.len(), 2);
        assert!(
            dependencies_before
                .iter()
                .all(|dependency| dependency["retirementEligible"] == true
                    && dependency["closureResolved"] == false)
        );
        let safe = serde_json::to_string(&dependencies_before).unwrap();
        assert!(!safe.contains(&receipt) && !safe.contains(&run) && !safe.contains(&request));
        let candidate = store.maintenance_candidates().unwrap().remove(0);
        store
            .maintenance_reconcile(
                &request_fixture(&candidate),
                &observation_fixture(&run, "running"),
            )
            .unwrap();
        store
            .maintenance_retire(&request_fixture(&candidate))
            .unwrap();
        let after = assess_state(root.path()).unwrap();
        assert!(after.resolved, "{:?}", after.blockers);
        assert!(inventory_resolved_state(root.path()).is_ok());
        let dependencies_after = maintenance_acceptance_dependencies(root.path()).unwrap();
        assert_eq!(dependencies_after.len(), 2);
        assert!(
            dependencies_after
                .iter()
                .all(|dependency| dependency["closureResolved"] == true)
        );
        for (before, after) in dependencies_before.iter().zip(&dependencies_after) {
            assert_eq!(before["cacheDigest"], after["cacheDigest"]);
            assert_eq!(before["scopeReference"], after["scopeReference"]);
        }
        // A different accepted mutation on the same active run has no exact
        // closure and must remain visible after the continuation is retired.
        let unrelated = root
            .path()
            .join("operations")
            .join(format!("{}.json", uuid::Uuid::new_v4()));
        crate::state::write_json(&unrelated, &json!({"method":"builder.start","digest":"c".repeat(64),"executionId":run,"result":{"executionId":run,"status":"queued"}})).unwrap();
        assert_eq!(
            blocker_count(
                &assess_state(root.path()).unwrap(),
                BlockerCategory::OperationCache
            ),
            1
        );
        assert!(inventory_resolved_state(root.path()).is_err());
        fs::remove_file(&unrelated).unwrap();
        let mut wrong_trigger = json(&operation).unwrap();
        wrong_trigger["result"]["details"]["followContinuation"]["trigger"] = json!("run_commit");
        crate::state::write_json(&operation, &wrong_trigger).unwrap();
        assert_eq!(
            blocker_count(
                &assess_state(root.path()).unwrap(),
                BlockerCategory::OperationCache
            ),
            1
        );
        crate::state::write_json(&operation, &json!({"method":"interactions.respond","digest":"a".repeat(64),"executionId":run,"result":result})).unwrap();
        let mut forged = json(&operation).unwrap();
        forged["result"]["details"]["followContinuation"]["receipt"] =
            json!("different-accepted-receipt");
        crate::state::write_json(&operation, &forged).unwrap();
        assert_eq!(
            blocker_count(
                &assess_state(root.path()).unwrap(),
                BlockerCategory::OperationCache
            ),
            1
        );
        crate::state::write_json(&responses.join(format!("{spool}.meta.json")), &json!({"executionId":run,"ownerScope":{"organizationId":"different-org","accountSubject":"account"}})).unwrap();
        let wrong_scope = assess_state(root.path()).unwrap();
        assert_eq!(
            blocker_count(&wrong_scope, BlockerCategory::OperationCache),
            2
        );
        assert_eq!(
            blocker_count(&wrong_scope, BlockerCategory::ResponseSpool),
            1
        );
    }

    #[test]
    fn maintenance_preview_is_read_only_and_io_errors_have_a_safe_category() {
        let root = tempfile::tempdir().unwrap();
        let store = crate::follow::FollowStore::open(root.path()).unwrap();
        let run = uuid::Uuid::new_v4().to_string();
        let receipt = store
            .issue_continuation("org", "account", "install", &run, "run_commit", None)
            .unwrap();
        store
            .activate_ui_handoff("org", "account", "install", &run, &receipt, None)
            .unwrap();
        let before = assessment::fingerprints(root.path()).unwrap();
        let preview = maintenance_preview(root.path()).unwrap();
        assert_eq!(preview.len(), 1);
        assert_eq!(before, assessment::fingerprints(root.path()).unwrap());
        let serialized = serde_json::to_string(&preview).unwrap();
        assert!(!serialized.contains("hostSessionId") && !serialized.contains("hostTaskId"));
        let io = anyhow::Error::new(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "private filesystem detail",
        ));
        assert_eq!(error_category(&io), BlockerCategory::UnreadableState);
        let safe = ManagedStateError::new(error_category(&io));
        assert_eq!(safe.to_string(), PENDING);
    }
    #[test]
    fn schema_digest_ignores_data_and_sidecars_but_detects_legacy_store_migration() {
        let root = tempfile::tempdir().unwrap();
        stores(root.path());
        let original = maintenance_schema_digest(root.path()).unwrap();
        let connection = Connection::open(root.path().join("presentation.sqlite3")).unwrap();
        connection
            .pragma_update(None, "wal_autocheckpoint", 0)
            .unwrap();
        row(
            &connection,
            "presentation_deliveries",
            &[("status", text("ready"))],
        );
        assert_eq!(original, maintenance_schema_digest(root.path()).unwrap());
        drop(connection);
        let connection = Connection::open(root.path().join("follow.sqlite3")).unwrap();
        connection.execute_batch("DROP TABLE continuation_resolutions; DROP TABLE continuation_observations; DROP TABLE follow_lineage; DROP TABLE follow_retired_capabilities; DROP TABLE follow_capability_bindings; DROP TABLE follow_generation_transitions; PRAGMA user_version=1;").unwrap();
        drop(connection);
        let legacy = maintenance_schema_digest(root.path()).unwrap();
        let store = crate::follow::FollowStore::open(root.path()).unwrap();
        assert_ne!(legacy, maintenance_schema_digest(root.path()).unwrap());
        drop(store);
    }
    #[test]
    fn malformed_or_stale_terminal_receipts_cannot_qualify_queued_cache() {
        for receipt in [
            Value::Null,
            json!([]),
            json!("terminal"),
            json!({"receiptId":uuid::Uuid::new_v4(),"generation":1}),
            json!({"receiptId":"invalid","generation":2}),
        ] {
            let root = tempfile::tempdir().unwrap();
            stores(root.path());
            let run = uuid::Uuid::new_v4().to_string();
            let connection = Connection::open(root.path().join("follow.sqlite3")).unwrap();
            row(
                &connection,
                "follow_sessions",
                &[
                    ("run_id", text(&run)),
                    ("generation", SqlValue::Integer(2)),
                    ("lifecycle", text("terminal")),
                    ("required_action", text("none")),
                    ("terminal_receipt_json", bytes(receipt)),
                ],
            );
            drop(connection);
            crate::state::write_json(&root.path().join("operations").join(format!("{}.json", uuid::Uuid::new_v4())), &json!({"method":"builder.start","digest":"a".repeat(64),"executionId":run,"result":{"executionId":run,"status":"queued"}})).unwrap();
            let report = assess_state(root.path()).unwrap();
            assert_eq!(blocker_count(&report, BlockerCategory::FollowPending), 1);
            assert_eq!(blocker_count(&report, BlockerCategory::OperationCache), 1);
            assert!(!report.resolved);
            assert!(inventory_resolved_state(root.path()).is_err());
        }
    }

    #[test]
    fn malformed_sqlite_row_types_do_not_hide_later_pending_rows() {
        let root = tempfile::tempdir().unwrap();
        stores(root.path());
        let connection = Connection::open(root.path().join("presentation.sqlite3")).unwrap();
        row(
            &connection,
            "presentation_sessions",
            &[
                ("view_session_id", text("a-malformed")),
                ("kind", text("browser")),
                ("entity_type", text("catalog")),
                ("status", text("active")),
                ("state_json", text("{}")),
            ],
        );
        row(
            &connection,
            "presentation_sessions",
            &[
                ("view_session_id", text("z-pending")),
                ("kind", text("interaction")),
                ("entity_type", text("request")),
                ("status", text("active")),
                ("state_json", bytes(json!({"requestId":"private-request"}))),
            ],
        );
        row(
            &connection,
            "presentation_deliveries",
            &[
                ("identity", text("bad-type")),
                ("status", text("ready")),
                ("continuation_json", text("{}")),
            ],
        );
        row(
            &connection,
            "presentation_deliveries",
            &[
                ("identity", text("later-delivery")),
                ("status", text("unknown")),
            ],
        );
        drop(connection);
        let connection = Connection::open(root.path().join("follow.sqlite3")).unwrap();
        row(
            &connection,
            "follow_sessions",
            &[
                ("follow_session_id", text("bad-follow")),
                ("host_task_id", text("bad-type")),
                ("lifecycle", text("terminal")),
                ("required_action", text("none")),
                ("terminal_receipt_json", text("{}")),
            ],
        );
        row(
            &connection,
            "follow_sessions",
            &[
                ("follow_session_id", text("later-follow")),
                ("host_task_id", text("later-type")),
                ("lifecycle", text("handoff_pending")),
                ("required_action", text("none")),
            ],
        );
        drop(connection);
        let report = assess_state(root.path()).unwrap();
        assert_eq!(blocker_count(&report, BlockerCategory::DomainMutation), 1);
        assert_eq!(
            blocker_count(&report, BlockerCategory::PresentationDeliveryPending),
            1
        );
        assert_eq!(
            blocker_count(&report, BlockerCategory::PresentationDeliveryUnknown),
            1
        );
        assert_eq!(blocker_count(&report, BlockerCategory::FollowPending), 1);
        assert!(blocker_count(&report, BlockerCategory::UnreadableState) >= 3);
        assert_eq!(
            blocker_count(&report, BlockerCategory::UnsupportedSchema),
            0
        );
        let safe = serde_json::to_string(&report).unwrap();
        assert!(
            !safe.contains("private-request")
                && !safe.contains("bad-follow")
                && !safe.contains("bad-type")
        );
        assert!(inventory_resolved_state(root.path()).is_err());
    }
    #[test]
    fn unknown_or_unbound_cached_mutations_and_mismatched_terminal_identity_block() {
        for record in [
            json!({"method":"builder.start","digest":"a".repeat(64),"executionId":null,"result":{"status":"queued"}}),
            json!({"method":"builder.start","digest":"a".repeat(64),"executionId":"not-a-run","result":{"status":"queued"}}),
            json!({"method":"future.mutate","digest":"a".repeat(64),"executionId":null,"result":{"status":"completed"}}),
            json!({"method":"runs.commit","digest":"a".repeat(64),"executionId":uuid::Uuid::new_v4(),"result":{"execution":{"id":uuid::Uuid::new_v4(),"status":"completed"}}}),
            json!({"method":"runs.commit","digest":"a".repeat(64),"executionId":uuid::Uuid::new_v4(),"result":{"status":"completed"}}),
        ] {
            let root = tempfile::tempdir().unwrap();
            crate::state::private_dir(root.path()).unwrap();
            crate::state::write_json(
                &root
                    .path()
                    .join("operations")
                    .join(format!("{}.json", uuid::Uuid::new_v4())),
                &record,
            )
            .unwrap();
            let report = assess_state(root.path()).unwrap();
            assert_eq!(blocker_count(&report, BlockerCategory::OperationCache), 1);
            assert!(inventory_resolved_state(root.path()).is_err());
        }
        let root = tempfile::tempdir().unwrap();
        crate::state::private_dir(root.path()).unwrap();
        crate::state::write_json(&root.path().join("operations").join(format!("{}.json", uuid::Uuid::new_v4())), &json!({"method":"interactions.draft.delete","digest":"a".repeat(64),"executionId":null,"result":{"requestId":uuid::Uuid::new_v4(),"deleted":true,"revision":1}})).unwrap();
        assert!(assess_state(root.path()).unwrap().resolved);
        assert!(inventory_resolved_state(root.path()).is_ok());
    }
    #[test]
    fn pending_compatibility_authoring_caches_cannot_hide_in_optional_output_fields() {
        for method in [
            "builder.respond",
            "editor.respond",
            "builder.finalize",
            "editor.finalize",
        ] {
            let root = tempfile::tempdir().unwrap();
            crate::state::private_dir(root.path()).unwrap();
            let record = json!({"method":method,"digest":"a".repeat(64),"executionId":null,"result":{
                "builderSession":{"id":uuid::Uuid::new_v4(),"status":"waiting_for_human"},
                "humanRequest":{"id":uuid::Uuid::new_v4(),"status":"pending"},"status":"waiting_for_human"
            }});
            crate::state::write_json(
                &root
                    .path()
                    .join("operations")
                    .join(format!("{}.json", uuid::Uuid::new_v4())),
                &record,
            )
            .unwrap();
            let report = assess_state(root.path()).unwrap();
            assert_eq!(
                blocker_count(&report, BlockerCategory::OperationCache),
                1,
                "{method}"
            );
            assert!(!report.resolved);
            assert!(inventory_resolved_state(root.path()).is_err());
        }
        let root = tempfile::tempdir().unwrap();
        crate::state::private_dir(root.path()).unwrap();
        crate::state::write_json(&root.path().join("operations").join(format!("{}.json", uuid::Uuid::new_v4())), &json!({"method":"workflows.create","digest":"a".repeat(64),"executionId":null,"result":{"workflowId":uuid::Uuid::new_v4(),"name":"Fixture metadata","slug":"fixture-metadata"}})).unwrap();
        assert!(assess_state(root.path()).unwrap().resolved);
        assert!(inventory_resolved_state(root.path()).is_ok());
    }
    #[test]
    fn readonly_preview_captures_domain_operations_and_binds_native_patch_dependencies() {
        let root = tempfile::tempdir().unwrap();
        stores(root.path());
        let connection = Connection::open(root.path().join("presentation.sqlite3")).unwrap();
        row(
            &connection,
            "presentation_operations",
            &[
                ("method", text("workflows.publish")),
                (
                    "params_json",
                    bytes(json!({"workflowId":uuid::Uuid::new_v4(),"expectedVersion":1})),
                ),
                ("status", text("pending")),
            ],
        );
        row(
            &connection,
            "presentation_deliveries",
            &[("status", text("ready"))],
        );
        drop(connection);
        let before = assessment::fingerprints(root.path()).unwrap();
        let preview = maintenance_preview(root.path()).unwrap();
        assert_eq!(before, assessment::fingerprints(root.path()).unwrap());
        assert_eq!(
            preview
                .iter()
                .filter(|candidate| candidate["kind"] == "presentation_operation")
                .count(),
            1
        );
        assert_eq!(
            preview
                .iter()
                .filter(|candidate| candidate["kind"] == "presentation_delivery")
                .count(),
            1
        );
        assert_eq!(
            blocker_count(
                &assess_state(root.path()).unwrap(),
                BlockerCategory::DomainMutation
            ),
            1
        );
        let baseline = assess_state(root.path()).unwrap().assessment_digest;
        let patch = root
            .path()
            .join("workflow-patches")
            .join(format!("{}.json", "a".repeat(64)));
        crate::state::write_json(
            &patch,
            &json!({"phase":"submitted","updateDigest":"b".repeat(64)}),
        )
        .unwrap();
        let submitted = assess_state(root.path()).unwrap().assessment_digest;
        assert_ne!(baseline, submitted);
        crate::state::write_json(
            &patch,
            &json!({"phase":"submitted","updateDigest":"c".repeat(64)}),
        )
        .unwrap();
        assert_ne!(
            submitted,
            assess_state(root.path()).unwrap().assessment_digest
        );
        let dependencies = assessment::fingerprints(root.path()).unwrap();
        crate::state::write_json(&root.path().join(format!("uninstall-work-cache-{}-0.json", uuid::Uuid::new_v4())), &json!({"schema":"app.loomex.runner.uninstall-work-cache-transition/v1","privateOwnerContext":true})).unwrap();
        assert_eq!(dependencies, assessment::fingerprints(root.path()).unwrap());
    }
    fn native_patch_fixture(workflow: &str) -> Value {
        let body = json!({"definition":{"nodes":[]},"expectedVersion":2});
        json!({"identity":"a".repeat(64),"workflowId":workflow,"expectedVersion":2,"expectedDefinitionChecksum":"b".repeat(64),"updateDigest":crate::state::json_digest(&body["definition"]),"payloadDigest":crate::state::json_digest(&body),"updateBody":body,"status":"submitted"})
    }

    #[test]
    fn standalone_native_patch_pending_unknown_and_malformed_state_cannot_be_discarded() {
        let root = tempfile::tempdir().unwrap();
        crate::state::private_dir(root.path()).unwrap();
        let workflow = uuid::Uuid::new_v4().to_string();
        let path = root
            .path()
            .join("workflow-patches")
            .join(format!("{}.json", "a".repeat(64)));
        let pending = native_patch_fixture(&workflow);
        crate::state::write_json(&path, &pending).unwrap();
        let report = assess_state(root.path()).unwrap();
        assert_eq!(blocker_count(&report, BlockerCategory::DomainMutation), 1);
        assert!(!report.resolved);
        assert!(inventory_resolved_state(root.path()).is_err());
        let mut unknown = pending;
        unknown["status"] = json!("future-completion");
        crate::state::write_json(&path, &unknown).unwrap();
        assert_eq!(
            blocker_count(
                &assess_state(root.path()).unwrap(),
                BlockerCategory::DomainMutation
            ),
            1
        );
        crate::state::atomic_write(&path, b"{").unwrap();
        assert_eq!(
            blocker_count(
                &assess_state(root.path()).unwrap(),
                BlockerCategory::UnreadableState
            ),
            1
        );
        crate::state::write_json(&path, &json!({"identity":"a".repeat(64),"workflowId":workflow,"status":"rejected","code":"WORKFLOW_PATCH_INVALID"})).unwrap();
        assert!(assess_state(root.path()).unwrap().resolved);
        let inventory = inventory_resolved_state(root.path()).unwrap();
        assert!(
            inventory.contains(&path) && inventory.contains(&root.path().join("workflow-patches"))
        );
        crate::state::atomic_write(
            &root.path().join("workflow-patches").join("unowned-note"),
            b"retain",
        )
        .unwrap();
        let report = assess_state(root.path()).unwrap();
        assert_eq!(
            blocker_count(&report, BlockerCategory::UnsupportedSchema),
            1
        );
        assert_eq!(blocker_count(&report, BlockerCategory::DomainMutation), 0);
        assert!(!report.resolved);
        assert!(inventory_resolved_state(root.path()).is_err());
        let unknown = root.path().join("workflow-patches").join("unowned-note");
        assert_eq!(fs::read(&unknown).unwrap(), b"retain");
        fs::remove_file(&unknown).unwrap();
        std::os::unix::fs::symlink(root.path().join("outside-authority"), &unknown).unwrap();
        let unsafe_report = assess_state(root.path()).unwrap();
        assert!(blocker_count(&unsafe_report, BlockerCategory::UnsafeState) > 0);
        assert_eq!(
            blocker_count(&unsafe_report, BlockerCategory::UnsupportedSchema),
            0
        );
        assert_eq!(
            blocker_count(&unsafe_report, BlockerCategory::DomainMutation),
            0
        );
        let error = inventory_resolved_state(root.path()).unwrap_err();
        assert_eq!(error_category(&error), BlockerCategory::UnsafeState);
    }

    #[test]
    fn standalone_native_patch_requires_exact_shared_owner_receipt_before_cleanup() {
        let root = tempfile::tempdir().unwrap();
        let store = crate::presentation::PresentationStore::open(root.path()).unwrap();
        let workflow = uuid::Uuid::new_v4().to_string();
        let original_key = uuid::Uuid::new_v4().to_string();
        let params = json!({"workflowId":workflow,"expectedVersion":2,"expectedDefinitionChecksum":"b".repeat(64),"operations":[{"nodeKey":"node","op":"replace","path":"/prompt","value":"PRIVATE PATCH CONTENT"}],"idempotencyKey":original_key});
        let session = store.dispatch("org", "account", "presentation.sessions.create", &json!({"kind":"monitor","entityType":"execution","entityId":uuid::Uuid::new_v4(),"state":{},"idempotencyKey":uuid::Uuid::new_v4()})).unwrap();
        store.dispatch("org", "account", "presentation.sessions.update", &json!({"viewSessionId":session["viewSessionId"],"expectedRevision":0,"state":{},"operation":{"method":"workflows.patch","params":params,"idempotencyKey":original_key,"reconciliation":{"method":"workflow.operations.get","params":{"operation":"workflows.update","idempotencyKey":original_key}}},"idempotencyKey":uuid::Uuid::new_v4()})).unwrap();
        let mut candidate = store.maintenance_operation_candidates().unwrap().remove(0);
        candidate["idempotencyKey"] = json!(uuid::Uuid::new_v4());
        let mut original = native_patch_fixture(&workflow);
        original["identity"] = json!(crate::state::json_digest(
            &json!({"organizationId":"org","accountSubject":"account","workflowId":workflow,"expectedVersion":2,"expectedDefinitionChecksum":"b".repeat(64),"operations":params["operations"],"idempotencyKey":original_key})
        ));
        candidate["nativePatchJournal"] = original.clone();
        let receipt = json!({"operation":"workflows.update","idempotencyKey":original_key,"status":"completed","response":{"workflow":{"id":workflow},"draft":{"definition":original["updateBody"]["definition"],"notes":"preserved historical notes"}}});
        store
            .maintenance_operation_settle(&candidate, &receipt)
            .unwrap();
        let mut resolved = original.clone();
        resolved["maintenanceResolution"] = json!({"schema":"loomex.native-patch-reconciliation/v1","originalJournalDigest":crate::state::json_digest(&original),"candidate":candidate,"canonicalReceipt":receipt,"receiptDigest":crate::state::json_digest(&receipt)});
        drop(store);
        let standalone = tempfile::tempdir().unwrap();
        crate::state::private_dir(standalone.path()).unwrap();
        let name = crate::state::json_digest(
            &json!({"organizationId":"org","accountSubject":"account","idempotencyKey":original_key}),
        );
        let path = standalone
            .path()
            .join("workflow-patches")
            .join(format!("{name}.json"));
        crate::state::write_json(&path, &resolved).unwrap();
        assert!(assess_state(standalone.path()).unwrap().resolved);
        assert!(
            inventory_resolved_state(standalone.path())
                .unwrap()
                .contains(&path)
        );
        let relocated = standalone
            .path()
            .join("workflow-patches")
            .join(format!("{}.json", "f".repeat(64)));
        fs::rename(&path, &relocated).unwrap();
        assert!(
            blocker_count(
                &assess_state(standalone.path()).unwrap(),
                BlockerCategory::UnsafeState
            ) > 0
        );
        assert!(inventory_resolved_state(standalone.path()).is_err());
        fs::rename(&relocated, &path).unwrap();
        let baseline = assess_state(standalone.path()).unwrap().assessment_digest;
        resolved["maintenanceResolution"]["canonicalReceipt"]["response"]["workflow"]["id"] =
            json!(uuid::Uuid::new_v4());
        crate::state::write_json(&path, &resolved).unwrap();
        let drift = assess_state(standalone.path()).unwrap();
        assert_ne!(baseline, drift.assessment_digest);
        assert_eq!(blocker_count(&drift, BlockerCategory::UnreadableState), 1);
        assert!(inventory_resolved_state(standalone.path()).is_err());
        assert!(
            !serde_json::to_string(&drift)
                .unwrap()
                .contains("PRIVATE PATCH CONTENT")
        );
    }
    #[test]
    fn authenticated_native_patch_acknowledgement_qualifies_only_exact_scope_key_and_body() {
        for canonical in [false, true] {
            let root = tempfile::tempdir().unwrap();
            crate::state::private_dir(root.path()).unwrap();
            let org = uuid::Uuid::new_v4().to_string();
            let account = uuid::Uuid::new_v4().to_string();
            let workflow = uuid::Uuid::new_v4().to_string();
            let key = uuid::Uuid::new_v4().to_string();
            let request = json!({"workflowId":workflow,"expectedVersion":2,"expectedDefinitionChecksum":"b".repeat(64),"operations":[{"nodeKey":"node","op":"replace","path":"/prompt","value":"PRIVATE ACK CONTENT"}],"idempotencyKey":key});
            let mut original = native_patch_fixture(&workflow);
            original["identity"] = json!(crate::state::json_digest(
                &json!({"organizationId":org,"accountSubject":account,"workflowId":workflow,"expectedVersion":2,"expectedDefinitionChecksum":"b".repeat(64),"operations":request["operations"],"idempotencyKey":key})
            ));
            let response = json!({"workflow":{"id":workflow},"draft":{"definition":original["updateBody"]["definition"],"notes":"historical accepted response"}});
            let receipt = json!({"operation":"workflows.update","idempotencyKey":key,"status":"completed","response":response});
            let acknowledged = crate::control::native_patch_acknowledgement(
                &serde_json::to_vec(&original).unwrap(),
                &org,
                &account,
                "fixture-installation",
                &request,
                &response,
                canonical.then_some(&receipt),
            )
            .unwrap();
            assert_eq!(acknowledged["status"], "submitted");
            assert_eq!(
                acknowledged["nativeAcknowledgement"]
                    .get("canonicalReceipt")
                    .is_some(),
                canonical
            );
            let stem = crate::state::json_digest(
                &json!({"organizationId":org,"accountSubject":account,"idempotencyKey":key}),
            );
            let path = root
                .path()
                .join("workflow-patches")
                .join(format!("{stem}.json"));
            crate::state::write_json(&path, &acknowledged).unwrap();
            assert!(assess_state(root.path()).unwrap().resolved);
            assert!(
                inventory_resolved_state(root.path())
                    .unwrap()
                    .contains(&path)
            );
            for field in [
                "originalJournalSha256",
                "organizationId",
                "operationKey",
                "responseDigest",
            ] {
                let mut wrong = acknowledged.clone();
                wrong["nativeAcknowledgement"][field] =
                    if field.ends_with("Digest") || field.ends_with("Sha256") {
                        json!("f".repeat(64))
                    } else {
                        json!(uuid::Uuid::new_v4())
                    };
                crate::state::write_json(&path, &wrong).unwrap();
                let report = assess_state(root.path()).unwrap();
                assert_eq!(
                    blocker_count(&report, BlockerCategory::UnreadableState),
                    1,
                    "{field}"
                );
                assert_eq!(blocker_count(&report, BlockerCategory::DomainMutation), 0);
                assert!(inventory_resolved_state(root.path()).is_err());
                assert!(
                    !serde_json::to_string(&report)
                        .unwrap()
                        .contains("PRIVATE ACK CONTENT")
                );
            }
            let mut wrong_body = acknowledged.clone();
            wrong_body["updateBody"]["definition"] = json!({"changed":true});
            crate::state::write_json(&path, &wrong_body).unwrap();
            assert_eq!(
                blocker_count(
                    &assess_state(root.path()).unwrap(),
                    BlockerCategory::UnreadableState
                ),
                1
            );
            assert!(inventory_resolved_state(root.path()).is_err());
            crate::state::write_json(&path, &acknowledged).unwrap();
            let relocated = root
                .path()
                .join("workflow-patches")
                .join(format!("{}.json", "f".repeat(64)));
            fs::rename(&path, &relocated).unwrap();
            assert!(
                blocker_count(
                    &assess_state(root.path()).unwrap(),
                    BlockerCategory::UnsafeState
                ) > 0
            );
            assert!(inventory_resolved_state(root.path()).is_err());
        }
    }
}
