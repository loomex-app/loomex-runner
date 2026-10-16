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
fn no_rows(connection: &Connection, query: &str) -> Result<()> {
    let exists: bool = connection
        .query_row(query, [], |row| row.get(0))
        .map_err(|_| anyhow::anyhow!(PENDING))?;
    ensure!(!exists, "{PENDING}");
    Ok(())
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
    let version: u32 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(|_| anyhow::anyhow!(PENDING))?;
    let tables: BTreeSet<String> = connection
        .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")?
        .query_map([], |row| row.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    let required: &[&str] = match name {
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
        _ => unreachable!(),
    };
    let mut allowed: BTreeSet<String> = required.iter().map(|value| (*value).into()).collect();
    if name == "presentation.sqlite3" && version == 2 {
        allowed.insert("presentation_deliveries".into());
    }
    ensure!(
        (name == "presentation.sqlite3" && matches!(version, 1 | 2)
            || name != "presentation.sqlite3" && version == 1)
            && tables == allowed,
        "{PENDING}"
    );
    no_rows(
        &connection,
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type IN ('trigger','view'))",
    )?;
    match name {
        "presentation.sqlite3" => {
            no_rows(
                &connection,
                "SELECT EXISTS(SELECT 1 FROM presentation_sessions WHERE status IS NULL OR status NOT IN ('active','inactive','resolved'))",
            )?;
            no_rows(
                &connection,
                "SELECT EXISTS(SELECT 1 FROM presentation_operations WHERE status IS NULL OR status!='completed')",
            )?;
            // `active` is also the default for ordinary browser/catalog and
            // workflow-detail views. It is presentation lifecycle, not evidence
            // that a remote mutation or delivery remains unresolved.
            let mut statement = connection.prepare(
                "SELECT kind,entity_type,status,organization_id,account_subject,state_json FROM presentation_sessions",
            )?;
            for row in statement.query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                ))
            })? {
                let (kind, entity, status, organization, account, bytes) = row?;
                let state: Value =
                    serde_json::from_slice(&bytes).map_err(|_| anyhow::anyhow!(PENDING))?;
                ensure!(state.is_object(), "{PENDING}");
                if status == "active" {
                    ensure!(
                        disposable_view_kind(&kind, &entity) && !has_pending_view_reference(&state),
                        "{PENDING}"
                    );
                }
                if let Some(delivery) = state
                    .get("continuationDelivery")
                    .filter(|value| !value.is_null())
                {
                    if delivery["schemaVersion"] == 2 {
                        // Current presentation state retains only an identity;
                        // its authoritative status lives in the delivery table.
                        ensure!(version == 2 && present(&delivery["identity"]), "{PENDING}");
                        let resolved: bool = connection.query_row(
                            "SELECT EXISTS(SELECT 1 FROM presentation_deliveries WHERE organization_id=?1 AND account_subject=?2 AND identity=?3 AND status IN ('acknowledged','rejected'))",
                            rusqlite::params![organization, account, delivery["identity"].as_str()], |row| row.get(0),
                        )?;
                        ensure!(resolved, "{PENDING}");
                    } else {
                        // Legacy rows carried their delivery result in state.
                        ensure!(
                            matches!(
                                delivery["status"].as_str(),
                                Some("acknowledged" | "rejected")
                            ),
                            "{PENDING}"
                        );
                    }
                }
            }
            if version == 2 {
                no_rows(
                    &connection,
                    "SELECT EXISTS(SELECT 1 FROM presentation_deliveries WHERE status IS NULL OR status NOT IN ('acknowledged','rejected'))",
                )?;
            }
        }
        "follow.sqlite3" => {
            no_rows(
                &connection,
                "SELECT EXISTS(SELECT 1 FROM follow_sessions WHERE lifecycle IS NULL OR required_action IS NULL OR lifecycle!='terminal' OR required_action!='none' OR terminal_receipt_json IS NULL OR pending_handoff_json IS NOT NULL)",
            )?;
            // A run-start/accepted-answer receipt without a matching terminal
            // follow record remains usable continuation authority.
            no_rows(
                &connection,
                "SELECT EXISTS(SELECT 1 FROM follow_continuations c WHERE NOT EXISTS (SELECT 1 FROM follow_sessions s WHERE s.organization_id=c.organization_id AND s.account_subject=c.account_subject AND s.installation_id=c.installation_id AND s.run_id=c.run_id AND s.lifecycle='terminal' AND s.terminal_receipt_json IS NOT NULL))",
            )?;
            let mut runs = connection.prepare("SELECT run_id FROM follow_sessions")?;
            for run in runs.query_map([], |row| row.get::<_, String>(0))? {
                terminal_runs.insert(run?);
            }
            let mut statement = connection.prepare(
                "SELECT terminal_receipt_json,recovery_json,cleanup_json FROM follow_sessions",
            )?;
            for row in statement.query_map([], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Option<Vec<u8>>>(1)?,
                    row.get::<_, Option<Vec<u8>>>(2)?,
                ))
            })? {
                let (terminal, recovery, cleanup) = row?;
                ensure!(
                    !serde_json::from_slice::<Value>(&terminal)
                        .map_err(|_| anyhow::anyhow!(PENDING))?
                        .is_null(),
                    "{PENDING}"
                );
                for embedded in [recovery, cleanup].into_iter().flatten() {
                    let value: Value =
                        serde_json::from_slice(&embedded).map_err(|_| anyhow::anyhow!(PENDING))?;
                    // No current code issues these fields. Non-null legacy or
                    // future authority must be reconciled rather than guessed.
                    ensure!(value.is_null(), "{PENDING}");
                }
            }
        }
        "recovery.sqlite3" => {
            no_rows(
                &connection,
                "SELECT EXISTS(SELECT 1 FROM recovery_records r WHERE registration_state='not_attempted' AND EXISTS(SELECT 1 FROM recovery_operations o WHERE o.recovery_id=r.recovery_id))",
            )?;
            no_rows(
                &connection,
                "SELECT EXISTS(SELECT 1 FROM recovery_operations WHERE status IS NULL OR status!='succeeded')",
            )?;
            no_rows(
                &connection,
                "SELECT EXISTS(SELECT 1 FROM recovery_records WHERE registration_state IS NULL OR lifecycle IS NULL OR current_operation_id IS NOT NULL OR pending_request_id IS NOT NULL OR NOT ((registration_state='removed' AND lifecycle='removed') OR (registration_state='not_attempted' AND lifecycle IN ('unchecked','unavailable') AND automation_id IS NULL)))",
            )?;
        }
        _ => unreachable!(),
    }
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
        let record = json(&entry.path())?;
        ensure!(
            present(&record["method"])
                && record["digest"]
                    .as_str()
                    .is_some_and(|digest| digest.len() == 64
                        && digest.bytes().all(|byte| byte.is_ascii_hexdigit())),
            "{PENDING}"
        );
        if record["expired"] != true {
            let result = record
                .get("result")
                .filter(|result| !result.is_null())
                .ok_or_else(|| anyhow::anyhow!(PENDING))?;
            ensure!(result.get("responseRef").is_none(), "{PENDING}");
            if let Some(run) = record["executionId"].as_str() {
                ensure!(
                    terminal_status(result) || terminal(dir, run, terminal_runs)?,
                    "{PENDING}"
                );
            }
        }
        paths.push(entry.path());
    }
    if wholly_owned {
        paths.push(root);
    }
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
        let metadata_path = root.join(format!("{id}.meta.json"));
        let record = json(&metadata_path)?;
        if let Some(run) = record["executionId"].as_str() {
            ensure!(terminal(dir, run, terminal_runs)?, "{PENDING}");
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
    }
    if wholly_owned {
        paths.push(root);
    }
    Ok(())
}

/// Absolute paths only. A directory is returned only if every direct child is
/// also included, so callers can preserve unknown files and remove deepest first.
pub(super) fn inventory_resolved_state(dir: &Path) -> Result<Vec<PathBuf>> {
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
        drop(loomex_runner::presentation::PresentationStore::open(dir).unwrap());
        drop(loomex_runner::follow::FollowStore::open(dir).unwrap());
        drop(loomex_runner::recovery::RecoveryStore::open(dir).unwrap());
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
    ) -> (loomex_runner::presentation::PresentationStore, Value) {
        let store = loomex_runner::presentation::PresentationStore::open(root).unwrap();
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
                    bytes(json!({"kind":"run_result","receipt":"verified-local-fact"})),
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
        crate::state::write_json(&path, &json!({"method":"runs.commit","digest":"a".repeat(64),"executionId":run,"result":{"execution":{"status":"completed"}}})).unwrap();
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
}
