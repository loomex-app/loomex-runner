//! Durable owner-scoped state for optional custom UI resources.
//!
//! Backend data remains authoritative. Restoring a view never invokes an operation
//! or recreates a prepare/commit authorization. Exact mutable call arguments live
//! only in the explicit operation journal, separate from the presentation state.

use anyhow::{Context, Result, bail, ensure};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde_json::{Value, json};
use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::Path,
    sync::Mutex,
};
use uuid::Uuid;

/// Retired presentation state is useful for an exact restore/retry, but is
/// local convenience state rather than execution authority.  Keep inactive or
/// resolved sessions and completed-operation results for thirty days.  Active
/// sessions, and any pending or ambiguous operation, are deliberately never
/// put on this expiry path.
const RETENTION_SECONDS: u64 = 30 * 24 * 60 * 60;
const MAX_STATE_BYTES: usize = 512 * 1024;
const MAX_JSON_DEPTH: usize = 32;
const MAX_JSON_NODES: usize = 20_000;
const NIL_UUID: &str = "00000000-0000-0000-0000-000000000000";

pub struct PresentationStore {
    connection: Mutex<Connection>,
}

#[derive(Clone, Copy)]
struct Scope<'a> {
    organization: &'a str,
    account: &'a str,
}

impl PresentationStore {
    pub fn open(dir: &Path) -> Result<Self> {
        crate::state::private_dir(dir)?;
        let path = dir.join("presentation.sqlite3");
        for candidate in [
            path.clone(),
            dir.join("presentation.sqlite3-wal"),
            dir.join("presentation.sqlite3-shm"),
        ] {
            if let Ok(metadata) = fs::symlink_metadata(candidate) {
                ensure!(
                    metadata.is_file()
                        && !metadata.file_type().is_symlink()
                        && metadata.uid() == unsafe { libc::geteuid() },
                    "UNSAFE_STATE"
                );
            }
        }
        let connection = Connection::open(&path)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        connection.busy_timeout(std::time::Duration::from_secs(5))?;
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.pragma_update(None, "synchronous", "FULL")?;
        connection.pragma_update(None, "foreign_keys", "ON")?;
        let version: u32 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
        ensure!(version <= 1, "UNSUPPORTED_STATE_VERSION");
        connection.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS presentation_sessions (
              view_session_id TEXT PRIMARY KEY,
              organization_id TEXT NOT NULL,
              account_subject TEXT NOT NULL,
              kind TEXT NOT NULL,
              entity_type TEXT NOT NULL,
              entity_id TEXT NOT NULL,
              revision INTEGER NOT NULL,
              state_json BLOB NOT NULL,
              status TEXT NOT NULL,
              created_at INTEGER NOT NULL,
              updated_at INTEGER NOT NULL,
              expires_at INTEGER
            );
            CREATE INDEX IF NOT EXISTS presentation_session_scope
              ON presentation_sessions(organization_id, account_subject, updated_at);
            CREATE INDEX IF NOT EXISTS presentation_session_expiry
              ON presentation_sessions(expires_at);
            CREATE TABLE IF NOT EXISTS presentation_operations (
              operation_id TEXT PRIMARY KEY,
              view_session_id TEXT NOT NULL REFERENCES presentation_sessions(view_session_id) ON DELETE CASCADE,
              organization_id TEXT NOT NULL,
              account_subject TEXT NOT NULL,
              method TEXT NOT NULL,
              params_json BLOB NOT NULL,
              operation_key TEXT NOT NULL,
              reconciliation_json BLOB NOT NULL,
              status TEXT NOT NULL,
              result_reference_json BLOB,
              created_at INTEGER NOT NULL,
              updated_at INTEGER NOT NULL,
              expires_at INTEGER,
              UNIQUE(view_session_id, operation_key)
            );
            CREATE INDEX IF NOT EXISTS presentation_operation_expiry
              ON presentation_operations(expires_at);
            CREATE TABLE IF NOT EXISTS presentation_receipts (
              organization_id TEXT NOT NULL,
              account_subject TEXT NOT NULL,
              method TEXT NOT NULL,
              idempotency_key TEXT NOT NULL,
              request_digest TEXT NOT NULL,
              result_json BLOB NOT NULL,
              created_at INTEGER NOT NULL,
              expires_at INTEGER NOT NULL,
              PRIMARY KEY(organization_id, account_subject, method, idempotency_key)
            );
            PRAGMA user_version = 1;
            ",
        )?;
        for candidate in [
            path,
            dir.join("presentation.sqlite3-wal"),
            dir.join("presentation.sqlite3-shm"),
        ] {
            if candidate.exists() {
                fs::set_permissions(candidate, fs::Permissions::from_mode(0o600))?;
            }
        }
        let store = Self {
            connection: Mutex::new(connection),
        };
        store.sweep(crate::state::now())?;
        Ok(store)
    }

    pub fn dispatch(&self, org: &str, account: &str, method: &str, p: &Value) -> Result<Value> {
        let scope = Scope {
            organization: org,
            account,
        };
        self.sweep(crate::state::now())?;
        match method {
            "presentation.sessions.create" => self.create(scope, p),
            "presentation.sessions.get" => self.get(scope, p),
            "presentation.sessions.update" => self.update(scope, p),
            "presentation.sessions.delete" => self.delete(scope, p),
            "presentation.operations.get" => self.operation_get(scope, p),
            "presentation.operations.settle" => self.operation_settle(scope, p),
            _ => bail!("METHOD_NOT_FOUND"),
        }
    }

    fn create(&self, scope: Scope<'_>, p: &Value) -> Result<Value> {
        validate_kind(required(p, "kind")?)?;
        validate_entity(required(p, "entityType")?, required(p, "entityId")?)?;
        validate_presentation_json(&p["state"])?;
        let key = required_uuid(p, "idempotencyKey")?;
        let digest = crate::state::json_digest(p);
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| anyhow::anyhow!("INTERNAL"))?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(value) = receipt(&tx, scope, "presentation.sessions.create", key, &digest)? {
            tx.commit()?;
            return Ok(value);
        }
        let id = Uuid::new_v4().to_string();
        let now = crate::state::now();
        tx.execute(
            "INSERT INTO presentation_sessions VALUES (?1,?2,?3,?4,?5,?6,0,?7,'active',?8,?8,NULL)",
            params![
                id,
                scope.organization,
                scope.account,
                p["kind"].as_str(),
                p["entityType"].as_str(),
                p["entityId"].as_str(),
                encode(&p["state"])?,
                now
            ],
        )?;
        let result = session_projection(&tx, scope, &id)?;
        save_receipt(
            &tx,
            scope,
            "presentation.sessions.create",
            key,
            &digest,
            &result,
            now,
        )?;
        tx.commit()?;
        Ok(result)
    }

    fn get(&self, scope: Scope<'_>, p: &Value) -> Result<Value> {
        let id = required_uuid(p, "viewSessionId")?;
        let connection = self
            .connection
            .lock()
            .map_err(|_| anyhow::anyhow!("INTERNAL"))?;
        session_projection(&connection, scope, id)
    }

    fn update(&self, scope: Scope<'_>, p: &Value) -> Result<Value> {
        let id = required_uuid(p, "viewSessionId")?;
        let key = required_uuid(p, "idempotencyKey")?;
        let expected = p["expectedRevision"].as_u64().context("INVALID_REQUEST")?;
        validate_presentation_json(&p["state"])?;
        let status = p.get("status").and_then(Value::as_str).unwrap_or("active");
        ensure!(
            ["active", "inactive", "resolved"].contains(&status),
            "INVALID_REQUEST"
        );
        if let Some(operation) = p.get("operation") {
            validate_operation(operation)?;
        }
        let digest = crate::state::json_digest(p);
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| anyhow::anyhow!("INTERNAL"))?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(value) = receipt(&tx, scope, "presentation.sessions.update", key, &digest)? {
            tx.commit()?;
            return Ok(value);
        }
        let current: Option<u64> = tx.query_row(
            "SELECT revision FROM presentation_sessions WHERE view_session_id=?1 AND organization_id=?2 AND account_subject=?3",
            params![id, scope.organization, scope.account],
            |row| row.get(0),
        ).optional()?;
        let current = current.context("VIEW_SESSION_NOT_FOUND")?;
        ensure!(current == expected, "REVISION_CONFLICT");
        if p.get("operation").is_some() || status != "active" {
            let unresolved: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM presentation_operations WHERE view_session_id=?1 AND status IN ('pending','ambiguous'))",
                params![id], |row| row.get(0))?;
            ensure!(!unresolved, "OPERATION_PENDING");
            ensure!(
                p.get("operation").is_none() || status == "active",
                "OPERATION_PENDING"
            );
        }
        let now = crate::state::now();
        let expires = (status != "active").then_some(now.saturating_add(RETENTION_SECONDS));
        tx.execute(
            "UPDATE presentation_sessions SET revision=revision+1,state_json=?1,status=?2,updated_at=?3,expires_at=?4 WHERE view_session_id=?5 AND organization_id=?6 AND account_subject=?7",
            params![encode(&p["state"])?, status, now, expires, id, scope.organization, scope.account],
        )?;
        let operation_id = if let Some(operation) = p.get("operation") {
            let operation_id = Uuid::new_v4().to_string();
            let reconciliation = operation
                .get("reconciliation")
                .cloned()
                .unwrap_or_else(|| json!({}));
            tx.execute(
                "INSERT INTO presentation_operations VALUES (?1,?2,?3,?4,?5,?6,?7,?8,'pending',NULL,?9,?9,NULL)",
                params![operation_id, id, scope.organization, scope.account, operation["method"].as_str(), encode(&operation["params"])?, operation["idempotencyKey"].as_str(), encode(&reconciliation)?, now],
            )?;
            Some(operation_id)
        } else {
            None
        };
        let mut result = session_projection(&tx, scope, id)?;
        if let Some(operation_id) = operation_id {
            result["operation"] = json!({"operationId":operation_id,"status":"pending"});
        }
        save_receipt(
            &tx,
            scope,
            "presentation.sessions.update",
            key,
            &digest,
            &result,
            now,
        )?;
        tx.commit()?;
        Ok(result)
    }

    fn delete(&self, scope: Scope<'_>, p: &Value) -> Result<Value> {
        let id = required_uuid(p, "viewSessionId")?;
        let key = required_uuid(p, "idempotencyKey")?;
        let digest = crate::state::json_digest(p);
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| anyhow::anyhow!("INTERNAL"))?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(value) = receipt(&tx, scope, "presentation.sessions.delete", key, &digest)? {
            tx.commit()?;
            return Ok(value);
        }
        let unresolved: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM presentation_operations WHERE view_session_id=?1 AND organization_id=?2 AND account_subject=?3 AND status IN ('pending','ambiguous'))",
            params![id, scope.organization, scope.account], |row| row.get(0),
        )?;
        ensure!(!unresolved, "OPERATION_PENDING");
        let changed = tx.execute(
            "DELETE FROM presentation_sessions WHERE view_session_id=?1 AND organization_id=?2 AND account_subject=?3",
            params![id, scope.organization, scope.account],
        )?;
        ensure!(changed == 1, "VIEW_SESSION_NOT_FOUND");
        let result = json!({"viewSessionId":id,"deleted":true});
        save_receipt(
            &tx,
            scope,
            "presentation.sessions.delete",
            key,
            &digest,
            &result,
            crate::state::now(),
        )?;
        tx.commit()?;
        Ok(result)
    }

    fn operation_get(&self, scope: Scope<'_>, p: &Value) -> Result<Value> {
        let session = required_uuid(p, "viewSessionId")?;
        let operation = required_uuid(p, "operationId")?;
        let connection = self
            .connection
            .lock()
            .map_err(|_| anyhow::anyhow!("INTERNAL"))?;
        connection.query_row(
            "SELECT method,params_json,operation_key,reconciliation_json,status,created_at,updated_at,result_reference_json FROM presentation_operations WHERE operation_id=?1 AND view_session_id=?2 AND organization_id=?3 AND account_subject=?4",
            params![operation, session, scope.organization, scope.account],
            |row| {
                let params_json: Vec<u8> = row.get(1)?;
                let reconciliation_json: Vec<u8> = row.get(3)?;
                let reference: Option<Vec<u8>> = row.get(7)?;
                Ok(json!({
                    "operationId":operation,"viewSessionId":session,"method":row.get::<_,String>(0)?,
                    "params":decode_sql(&params_json)?,"idempotencyKey":row.get::<_,String>(2)?,
                    "reconciliation":decode_sql(&reconciliation_json)?,"status":row.get::<_,String>(4)?,
                    "createdAt":row.get::<_,u64>(5)?,"updatedAt":row.get::<_,u64>(6)?,
                    "resultReference":reference.map(|bytes|decode_sql(&bytes)).transpose()?
                }))
            },
        ).optional()?.context("OPERATION_NOT_FOUND")
    }

    fn operation_settle(&self, scope: Scope<'_>, p: &Value) -> Result<Value> {
        let session = required_uuid(p, "viewSessionId")?;
        let operation = required_uuid(p, "operationId")?;
        let key = required_uuid(p, "idempotencyKey")?;
        let status = required(p, "status")?;
        ensure!(
            ["completed", "ambiguous"].contains(&status),
            "INVALID_REQUEST"
        );
        let reference = p.get("resultReference").cloned().unwrap_or(Value::Null);
        if !reference.is_null() {
            validate_presentation_json(&reference)?;
        }
        let digest = crate::state::json_digest(p);
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| anyhow::anyhow!("INTERNAL"))?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(value) = receipt(&tx, scope, "presentation.operations.settle", key, &digest)? {
            tx.commit()?;
            return Ok(value);
        }
        let current: Option<String> = tx.query_row(
            "SELECT status FROM presentation_operations WHERE operation_id=?1 AND view_session_id=?2 AND organization_id=?3 AND account_subject=?4",
            params![operation, session, scope.organization, scope.account], |row| row.get(0),
        ).optional()?;
        let current = current.context("OPERATION_NOT_FOUND")?;
        ensure!(
            ["pending", "ambiguous"].contains(&current.as_str()),
            "OPERATION_SETTLED"
        );
        let now = crate::state::now();
        let expires = (status == "completed").then_some(now.saturating_add(RETENTION_SECONDS));
        tx.execute(
            "UPDATE presentation_operations SET status=?1,result_reference_json=?2,updated_at=?3,expires_at=?4 WHERE operation_id=?5",
            params![status, (!reference.is_null()).then(|| encode(&reference)).transpose()?, now, expires, operation],
        )?;
        // A session may have been retired while its exact operation was still
        // awaiting reconciliation.  Pending and ambiguous operations must
        // clear any old retirement deadline; a completed operation starts a
        // fresh 30-day restore window only for an already inactive/resolved
        // session.  This prevents a delayed settlement from being swept by a
        // deadline armed before the operation was known to be final.
        match status {
            "completed" => {
                tx.execute(
                    "UPDATE presentation_sessions SET expires_at=CASE WHEN status IN ('inactive','resolved') THEN ?1 ELSE NULL END WHERE view_session_id=?2 AND organization_id=?3 AND account_subject=?4",
                    params![now.saturating_add(RETENTION_SECONDS), session, scope.organization, scope.account],
                )?;
            }
            "ambiguous" => {
                tx.execute(
                    "UPDATE presentation_sessions SET expires_at=NULL WHERE view_session_id=?1 AND organization_id=?2 AND account_subject=?3",
                    params![session, scope.organization, scope.account],
                )?;
            }
            _ => unreachable!("status validated above"),
        }
        let result = json!({"operationId":operation,"viewSessionId":session,"status":status,"updatedAt":now,"resultReference":reference});
        save_receipt(
            &tx,
            scope,
            "presentation.operations.settle",
            key,
            &digest,
            &result,
            now,
        )?;
        tx.commit()?;
        Ok(result)
    }

    pub fn delete_entities(
        &self,
        org: &str,
        account: &str,
        entity_type: &str,
        ids: &[&str],
    ) -> Result<()> {
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| anyhow::anyhow!("INTERNAL"))?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        for id in ids {
            let now = crate::state::now();
            // Entity retirement is not an instruction to erase an owner view
            // immediately.  Preserve the exact resolved session for the same
            // 30-day restore window as an explicit inactive/resolved update.
            // An unresolved operation is execution evidence, so it clears the
            // deadline until a final settlement explicitly starts a new window.
            tx.execute(
                "UPDATE presentation_sessions SET status='resolved',revision=revision+1,updated_at=?1,expires_at=CASE WHEN EXISTS (SELECT 1 FROM presentation_operations operation WHERE operation.view_session_id=presentation_sessions.view_session_id AND operation.status IN ('pending','ambiguous')) THEN NULL ELSE ?2 END WHERE organization_id=?3 AND account_subject=?4 AND entity_type=?5 AND entity_id=?6",
                params![now, now.saturating_add(RETENTION_SECONDS), org, account, entity_type, id],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn sweep(&self, at: u64) -> Result<()> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| anyhow::anyhow!("INTERNAL"))?;
        connection.execute("DELETE FROM presentation_sessions WHERE expires_at IS NOT NULL AND expires_at <= ?1 AND NOT EXISTS (SELECT 1 FROM presentation_operations operation WHERE operation.view_session_id=presentation_sessions.view_session_id AND operation.status IN ('pending','ambiguous'))", params![at])?;
        // Only completed operation results receive an expiry.  Keeping this
        // predicate explicit makes a corrupt or future status conservative:
        // it cannot turn an unresolved operation into a cleanup candidate.
        connection.execute(
            "DELETE FROM presentation_operations WHERE expires_at IS NOT NULL AND expires_at <= ?1 AND status='completed'",
            params![at],
        )?;
        connection.execute(
            "DELETE FROM presentation_receipts WHERE expires_at <= ?1",
            params![at],
        )?;
        Ok(())
    }
}

fn session_projection(connection: &Connection, scope: Scope<'_>, id: &str) -> Result<Value> {
    connection.query_row(
        "SELECT kind,entity_type,entity_id,revision,state_json,status,created_at,updated_at,expires_at FROM presentation_sessions WHERE view_session_id=?1 AND organization_id=?2 AND account_subject=?3",
        params![id, scope.organization, scope.account],
        |row| {
            let state: Vec<u8> = row.get(4)?;
            Ok(json!({
                "viewSessionId":id,"kind":row.get::<_,String>(0)?,"entityType":row.get::<_,String>(1)?,
                "entityId":row.get::<_,String>(2)?,"revision":row.get::<_,u64>(3)?,"state":decode_sql(&state)?,
                "status":row.get::<_,String>(5)?,"createdAt":row.get::<_,u64>(6)?,"updatedAt":row.get::<_,u64>(7)?,
                "expiresAt":row.get::<_,Option<u64>>(8)?,"operation":unresolved_operation(connection,id)?
            }))
        },
    ).optional()?.context("VIEW_SESSION_NOT_FOUND")
}

fn unresolved_operation(connection: &Connection, session: &str) -> rusqlite::Result<Option<Value>> {
    connection.query_row(
        "SELECT operation_id,status FROM presentation_operations WHERE view_session_id=?1 AND status IN ('pending','ambiguous') ORDER BY created_at DESC LIMIT 1",
        params![session], |row| Ok(json!({"operationId":row.get::<_,String>(0)?,"status":row.get::<_,String>(1)?})),
    ).optional()
}

fn receipt(
    connection: &Connection,
    scope: Scope<'_>,
    method: &str,
    key: &str,
    digest: &str,
) -> Result<Option<Value>> {
    let row: Option<(String, Vec<u8>)> = connection.query_row(
        "SELECT request_digest,result_json FROM presentation_receipts WHERE organization_id=?1 AND account_subject=?2 AND method=?3 AND idempotency_key=?4",
        params![scope.organization, scope.account, method, key], |row| Ok((row.get(0)?, row.get(1)?)),
    ).optional()?;
    match row {
        None => Ok(None),
        Some((stored, bytes)) => {
            ensure!(stored == digest, "IDEMPOTENCY_CONFLICT");
            Ok(Some(serde_json::from_slice(&bytes)?))
        }
    }
}

fn save_receipt(
    connection: &Connection,
    scope: Scope<'_>,
    method: &str,
    key: &str,
    digest: &str,
    result: &Value,
    now: u64,
) -> Result<()> {
    connection.execute(
        "INSERT INTO presentation_receipts VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
        params![
            scope.organization,
            scope.account,
            method,
            key,
            digest,
            encode(result)?,
            now,
            now.saturating_add(RETENTION_SECONDS)
        ],
    )?;
    Ok(())
}

fn encode(value: &Value) -> Result<Vec<u8>> {
    Ok(serde_json::to_vec(value)?)
}

fn decode_sql(bytes: &[u8]) -> rusqlite::Result<Value> {
    serde_json::from_slice(bytes).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            bytes.len(),
            rusqlite::types::Type::Blob,
            Box::new(error),
        )
    })
}

fn required<'a>(p: &'a Value, key: &str) -> Result<&'a str> {
    p[key]
        .as_str()
        .filter(|value| !value.is_empty())
        .context("INVALID_REQUEST")
}

fn required_uuid<'a>(p: &'a Value, key: &str) -> Result<&'a str> {
    let value = required(p, key)?;
    Uuid::parse_str(value).map_err(|_| anyhow::anyhow!("INVALID_REQUEST"))?;
    Ok(value)
}

fn validate_kind(kind: &str) -> Result<()> {
    ensure!(
        [
            "browser",
            "authoring",
            "prepare",
            "monitor",
            "interaction",
            "connection",
            "organizations"
        ]
        .contains(&kind),
        "INVALID_REQUEST"
    );
    Ok(())
}

fn validate_entity(kind: &str, id: &str) -> Result<()> {
    ensure!(
        [
            "catalog",
            "workflow",
            "request",
            "execution",
            "builderSession",
            "preparation"
        ]
        .contains(&kind),
        "INVALID_REQUEST"
    );
    Uuid::parse_str(id).map_err(|_| anyhow::anyhow!("INVALID_REQUEST"))?;
    ensure!(kind == "catalog" || id != NIL_UUID, "INVALID_REQUEST");
    ensure!(kind != "catalog" || id == NIL_UUID, "INVALID_REQUEST");
    Ok(())
}

fn validate_operation(value: &Value) -> Result<()> {
    let object = value.as_object().context("INVALID_REQUEST")?;
    ensure!(
        (3..=4).contains(&object.len())
            && object.keys().all(
                |key| ["method", "params", "idempotencyKey", "reconciliation"]
                    .contains(&key.as_str())
            ),
        "INVALID_REQUEST"
    );
    let catalog: Value = serde_json::from_str(include_str!("../contracts/method-catalog.json"))?;
    let methods = catalog["methods"].as_array().context("INTERNAL")?;
    let mutation = required(value, "method")?;
    ensure!(
        methods
            .iter()
            .any(|entry| entry["name"] == mutation && entry["mutating"] == true)
            && !mutation.starts_with("presentation.")
            && !mutation.starts_with("auth.")
            && mutation != "organizations.select"
            && mutation != "daemon.drain",
        "INVALID_REQUEST"
    );
    value["params"].as_object().context("INVALID_REQUEST")?;
    required_uuid(value, "idempotencyKey")?;
    if let Some(reconciliation) = value.get("reconciliation") {
        let reconciliation_object = reconciliation.as_object().context("INVALID_REQUEST")?;
        ensure!(
            reconciliation_object.len() == 2
                && reconciliation_object
                    .keys()
                    .all(|key| ["method", "params"].contains(&key.as_str())),
            "INVALID_REQUEST"
        );
        let reconciliation_method = required(reconciliation, "method")?;
        ensure!(
            methods.iter().any(|entry| {
                entry["name"] == reconciliation_method && entry["mutating"] == false
            }),
            "INVALID_REQUEST"
        );
        reconciliation["params"]
            .as_object()
            .context("INVALID_REQUEST")?;
    }
    ensure!(
        serde_json::to_vec(value)?.len() <= MAX_STATE_BYTES,
        "INVALID_REQUEST"
    );
    Ok(())
}

fn validate_presentation_json(value: &Value) -> Result<()> {
    ensure!(
        serde_json::to_vec(value)?.len() <= MAX_STATE_BYTES,
        "INVALID_REQUEST"
    );
    let mut nodes = 0usize;
    validate_node(value, 0, &mut nodes)
}

fn validate_node(value: &Value, depth: usize, nodes: &mut usize) -> Result<()> {
    *nodes += 1;
    ensure!(
        depth <= MAX_JSON_DEPTH && *nodes <= MAX_JSON_NODES,
        "INVALID_REQUEST"
    );
    match value {
        Value::Object(object) => {
            for (key, child) in object {
                ensure!(
                    !forbidden_presentation_key(key),
                    "UNSAFE_PRESENTATION_STATE"
                );
                validate_node(child, depth + 1, nodes)?;
            }
        }
        Value::Array(values) => {
            for child in values {
                validate_node(child, depth + 1, nodes)?;
            }
        }
        Value::String(text) => ensure!(text.len() <= 64 * 1024, "INVALID_REQUEST"),
        _ => {}
    }
    Ok(())
}

fn forbidden_presentation_key(key: &str) -> bool {
    let key = key
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect::<String>();
    [
        "token",
        "confirmation",
        "authorization",
        "credential",
        "password",
        "secret",
        "apikey",
        "privatekey",
        "signingkey",
        "cookie",
        "idempotencykey",
    ]
    .iter()
    .any(|sensitive| key.contains(sensitive))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope() -> Scope<'static> {
        Scope {
            organization: "org-a",
            account: "user-a",
        }
    }
    fn create(store: &PresentationStore) -> Value {
        store.create(scope(), &json!({"kind":"monitor","entityType":"execution","entityId":Uuid::new_v4(),"state":{"tab":"events"},"idempotencyKey":Uuid::new_v4()})).unwrap()
    }

    #[test]
    fn sessions_reload_and_enforce_cas_and_account_scope() {
        let temp = tempfile::tempdir().unwrap();
        let first = PresentationStore::open(temp.path()).unwrap();
        let session = create(&first);
        let id = session["viewSessionId"].as_str().unwrap().to_owned();
        drop(first);
        let reopened = PresentationStore::open(temp.path()).unwrap();
        assert_eq!(
            reopened.get(scope(), &json!({"viewSessionId":id})).unwrap()["state"]["tab"],
            "events"
        );
        assert_eq!(
            reopened
                .get(
                    Scope {
                        organization: "org-a",
                        account: "user-b"
                    },
                    &json!({"viewSessionId":id})
                )
                .unwrap_err()
                .to_string(),
            "VIEW_SESSION_NOT_FOUND"
        );
        let mutation = json!({"viewSessionId":id,"expectedRevision":0,"state":{"tab":"artifacts"},"idempotencyKey":Uuid::new_v4()});
        assert_eq!(reopened.update(scope(), &mutation).unwrap()["revision"], 1);
        assert_eq!(reopened.update(scope(), &json!({"viewSessionId":id,"expectedRevision":0,"state":{},"idempotencyKey":Uuid::new_v4()})).unwrap_err().to_string(), "REVISION_CONFLICT");
    }

    #[test]
    fn exact_operation_is_separate_atomic_and_idempotent() {
        let temp = tempfile::tempdir().unwrap();
        let store = PresentationStore::open(temp.path()).unwrap();
        let session = create(&store);
        let id = session["viewSessionId"].as_str().unwrap();
        let operation_key = Uuid::new_v4();
        let update_key = Uuid::new_v4();
        let update = json!({"viewSessionId":id,"expectedRevision":0,"state":{"phase":"submitting"},"operation":{"method":"runs.commit","params":{"confirmationKey":"owner-only","preparationId":Uuid::new_v4()},"idempotencyKey":operation_key,"reconciliation":{"method":"runs.get","params":{"runId":Uuid::new_v4()}}},"idempotencyKey":update_key});
        let first = store.update(scope(), &update).unwrap();
        assert_eq!(store.update(scope(), &update).unwrap(), first);
        assert!(!first.to_string().contains("owner-only"));
        let operation = first["operation"]["operationId"].as_str().unwrap();
        let raw = store
            .operation_get(
                scope(),
                &json!({"viewSessionId":id,"operationId":operation}),
            )
            .unwrap();
        assert_eq!(raw["params"]["confirmationKey"], "owner-only");
        assert_eq!(raw["idempotencyKey"], operation_key.to_string());
        assert_eq!(
            store
                .delete(
                    scope(),
                    &json!({"viewSessionId":id,"idempotencyKey":Uuid::new_v4()})
                )
                .unwrap_err()
                .to_string(),
            "OPERATION_PENDING"
        );
        let entity = first["entityId"].as_str().unwrap();
        store
            .delete_entities("org-a", "user-a", "execution", &[entity])
            .unwrap();
        assert_eq!(
            store.get(scope(), &json!({"viewSessionId":id})).unwrap()["status"],
            "resolved"
        );
        assert!(
            store
                .operation_get(
                    scope(),
                    &json!({"viewSessionId":id,"operationId":operation})
                )
                .is_ok()
        );
        assert_eq!(store.update(scope(), &json!({"viewSessionId":id,"expectedRevision":2,"state":{},"operation":update["operation"],"idempotencyKey":Uuid::new_v4()})).unwrap_err().to_string(), "OPERATION_PENDING");
    }

    #[test]
    fn commit_without_reconciliation_restores_for_exact_retry() {
        let temp = tempfile::tempdir().unwrap();
        let store = PresentationStore::open(temp.path()).unwrap();
        let session = create(&store);
        let id = session["viewSessionId"].as_str().unwrap().to_owned();
        let operation_key = Uuid::new_v4();
        let updated = store
            .update(
                scope(),
                &json!({"viewSessionId":id,"expectedRevision":0,"state":{"phase":"starting"},"operation":{"method":"runs.commit","params":{"confirmationKey":"owner-only","preparationId":Uuid::new_v4(),"bindingDigest":"a".repeat(64)},"idempotencyKey":operation_key},"idempotencyKey":Uuid::new_v4()}),
            )
            .unwrap();
        let operation = updated["operation"]["operationId"]
            .as_str()
            .unwrap()
            .to_owned();
        drop(store);

        let reopened = PresentationStore::open(temp.path()).unwrap();
        let raw = reopened
            .operation_get(
                scope(),
                &json!({"viewSessionId":id,"operationId":operation}),
            )
            .unwrap();
        assert_eq!(raw["method"], "runs.commit");
        assert_eq!(raw["idempotencyKey"], operation_key.to_string());
        assert_eq!(raw["reconciliation"], json!({}));
        assert_eq!(raw["status"], "pending");
        assert!(
            validate_operation(
                &json!({"method":"loomex_run_commit","params":{},"idempotencyKey":Uuid::new_v4()})
            )
            .is_err()
        );
    }

    #[test]
    fn retention_keeps_active_and_ambiguous_but_purges_resolved() {
        let temp = tempfile::tempdir().unwrap();
        let store = PresentationStore::open(temp.path()).unwrap();
        let active = create(&store);
        let active_id = active["viewSessionId"].as_str().unwrap();
        let pending = store.update(scope(), &json!({"viewSessionId":active_id,"expectedRevision":0,"state":{},"operation":{"method":"interactions.respond","params":{"requestId":Uuid::new_v4()},"idempotencyKey":Uuid::new_v4(),"reconciliation":{"method":"interactions.get","params":{"requestId":Uuid::new_v4()}}},"idempotencyKey":Uuid::new_v4()})).unwrap();
        let operation_id = pending["operation"]["operationId"].as_str().unwrap();
        store.operation_settle(scope(), &json!({"viewSessionId":active_id,"operationId":operation_id,"status":"ambiguous","idempotencyKey":Uuid::new_v4()})).unwrap();
        let resolved = create(&store);
        let resolved_id = resolved["viewSessionId"].as_str().unwrap();
        store.update(scope(), &json!({"viewSessionId":resolved_id,"expectedRevision":0,"state":{},"status":"resolved","idempotencyKey":Uuid::new_v4()})).unwrap();
        store
            .sweep(crate::state::now() + RETENTION_SECONDS + 1)
            .unwrap();
        assert_eq!(
            store
                .get(scope(), &json!({"viewSessionId":resolved_id}))
                .unwrap_err()
                .to_string(),
            "VIEW_SESSION_NOT_FOUND"
        );
        assert!(
            store
                .get(scope(), &json!({"viewSessionId":active["viewSessionId"]}))
                .is_ok()
        );
        assert!(
            store
                .operation_get(
                    scope(),
                    &json!({"viewSessionId":active_id,"operationId":operation_id})
                )
                .is_ok()
        );
    }

    #[test]
    fn entity_retirement_uses_the_same_thirty_day_restore_window() {
        let temp = tempfile::tempdir().unwrap();
        let store = PresentationStore::open(temp.path()).unwrap();
        let session = create(&store);
        let id = session["viewSessionId"].as_str().unwrap();
        let entity = session["entityId"].as_str().unwrap();
        store
            .delete_entities("org-a", "user-a", "execution", &[entity])
            .unwrap();
        let retired = store.get(scope(), &json!({"viewSessionId":id})).unwrap();
        assert_eq!(retired["status"], "resolved");
        let expiry = retired["expiresAt"].as_u64().unwrap();
        store.sweep(expiry - 1).unwrap();
        assert!(store.get(scope(), &json!({"viewSessionId":id})).is_ok());
        store.sweep(expiry).unwrap();
        assert_eq!(
            store
                .get(scope(), &json!({"viewSessionId":id}))
                .unwrap_err()
                .to_string(),
            "VIEW_SESSION_NOT_FOUND"
        );
    }

    #[test]
    fn delayed_operation_settlement_rearms_retired_session_retention() {
        let temp = tempfile::tempdir().unwrap();
        let store = PresentationStore::open(temp.path()).unwrap();
        let session = create(&store);
        let id = session["viewSessionId"].as_str().unwrap();
        let entity = session["entityId"].as_str().unwrap();
        let pending = store
            .update(
                scope(),
                &json!({"viewSessionId":id,"expectedRevision":0,"state":{},"operation":{"method":"interactions.respond","params":{"requestId":Uuid::new_v4()},"idempotencyKey":Uuid::new_v4()},"idempotencyKey":Uuid::new_v4()}),
            )
            .unwrap();
        let operation = pending["operation"]["operationId"].as_str().unwrap();
        store
            .delete_entities("org-a", "user-a", "execution", &[entity])
            .unwrap();
        assert!(store.get(scope(), &json!({"viewSessionId":id})).unwrap()["expiresAt"].is_null());

        // Model a pre-fix retired deadline that elapsed while this operation
        // was awaiting reconciliation.  Sweep must retain the unresolved row.
        {
            let connection = store.connection.lock().unwrap();
            connection
                .execute(
                    "UPDATE presentation_sessions SET expires_at=1 WHERE view_session_id=?1",
                    params![id],
                )
                .unwrap();
        }
        store.sweep(2).unwrap();
        assert!(store.get(scope(), &json!({"viewSessionId":id})).is_ok());

        store
            .operation_settle(
                scope(),
                &json!({"viewSessionId":id,"operationId":operation,"status":"ambiguous","idempotencyKey":Uuid::new_v4()}),
            )
            .unwrap();
        assert!(store.get(scope(), &json!({"viewSessionId":id})).unwrap()["expiresAt"].is_null());
        store
            .sweep(crate::state::now() + RETENTION_SECONDS + 1)
            .unwrap();
        assert!(store.get(scope(), &json!({"viewSessionId":id})).is_ok());

        store
            .operation_settle(
                scope(),
                &json!({"viewSessionId":id,"operationId":operation,"status":"completed","idempotencyKey":Uuid::new_v4()}),
            )
            .unwrap();
        let expiry = store.get(scope(), &json!({"viewSessionId":id})).unwrap()["expiresAt"]
            .as_u64()
            .unwrap();
        store.sweep(expiry - 1).unwrap();
        assert!(store.get(scope(), &json!({"viewSessionId":id})).is_ok());
        store.sweep(expiry).unwrap();
        assert_eq!(
            store
                .get(scope(), &json!({"viewSessionId":id}))
                .unwrap_err()
                .to_string(),
            "VIEW_SESSION_NOT_FOUND"
        );
    }

    #[test]
    fn concurrent_updates_allow_exactly_one_revision_winner() {
        let temp = tempfile::tempdir().unwrap();
        let store = std::sync::Arc::new(PresentationStore::open(temp.path()).unwrap());
        let session = create(&store);
        let id = session["viewSessionId"].as_str().unwrap().to_owned();
        let mut workers = vec![];
        for tab in ["events", "artifacts"] {
            let store = store.clone();
            let id = id.clone();
            workers.push(std::thread::spawn(move || store.update(scope(), &json!({"viewSessionId":id,"expectedRevision":0,"state":{"tab":tab},"idempotencyKey":Uuid::new_v4()}))));
        }
        let results = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|result| result
                    .as_ref()
                    .is_err_and(|error| error.to_string() == "REVISION_CONFLICT"))
                .count(),
            1
        );
    }

    #[test]
    fn presentation_state_rejects_confirmation_and_credentials() {
        for state in [
            json!({"confirmationKey":"x"}),
            json!({"nested":{"access_token":"x"}}),
            json!({"token":"x"}),
            json!({"confirmation":true}),
            json!({"authorizationHeader":"Bearer x"}),
            json!({"api_key":"x"}),
        ] {
            assert_eq!(
                validate_presentation_json(&state).unwrap_err().to_string(),
                "UNSAFE_PRESENTATION_STATE"
            );
        }
        validate_presentation_json(&json!({
            "currentQuestionId":"question-1",
            "answers":{"question-1":"ordinary answer content may contain the word token"}
        }))
        .unwrap();
    }

    #[test]
    fn database_is_owner_only() {
        let temp = tempfile::tempdir().unwrap();
        let _store = PresentationStore::open(temp.path()).unwrap();
        assert_eq!(
            fs::metadata(temp.path().join("presentation.sqlite3"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
}
