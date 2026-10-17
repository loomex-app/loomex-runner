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
        ensure!(version <= 3, "UNSUPPORTED_STATE_VERSION");
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
            CREATE TABLE IF NOT EXISTS presentation_deliveries (
              organization_id TEXT NOT NULL,
              account_subject TEXT NOT NULL,
              identity TEXT NOT NULL,
              continuation_json BLOB NOT NULL,
              revision INTEGER NOT NULL,
              status TEXT NOT NULL,
              attempt_id TEXT,
              error_code TEXT,
              created_at INTEGER NOT NULL,
              updated_at INTEGER NOT NULL,
              PRIMARY KEY(organization_id, account_subject, identity)
            );
            PRAGMA user_version = 3;
            ",
        )?;
        crate::continuation_resolution::initialize(&connection)?;
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
            "presentation.sessions.restore" => self.restore(scope, p),
            "presentation.sessions.update" => self.update(scope, p),
            "presentation.sessions.delete" => self.delete(scope, p),
            "presentation.operations.get" => self.operation_get(scope, p),
            "presentation.operations.settle" => self.operation_settle(scope, p),
            "presentation.delivery.get" => self.delivery_get(scope, p),
            "presentation.delivery.begin" => self.delivery_begin(scope, p),
            "presentation.delivery.settle" => self.delivery_settle(scope, p),
            _ => bail!("METHOD_NOT_FOUND"),
        }
    }

    /// Register runner-derived continuation authority independently of any
    /// disposable presentation session. Re-registering the exact authority is
    /// idempotent, while an identity collision is rejected.
    pub fn register_delivery(
        &self,
        org: &str,
        account: &str,
        identity: &str,
        continuation: &Value,
    ) -> Result<Value> {
        validate_delivery_identity(identity)?;
        validate_continuation(continuation)?;
        let scope = Scope {
            organization: org,
            account,
        };
        let encoded = encode(continuation)?;
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| anyhow::anyhow!("INTERNAL"))?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing: Option<Vec<u8>> = tx
            .query_row(
                "SELECT continuation_json FROM presentation_deliveries WHERE organization_id=?1 AND account_subject=?2 AND identity=?3",
                params![scope.organization, scope.account, identity],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(existing) = existing {
            ensure!(
                decode(&existing)? == *continuation,
                "DELIVERY_IDENTITY_CONFLICT"
            );
        } else {
            let now = crate::state::now();
            tx.execute(
                "INSERT INTO presentation_deliveries VALUES (?1,?2,?3,?4,0,'ready',NULL,NULL,?5,?5)",
                params![scope.organization, scope.account, identity, encoded, now],
            )?;
        }
        let result = delivery_projection(&tx, scope, identity)?;
        tx.commit()?;
        Ok(result)
    }

    /// Conservatively import delivery outcomes written by pre-v2 browser
    /// cards. Only the identity and outcome are read; legacy prompt text is
    /// never copied into the delivery table.
    pub fn import_legacy_delivery(&self, org: &str, account: &str, identity: &str) -> Result<()> {
        validate_delivery_identity(identity)?;
        let scope = Scope {
            organization: org,
            account,
        };
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| anyhow::anyhow!("INTERNAL"))?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if crate::continuation_resolution::projection(
            &tx,
            "presentation_delivery",
            scope.organization,
            scope.account,
            "",
            identity,
        )?["state"]
            != "unresolved"
        {
            tx.commit()?;
            return Ok(());
        }
        let current: Option<(u64, String, Option<String>)> = tx
            .query_row(
                "SELECT revision,status,attempt_id FROM presentation_deliveries WHERE organization_id=?1 AND account_subject=?2 AND identity=?3",
                params![scope.organization, scope.account, identity],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        let Some((0, current_status, None)) = current else {
            tx.commit()?;
            return Ok(());
        };
        if current_status != "ready" {
            tx.commit()?;
            return Ok(());
        }
        let mut statement = tx.prepare(
            "SELECT state_json FROM presentation_sessions WHERE organization_id=?1 AND account_subject=?2",
        )?;
        let rows = statement.query_map(params![scope.organization, scope.account], |row| {
            row.get::<_, Vec<u8>>(0)
        })?;
        let mut imported: Option<&'static str> = None;
        for row in rows {
            let state = decode(&row?)?;
            let Some(legacy) = state
                .get("continuationDelivery")
                .and_then(Value::as_object)
                .filter(|legacy| legacy.get("identity").and_then(Value::as_str) == Some(identity))
                .filter(|legacy| legacy.get("schemaVersion").and_then(Value::as_u64) == Some(1))
            else {
                continue;
            };
            let mapped = match legacy.get("status").and_then(Value::as_str) {
                Some("acknowledged") => "acknowledged",
                Some("sending" | "unknown") => "unknown",
                Some("rejected") => "rejected",
                Some("ready" | "unsupported" | "not_sent") => "not_sent",
                _ => "unknown",
            };
            imported = Some(match imported {
                None => mapped,
                Some(previous) if previous == mapped => previous,
                Some(_) => "unknown",
            });
        }
        drop(statement);
        if let Some(status) = imported {
            tx.execute(
                "UPDATE presentation_deliveries SET revision=revision+1,status=?1,error_code='LEGACY_DELIVERY_IMPORT',updated_at=?2 WHERE organization_id=?3 AND account_subject=?4 AND identity=?5 AND revision=0 AND status='ready' AND attempt_id IS NULL",
                params![status, crate::state::now(), scope.organization, scope.account, identity],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    fn delivery_get(&self, scope: Scope<'_>, p: &Value) -> Result<Value> {
        let identity = required(p, "identity")?;
        validate_delivery_identity(identity)?;
        let connection = self
            .connection
            .lock()
            .map_err(|_| anyhow::anyhow!("INTERNAL"))?;
        delivery_projection(&connection, scope, identity)
    }

    fn delivery_begin(&self, scope: Scope<'_>, p: &Value) -> Result<Value> {
        let identity = required(p, "identity")?;
        validate_delivery_identity(identity)?;
        let expected = p["expectedRevision"].as_u64().context("INVALID_REQUEST")?;
        let attempt = required_uuid(p, "attemptId")?;
        let key = required_uuid(p, "idempotencyKey")?;
        let digest = crate::state::json_digest(p);
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| anyhow::anyhow!("INTERNAL"))?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        crate::continuation_resolution::eligible(
            &tx,
            "presentation_delivery",
            scope.organization,
            scope.account,
            "",
            identity,
        )?;
        if let Some(value) = receipt(&tx, scope, "presentation.delivery.begin", key, &digest)? {
            // Re-project additive closure metadata only after the current
            // eligibility fence. Preserve the historical mutation fields and
            // immutable stored receipt bytes, including pre-extension receipts.
            let value = delivery_resolution_projection(&tx, scope, identity, value)?;
            tx.commit()?;
            return Ok(value);
        }
        let current: Option<(u64, String)> = tx
            .query_row(
                "SELECT revision,status FROM presentation_deliveries WHERE organization_id=?1 AND account_subject=?2 AND identity=?3",
                params![scope.organization, scope.account, identity],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let (revision, status) = current.context("DELIVERY_NOT_READY")?;
        ensure!(revision == expected, "REVISION_CONFLICT");
        ensure!(
            ["ready", "not_sent", "rejected"].contains(&status.as_str()),
            "DELIVERY_NOT_READY"
        );
        let now = crate::state::now();
        tx.execute(
            "UPDATE presentation_deliveries SET revision=revision+1,status='sending',attempt_id=?1,error_code=NULL,updated_at=?2 WHERE organization_id=?3 AND account_subject=?4 AND identity=?5",
            params![attempt, now, scope.organization, scope.account, identity],
        )?;
        let result = delivery_projection(&tx, scope, identity)?;
        save_receipt(
            &tx,
            scope,
            "presentation.delivery.begin",
            key,
            &digest,
            &result,
            now,
        )?;
        tx.commit()?;
        Ok(result)
    }

    fn delivery_settle(&self, scope: Scope<'_>, p: &Value) -> Result<Value> {
        let identity = required(p, "identity")?;
        validate_delivery_identity(identity)?;
        let expected = p["expectedRevision"].as_u64().context("INVALID_REQUEST")?;
        let attempt = required_uuid(p, "attemptId")?;
        let status = required(p, "status")?;
        ensure!(
            ["not_sent", "acknowledged", "rejected", "unknown"].contains(&status),
            "INVALID_REQUEST"
        );
        let error_code = p.get("errorCode").and_then(Value::as_str);
        if let Some(error_code) = error_code {
            validate_safe_error_code(error_code)?;
        }
        let key = required_uuid(p, "idempotencyKey")?;
        let digest = crate::state::json_digest(p);
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| anyhow::anyhow!("INTERNAL"))?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        crate::continuation_resolution::eligible(
            &tx,
            "presentation_delivery",
            scope.organization,
            scope.account,
            "",
            identity,
        )?;
        if let Some(value) = receipt(&tx, scope, "presentation.delivery.settle", key, &digest)? {
            // Re-project additive closure metadata only after the current
            // eligibility fence. Preserve the historical mutation fields and
            // immutable stored receipt bytes, including pre-extension receipts.
            let value = delivery_resolution_projection(&tx, scope, identity, value)?;
            tx.commit()?;
            return Ok(value);
        }
        let current: Option<(u64, String, Option<String>)> = tx
            .query_row(
                "SELECT revision,status,attempt_id FROM presentation_deliveries WHERE organization_id=?1 AND account_subject=?2 AND identity=?3",
                params![scope.organization, scope.account, identity],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        let (revision, current_status, current_attempt) = current.context("DELIVERY_NOT_READY")?;
        ensure!(revision == expected, "REVISION_CONFLICT");
        ensure!(current_status == "sending", "DELIVERY_NOT_READY");
        ensure!(
            current_attempt.as_deref() == Some(attempt),
            "DELIVERY_ATTEMPT_CONFLICT"
        );
        let now = crate::state::now();
        tx.execute(
            "UPDATE presentation_deliveries SET revision=revision+1,status=?1,error_code=?2,updated_at=?3 WHERE organization_id=?4 AND account_subject=?5 AND identity=?6",
            params![status, error_code, now, scope.organization, scope.account, identity],
        )?;
        let result = delivery_projection(&tx, scope, identity)?;
        save_receipt(
            &tx,
            scope,
            "presentation.delivery.settle",
            key,
            &digest,
            &result,
            now,
        )?;
        tx.commit()?;
        Ok(result)
    }

    /// Exact local records for owner-reviewed maintenance. No host session identifiers are exposed.
    pub fn maintenance_candidates(&self) -> Result<Vec<Value>> {
        let c = self
            .connection
            .lock()
            .map_err(|_| anyhow::anyhow!("INTERNAL"))?;
        maintenance_delivery_candidates(&c)
    }

    pub fn maintenance_retire(&self, request: &Value) -> Result<Value> {
        self.maintenance_close(
            request,
            "retired_by_owner",
            json!({"reasonCode":"OWNER_RETIRED_LOCAL_CONTINUATION"}),
        )
    }

    /// The caller supplies a completely retrieved authoritative run/result observation.
    pub fn maintenance_reconcile(&self, request: &Value, observation: &Value) -> Result<Value> {
        let mut c = self
            .connection
            .lock()
            .map_err(|_| anyhow::anyhow!("INTERNAL"))?;
        let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let candidate = maintenance_delivery_candidates(&tx)?
            .into_iter()
            .find(|v| {
                v["organizationId"] == request["organizationId"]
                    && v["accountSubject"] == request["accountSubject"]
                    && v["recordId"] == request["recordId"]
            })
            .context("MANAGED_WORK_CHANGED")?;
        crate::continuation_resolution::matches(&candidate, request)?;
        let result = crate::continuation_resolution::observe(&tx, &candidate, observation)?;
        tx.commit()?;
        Ok(result)
    }

    fn maintenance_close(&self, request: &Value, state: &str, evidence: Value) -> Result<Value> {
        let mut c = self
            .connection
            .lock()
            .map_err(|_| anyhow::anyhow!("INTERNAL"))?;
        let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let candidate = maintenance_delivery_candidates(&tx)?
            .into_iter()
            .find(|v| {
                v["organizationId"] == request["organizationId"]
                    && v["accountSubject"] == request["accountSubject"]
                    && v["recordId"] == request["recordId"]
            })
            .context("MANAGED_WORK_CHANGED")?;
        crate::continuation_resolution::matches(&candidate, request)?;
        ensure!(
            candidate["retirementEligible"] == true,
            "MANAGED_WORK_RETIREMENT_UNSUPPORTED"
        );
        let observed = crate::continuation_resolution::observation(&tx, &candidate)?;
        ensure!(
            observed["recordDigest"] == candidate["recordDigest"],
            "MANAGED_WORK_RECONCILIATION_REQUIRED"
        );
        let result =
            crate::continuation_resolution::close(&tx, &candidate, request, state, evidence)?;
        tx.commit()?;
        Ok(result)
    }

    fn create(&self, scope: Scope<'_>, p: &Value) -> Result<Value> {
        validate_kind(required(p, "kind")?)?;
        validate_entity(
            required(p, "kind")?,
            required(p, "entityType")?,
            required(p, "entityId")?,
        )?;
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

    /// Return only the durable display projection needed to paint a restored
    /// view.  This intentionally has no operation arguments, idempotency
    /// material, timestamps, or owner credentials.  A caller must use the
    /// ordinary owner-scoped operation APIs to reconcile or retry anything.
    fn restore(&self, scope: Scope<'_>, p: &Value) -> Result<Value> {
        let id = required_uuid(p, "viewSessionId")?;
        let connection = self
            .connection
            .lock()
            .map_err(|_| anyhow::anyhow!("INTERNAL"))?;
        restore_projection(&connection, scope, id)
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
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| anyhow::anyhow!("INTERNAL"))?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let result = settle_operation(&tx, scope, p)?;
        tx.commit()?;
        Ok(result)
    }

    /// Private maintenance data. Exact arguments may contain prompts or capabilities.
    pub fn maintenance_operation_candidates(&self) -> Result<Vec<Value>> {
        let c = self
            .connection
            .lock()
            .map_err(|_| anyhow::anyhow!("INTERNAL"))?;
        maintenance_operation_candidates(&c)
    }

    /// Apply a completely read owner-checked receipt through the ordinary settlement owner.
    pub fn maintenance_operation_settle(
        &self,
        request: &Value,
        canonical_receipt: &Value,
    ) -> Result<Value> {
        ensure!(
            request["recordDigest"] == operation_binding_digest(request),
            "MANAGED_WORK_CHANGED"
        );
        verify_maintenance_operation_receipt(request, canonical_receipt)?;
        let scope = Scope {
            organization: required(request, "organizationId")?,
            account: required(request, "accountSubject")?,
        };
        let key = required_uuid(request, "idempotencyKey")?;
        let summary = maintenance_operation_summary(request, canonical_receipt)?;
        let p = json!({"viewSessionId":request["viewSessionId"],"operationId":request["operationId"],"status":"completed","idempotencyKey":key,
            "resultReference":{"maintenanceDomainReceipt":summary}});
        let mut c = self
            .connection
            .lock()
            .map_err(|_| anyhow::anyhow!("INTERNAL"))?;
        let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(cached) = receipt(
            &tx,
            scope,
            "presentation.operations.maintenance_reconcile",
            key,
            &crate::state::json_digest(&p),
        )? {
            tx.commit()?;
            return Ok(cached);
        }
        // The shared owner's exact receipt is authoritative after an interrupted
        // maintenance checkpoint; replay cannot mutate a newer journal.
        if let Some(cached) = receipt(
            &tx,
            scope,
            "presentation.operations.settle",
            key,
            &crate::state::json_digest(&p),
        )? {
            tx.commit()?;
            return Ok(cached["resultReference"]["maintenanceDomainReceipt"].clone());
        }
        let current = maintenance_operation_candidates(&tx)?
            .into_iter()
            .find(|v| {
                v["operationId"] == request["operationId"]
                    && v["viewSessionId"] == request["viewSessionId"]
                    && v["organizationId"] == request["organizationId"]
                    && v["accountSubject"] == request["accountSubject"]
            })
            .context("MANAGED_WORK_CHANGED")?;
        for field in [
            "kind",
            "installationId",
            "recordId",
            "operationId",
            "viewSessionId",
            "revision",
            "generation",
            "attemptId",
            "method",
            "params",
            "operationKey",
            "reconciliation",
            "recordDigest",
            "status",
        ] {
            ensure!(
                current.get(field) == request.get(field),
                "MANAGED_WORK_CHANGED"
            );
        }
        ensure!(
            current["reconciliationSupported"] == true,
            "MANAGED_WORK_RECONCILIATION_UNSUPPORTED"
        );
        if current["status"] == "completed" {
            ensure!(current["method"] == "workflows.patch", "OPERATION_SETTLED");
            // Ordinary patch completion already owns this operation's result.
            // Only record the new canonical maintenance proof; preserve every
            // historical row field, including its original result and expiry.
            save_receipt(
                &tx,
                scope,
                "presentation.operations.maintenance_reconcile",
                key,
                &crate::state::json_digest(&p),
                &summary,
                crate::state::now(),
            )?;
            tx.commit()?;
            return Ok(summary);
        }
        settle_operation(&tx, scope, &p)?;
        tx.commit()?;
        Ok(summary)
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

/// Full journal authority for the maintenance child; never export as a public report.
pub fn maintenance_operation_candidates(c: &Connection) -> Result<Vec<Value>> {
    let mut stmt=c.prepare("SELECT o.organization_id,o.account_subject,o.operation_id,o.view_session_id,s.revision,o.method,o.params_json,o.operation_key,o.reconciliation_json,o.status,o.created_at,o.result_reference_json FROM presentation_operations o JOIN presentation_sessions s ON s.view_session_id=o.view_session_id AND s.organization_id=o.organization_id AND s.account_subject=o.account_subject ORDER BY o.operation_id")?;
    let rows = stmt
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, u64>(4)?,
                r.get::<_, String>(5)?,
                r.get::<_, Vec<u8>>(6)?,
                r.get::<_, String>(7)?,
                r.get::<_, Vec<u8>>(8)?,
                r.get::<_, String>(9)?,
                r.get::<_, u64>(10)?,
                r.get::<_, Option<Vec<u8>>>(11)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    rows.into_iter().map(|(org,account,id,session,revision,method,bytes,key,reconcile,status,created,reference)| {
        let params=decode(&bytes)?;let reconciliation=decode(&reconcile)?;
        let mut candidate=json!({"kind":"presentation_operation","organizationId":org,"accountSubject":account,"installationId":"","recordId":id,"operationId":id,"viewSessionId":session,"revision":revision,"generation":null,"attemptId":null,"method":method,"params":params,"operationKey":key,"reconciliation":reconciliation,"createdAt":created});
        candidate["recordDigest"]=json!(operation_binding_digest(&candidate));
        candidate["reconciliationSupported"]=json!(maintenance_operation_plan(&candidate).is_ok());
        candidate["status"]=json!(status);
        candidate["resultReference"]=reference.map(|v|decode(&v)).transpose()?.unwrap_or(Value::Null);
        candidate["resolution"]=if status=="completed" && candidate["resultReference"]["maintenanceDomainReceipt"]["recordDigest"]==candidate["recordDigest"] {candidate["resultReference"]["maintenanceDomainReceipt"].clone()}else{json!({"state":if status=="completed" {"reconciled"}else{"unresolved"}})};
        Ok(candidate)
    }).collect()
}

fn operation_binding_digest(candidate: &Value) -> String {
    let mut binding = serde_json::Map::new();
    for key in [
        "kind",
        "organizationId",
        "accountSubject",
        "installationId",
        "recordId",
        "operationId",
        "viewSessionId",
        "revision",
        "generation",
        "attemptId",
        "method",
        "params",
        "operationKey",
        "reconciliation",
        "createdAt",
    ] {
        binding.insert(key.into(), candidate[key].clone());
    }
    crate::state::json_digest(&Value::Object(binding))
}

pub(crate) fn maintenance_operation_summary(candidate: &Value, receipt: &Value) -> Result<Value> {
    Ok(
        json!({"schemaVersion":"loomex.domain-operation-reconciliation/v1","state":"reconciled","kind":"presentation_operation","recordDigest":candidate["recordDigest"],"operationReference":crate::state::json_digest(&candidate["operationId"]),"scopeReference":crate::state::json_digest(&json!([candidate["organizationId"],candidate["accountSubject"],candidate["installationId"]])),"originalKeyReference":crate::state::json_digest(&candidate["operationKey"]),"method":candidate["method"],"status":"completed","receiptDigest":crate::state::json_digest(receipt),"responseDigest":crate::state::json_digest(&receipt["response"])}),
    )
}

fn maintenance_operation_descriptor(candidate: &Value) -> Result<(&str, &str)> {
    let method = required(candidate, "method")?;
    let (route, operation) = match method {
        "workflows.patch" => ("workflow.operations.get", "workflows.update"),
        "workflows.create" | "workflows.update" | "workflows.publish" | "builder.start"
        | "editor.start" => ("workflow.operations.get", method),
        "persona.roles.create" => ("personas.operations.get", "role.create"),
        "personas.create" => ("personas.operations.get", "person.create"),
        "personas.chat_context.create" => ("personas.operations.get", "chat_context.create"),
        "personas.memory.write" => ("personas.operations.get", "memory.write"),
        "personas.memory.update" => ("personas.operations.get", "memory.update"),
        _ => bail!("MANAGED_WORK_RECONCILIATION_UNSUPPORTED"),
    };
    let key = required_uuid(candidate, "operationKey")?;
    validate_operation(
        &json!({"method":method,"params":candidate["params"],"idempotencyKey":key,"reconciliation":candidate["reconciliation"]}),
    )?;
    ensure!(
        candidate["params"]["idempotencyKey"] == key
            && candidate["reconciliation"]
                == json!({"method":route,"params":{"operation":operation,"idempotencyKey":key}}),
        "MANAGED_WORK_RECONCILIATION_UNSUPPORTED"
    );
    Ok((route, operation))
}

/// The only allowed maintenance read for an exact original mutation journal.
pub(crate) fn maintenance_operation_plan(candidate: &Value) -> Result<Value> {
    let (route, operation) = maintenance_operation_descriptor(candidate)?;
    let catalog: Value = serde_json::from_str(include_str!("../contracts/method-catalog.json"))?;
    let methods = catalog["methods"].as_array().context("INTERNAL")?;
    let mutation = methods
        .iter()
        .find(|entry| entry["name"] == candidate["method"])
        .context("MANAGED_WORK_RECONCILIATION_UNSUPPORTED")?;
    crate::control::validate_params(&candidate["params"], &mutation["inputSchema"])
        .map_err(|_| anyhow::anyhow!("MANAGED_WORK_RECEIPT_MISMATCH"))?;
    if let Some(org) = candidate["params"].get("organizationId") {
        ensure!(
            org == &candidate["organizationId"],
            "MANAGED_WORK_RECEIPT_MISMATCH"
        );
    }
    let params = json!({"operation":operation,"idempotencyKey":candidate["operationKey"]});
    Ok(json!({"method":route,"params":params}))
}

pub(crate) fn verify_native_patch_journal(candidate: &Value, response: &Value) -> Result<()> {
    let p = &candidate["params"];
    let record = &candidate["nativePatchJournal"];
    let notes = p.get("notes").and_then(Value::as_str);
    let common = json!({"organizationId":candidate["organizationId"],"accountSubject":candidate["accountSubject"],"workflowId":p["workflowId"],"expectedVersion":p["expectedVersion"],"expectedDefinitionChecksum":p["expectedDefinitionChecksum"],"operations":p["operations"],"idempotencyKey":candidate["operationKey"]});
    let legacy = notes.is_none() && record["identity"] == crate::state::json_digest(&common);
    let mut current = common;
    current["requestedNotes"] = notes.map(Value::from).unwrap_or(Value::Null);
    ensure!(
        record["identity"] == crate::state::json_digest(&current) || legacy,
        "MANAGED_WORK_RECEIPT_MISMATCH"
    );
    ensure!(
        record["status"] == "submitted"
            && record["workflowId"] == p["workflowId"]
            && record["expectedVersion"] == p["expectedVersion"]
            && record["expectedDefinitionChecksum"] == p["expectedDefinitionChecksum"],
        "MANAGED_WORK_RECEIPT_MISMATCH"
    );
    let body = &record["updateBody"];
    let fields = body.as_object().context("MANAGED_WORK_RECEIPT_MISMATCH")?;
    let (notes_provided, expected_notes) = if legacy {
        ensure!(
            record.get("notesProvided").is_none() && record.get("expectedNotes").is_none(),
            "MANAGED_WORK_RECEIPT_MISMATCH"
        );
        (false, None)
    } else {
        (
            record["notesProvided"]
                .as_bool()
                .context("MANAGED_WORK_RECEIPT_MISMATCH")?,
            Some(
                record["expectedNotes"]
                    .as_str()
                    .context("MANAGED_WORK_RECEIPT_MISMATCH")?,
            ),
        )
    };
    ensure!(
        notes_provided == notes.is_some()
            && (!notes_provided || expected_notes == notes)
            && fields.len() == if notes_provided { 3 } else { 2 },
        "MANAGED_WORK_RECEIPT_MISMATCH"
    );
    ensure!(
        body["expectedVersion"] == p["expectedVersion"]
            && body["definition"].is_object()
            && crate::state::json_digest(&body["definition"]) == record["updateDigest"]
            && crate::state::json_digest(body) == record["payloadDigest"]
            && (!notes_provided || body["notes"].as_str() == expected_notes),
        "MANAGED_WORK_RECEIPT_MISMATCH"
    );
    ensure!(
        response["workflow"]["id"] == p["workflowId"]
            && response["draft"]["definition"].is_object()
            && crate::state::json_digest(&response["draft"]["definition"])
                == record["updateDigest"]
            && response["draft"]["notes"].is_string()
            && expected_notes.is_none_or(|notes| response["draft"]["notes"] == notes),
        "MANAGED_WORK_RECEIPT_MISMATCH"
    );
    Ok(())
}

/// Validate a verified maintenance receipt attached to the original native
/// patch journal. The marker preserves submitted state and carries no replay authority.
pub(crate) fn maintenance_native_patch_resolved(record: &Value) -> Result<bool> {
    let Some(marker) = record.get("maintenanceResolution") else {
        return Ok(false);
    };
    let fields = marker
        .as_object()
        .context("MANAGED_WORK_RECEIPT_MISMATCH")?;
    ensure!(
        fields.len() == 5
            && [
                "schema",
                "originalJournalDigest",
                "candidate",
                "canonicalReceipt",
                "receiptDigest"
            ]
            .iter()
            .all(|key| fields.contains_key(*key))
            && marker["schema"] == "loomex.native-patch-reconciliation/v1",
        "MANAGED_WORK_RECEIPT_MISMATCH"
    );
    let mut original = record.clone();
    original
        .as_object_mut()
        .context("MANAGED_WORK_RECEIPT_MISMATCH")?
        .remove("maintenanceResolution");
    let candidate = &marker["candidate"];
    let receipt = &marker["canonicalReceipt"];
    ensure!(
        candidate["kind"] == "presentation_operation"
            && candidate["method"] == "workflows.patch"
            && marker["originalJournalDigest"] == crate::state::json_digest(&original)
            && candidate["nativePatchJournal"] == original
            && candidate["recordDigest"] == operation_binding_digest(candidate)
            && marker["receiptDigest"] == crate::state::json_digest(receipt),
        "MANAGED_WORK_RECEIPT_MISMATCH"
    );
    verify_maintenance_operation_receipt(candidate, receipt)?;
    Ok(true)
}

fn validate_catalog_result(method: &str, result: &Value) -> Result<()> {
    ensure!(
        result.is_object() && result.get("responseRef").is_none(),
        "MANAGED_WORK_RECEIPT_MISMATCH"
    );
    let catalog: Value = serde_json::from_str(include_str!("../contracts/method-catalog.json"))?;
    let output = &catalog["methods"]
        .as_array()
        .context("INTERNAL")?
        .iter()
        .find(|v| v["name"] == method)
        .context("INTERNAL")?["outputSchema"];
    let variants = output["oneOf"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or_else(|| std::slice::from_ref(output));
    ensure!(
        variants
            .iter()
            .filter(
                |schema| schema.get("required").and_then(Value::as_array).is_some()
                    && schema["properties"].get("responseRef").is_none()
            )
            .any(|schema| crate::control::validate_params(result, schema).is_ok()),
        "MANAGED_WORK_RECEIPT_MISMATCH"
    );
    Ok(())
}

pub(crate) fn verify_maintenance_operation_receipt(
    candidate: &Value,
    receipt: &Value,
) -> Result<()> {
    let plan = maintenance_operation_plan(candidate)?;
    let route = plan["method"].as_str().context("INTERNAL")?;
    let operation = plan["params"]["operation"].as_str().context("INTERNAL")?;
    ensure!(
        receipt["operation"] == operation
            && receipt["status"] == "completed"
            && receipt["response"].is_object()
            && receipt.get("responseRef").is_none(),
        "MANAGED_WORK_RECEIPT_MISMATCH"
    );
    if route == "personas.operations.get" {
        crate::control::verify_persona_receipt(&candidate["reconciliation"]["params"], receipt)
            .map_err(|_| anyhow::anyhow!("MANAGED_WORK_RECEIPT_MISMATCH"))?;
    } else {
        validate_catalog_result(route, receipt)?;
        ensure!(
            receipt["idempotencyKey"] == candidate["operationKey"],
            "MANAGED_WORK_RECEIPT_MISMATCH"
        );
    }
    let method = required(candidate, "method")?;
    validate_catalog_result(method, &receipt["response"])?;
    if ["builder.start", "editor.start"].contains(&method) {
        crate::control::verify_native_authoring_start(method, &receipt["response"])
            .map_err(|_| anyhow::anyhow!("MANAGED_WORK_RECEIPT_MISMATCH"))?;
    }
    crate::control::verify_persona_creation(method, &candidate["params"], &receipt["response"])
        .map_err(|_| anyhow::anyhow!("MANAGED_WORK_RECEIPT_MISMATCH"))?;
    if method == "workflows.patch" {
        verify_native_patch_journal(candidate, &receipt["response"])?;
    }
    if ["workflows.update", "workflows.publish", "workflows.patch"].contains(&method) {
        ensure!(
            receipt["response"]["workflow"]["id"] == candidate["params"]["workflowId"],
            "MANAGED_WORK_RECEIPT_MISMATCH"
        );
    }
    Ok(())
}

fn settle_operation(c: &Connection, scope: Scope<'_>, p: &Value) -> Result<Value> {
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
    if let Some(value) = receipt(c, scope, "presentation.operations.settle", key, &digest)? {
        return Ok(value);
    }
    let current: Option<String> = c.query_row(
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
    c.execute(
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
            c.execute(
                    "UPDATE presentation_sessions SET expires_at=CASE WHEN status IN ('inactive','resolved') THEN ?1 ELSE NULL END WHERE view_session_id=?2 AND organization_id=?3 AND account_subject=?4",
                    params![now.saturating_add(RETENTION_SECONDS), session, scope.organization, scope.account],
                )?;
        }
        "ambiguous" => {
            c.execute(
                    "UPDATE presentation_sessions SET expires_at=NULL WHERE view_session_id=?1 AND organization_id=?2 AND account_subject=?3",
                    params![session, scope.organization, scope.account],
                )?;
        }
        _ => unreachable!("status validated above"),
    }
    let result = json!({"operationId":operation,"viewSessionId":session,"status":status,"updatedAt":now,"resultReference":reference});
    save_receipt(
        c,
        scope,
        "presentation.operations.settle",
        key,
        &digest,
        &result,
        now,
    )?;
    Ok(result)
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
                "expiresAt":row.get::<_,Option<u64>>(8)?,"operation":unresolved_operation(connection,scope,id)?
            }))
        },
    ).optional()?.context("VIEW_SESSION_NOT_FOUND")
}

/// Read-only canonical snapshot projection, also used by strict uninstall assessment.
pub fn maintenance_delivery_candidates(c: &Connection) -> Result<Vec<Value>> {
    let mut stmt=c.prepare("SELECT organization_id,account_subject,identity,continuation_json,revision,status,attempt_id,error_code,created_at,updated_at FROM presentation_deliveries ORDER BY organization_id,account_subject,identity")?;
    let rows = stmt
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, Vec<u8>>(3)?,
                r.get::<_, u64>(4)?,
                r.get::<_, String>(5)?,
                r.get::<_, Option<String>>(6)?,
                r.get::<_, Option<String>>(7)?,
                r.get::<_, u64>(8)?,
                r.get::<_, u64>(9)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    rows.into_iter().map(|(org,account,id,bytes,revision,status,attempt,error,created,updated)| {
        let continuation=decode(&bytes)?;
        let mut v=json!({"kind":"presentation_delivery","retirementEligible":continuation["kind"]=="follow","organizationId":org,"accountSubject":account,"installationId":"","recordId":id,"runId":continuation["runId"],"revision":revision,"generation":null,"attemptId":attempt,"status":status,"recordDigest":crate::state::json_digest(&json!([continuation,revision,status,attempt,error,created,updated]))});
        v["resolution"]=crate::continuation_resolution::projection(c,"presentation_delivery",&org,&account,"",&id)?;
        v["backendObservation"]=crate::continuation_resolution::observation(c,&v)?;
        Ok(v)
    }).collect()
}

pub fn maintenance_resolved(c: &Connection, candidate: &Value) -> Result<bool> {
    crate::continuation_resolution::resolved(c, candidate)
}

fn delivery_projection(connection: &Connection, scope: Scope<'_>, identity: &str) -> Result<Value> {
    let result = connection
        .query_row(
            "SELECT continuation_json,revision,status,attempt_id FROM presentation_deliveries WHERE organization_id=?1 AND account_subject=?2 AND identity=?3",
            params![scope.organization, scope.account, identity],
            |row| {
                let continuation: Vec<u8> = row.get(0)?;
                Ok(json!({
                    "schemaVersion":2,
                    "identity":identity,
                    "continuation":decode_sql(&continuation)?,
                    "revision":row.get::<_,u64>(1)?,
                    "status":row.get::<_,String>(2)?,
                    "attemptId":row.get::<_,Option<String>>(3)?,
                }))
            },
        )
        .optional()?
        .context("DELIVERY_NOT_READY")?;
    delivery_resolution_projection(connection, scope, identity, result)
}

fn delivery_resolution_projection(
    connection: &Connection,
    scope: Scope<'_>,
    identity: &str,
    mut result: Value,
) -> Result<Value> {
    result["resolution"] = crate::continuation_resolution::projection(
        connection,
        "presentation_delivery",
        scope.organization,
        scope.account,
        "",
        identity,
    )?;
    result["continuationEligible"] = json!(result["resolution"]["state"] == "unresolved");
    Ok(result)
}

/// Narrow, versioned projection for UI re-entry.  Keep this separate from
/// `session_projection`: `get` is a compatibility surface and deliberately
/// retains its full existing projection.
fn restore_projection(connection: &Connection, scope: Scope<'_>, id: &str) -> Result<Value> {
    let row: Option<(String, String, String, u64, Vec<u8>, String)> = connection.query_row(
        "SELECT kind,entity_type,entity_id,revision,state_json,status FROM presentation_sessions WHERE view_session_id=?1 AND organization_id=?2 AND account_subject=?3",
        params![id, scope.organization, scope.account],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?)),
    ).optional()?;
    let (kind, entity_type, entity_id, revision, state, status) =
        row.context("VIEW_SESSION_NOT_FOUND")?;
    let state = decode_sql(&state)?;
    // Stored state is validated before every write.  Validate again at the
    // restoration boundary so a malformed or unsafe local row cannot be
    // promoted into the immediate-paint projection.
    validate_presentation_json(&state)?;
    Ok(json!({
        "restoreVersion":"presentation.sessions.restore/v1",
        "viewSessionId":id,"kind":kind,"entityType":entity_type,
        "entityId":entity_id,"revision":revision,"state":restore_state_projection(&state),
        "status":status,"pendingOperation":unresolved_operation(connection,scope,id)?,"details":{}
    }))
}

/// The restore API is an immediate, display-only projection. Full state stays
/// behind the later owner-checked `presentation.sessions.get` read. In
/// particular, setup controls can contain a workspace path and forms can
/// contain draft values, neither of which belongs in this fast surface.
fn restore_state_projection(state: &Value) -> Value {
    let Some(source) = state.as_object() else {
        return json!({});
    };
    let mut projected = serde_json::Map::new();
    if source
        .get("schemaVersion")
        .and_then(Value::as_u64)
        .is_some()
    {
        projected.insert("schemaVersion".into(), source["schemaVersion"].clone());
    }
    if let Some(screen) = safe_restore_screen(source.get("screen")) {
        projected.insert("screen".into(), Value::String(screen));
    }
    if let Some(display) = safe_display_projection(source.get("display")) {
        projected.insert("display".into(), display);
    }
    Value::Object(projected)
}

fn safe_restore_screen(value: Option<&Value>) -> Option<String> {
    let screen = value?.as_str()?;
    [
        "browser",
        "detail",
        "setup",
        "review",
        "monitor",
        "interaction",
        "runs",
        "authoring",
    ]
    .contains(&screen)
    .then(|| screen.to_owned())
}

fn safe_restore_text(value: Option<&Value>, maximum: usize) -> Option<String> {
    let text = value?.as_str()?.trim();
    (!text.is_empty() && text.len() <= maximum).then(|| text.to_owned())
}

fn safe_display_projection(value: Option<&Value>) -> Option<Value> {
    let source = value?.as_object()?;
    let mut projected = serde_json::Map::new();
    if let Some(screen) = safe_restore_screen(source.get("screen")) {
        projected.insert("screen".into(), Value::String(screen));
    }
    for (key, maximum) in [
        ("workflowName", 160),
        ("title", 160),
        ("stageLabel", 160),
        ("currentNodeName", 160),
        ("status", 64),
        ("description", 280),
    ] {
        if let Some(text) = safe_restore_text(source.get(key), maximum) {
            projected.insert(key.into(), Value::String(text));
        }
    }
    if let Some(entity_id) = source
        .get("entityId")
        .and_then(Value::as_str)
        .filter(|id| Uuid::parse_str(id).is_ok())
    {
        projected.insert("entityId".into(), Value::String(entity_id.to_owned()));
    }
    for key in ["version", "latestSequence", "nodeCount"] {
        if let Some(number) = source.get(key).and_then(Value::as_u64) {
            projected.insert(key.into(), Value::Number(number.into()));
        }
    }
    let rows = source.get("rows").and_then(Value::as_array).map(|rows| {
        rows.iter()
            .take(5)
            .filter_map(safe_display_row)
            .collect::<Vec<_>>()
    });
    if let Some(rows) = rows.filter(|rows| !rows.is_empty()) {
        projected.insert("rows".into(), Value::Array(rows));
    }
    (!projected.is_empty()).then_some(Value::Object(projected))
}

fn safe_display_row(value: &Value) -> Option<Value> {
    let source = value.as_object()?;
    let id = source.get("id")?.as_str()?;
    if Uuid::parse_str(id).is_err() {
        return None;
    }
    let mut row = serde_json::Map::from_iter([(String::from("id"), Value::String(id.to_owned()))]);
    for (key, maximum) in [("name", 160), ("description", 280), ("status", 64)] {
        if let Some(text) = safe_restore_text(source.get(key), maximum) {
            row.insert(key.into(), Value::String(text));
        }
    }
    for key in ["version", "nodeCount"] {
        if let Some(number) = source.get(key).and_then(Value::as_u64) {
            row.insert(key.into(), Value::Number(number.into()));
        }
    }
    Some(Value::Object(row))
}

fn unresolved_operation(
    connection: &Connection,
    scope: Scope<'_>,
    session: &str,
) -> rusqlite::Result<Option<Value>> {
    connection.query_row(
        "SELECT operation_id,status FROM presentation_operations WHERE view_session_id=?1 AND organization_id=?2 AND account_subject=?3 AND status IN ('pending','ambiguous') ORDER BY created_at DESC LIMIT 1",
        params![session, scope.organization, scope.account], |row| Ok(json!({"operationId":row.get::<_,String>(0)?,"status":row.get::<_,String>(1)?})),
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

fn decode(bytes: &[u8]) -> Result<Value> {
    Ok(serde_json::from_slice(bytes)?)
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

fn validate_delivery_identity(identity: &str) -> Result<()> {
    ensure!(
        !identity.is_empty()
            && identity.len() <= 384
            && !identity.chars().any(char::is_whitespace)
            && (identity.starts_with("start:")
                || identity.starts_with("follow:")
                || identity.starts_with("question:")
                || identity.starts_with("persona:")),
        "INVALID_REQUEST"
    );
    Ok(())
}

fn validate_safe_error_code(code: &str) -> Result<()> {
    ensure!(
        !code.is_empty()
            && code.len() <= 64
            && code
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_'),
        "INVALID_REQUEST"
    );
    Ok(())
}

fn validate_continuation(value: &Value) -> Result<()> {
    let object = value.as_object().context("INVALID_REQUEST")?;
    let kind = required(value, "kind")?;
    match kind {
        "follow" => {
            ensure!(
                object.keys().all(|key| {
                    [
                        "kind",
                        "schemaVersion",
                        "runId",
                        "receipt",
                        "trigger",
                        "requestId",
                        "requestStatus",
                    ]
                    .contains(&key.as_str())
                }),
                "INVALID_REQUEST"
            );
            ensure!(
                required(value, "schemaVersion")? == "loomex.follow-session.continuation/v1",
                "INVALID_REQUEST"
            );
            required_uuid(value, "runId")?;
            let receipt = required(value, "receipt")?;
            ensure!(
                (16..=2048).contains(&receipt.len())
                    && receipt
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-'),
                "INVALID_REQUEST"
            );
            ensure!(required(value, "trigger")?.len() <= 64, "INVALID_REQUEST");
            if let Some(request) = value.get("requestId").filter(|value| !value.is_null()) {
                ensure!(
                    request
                        .as_str()
                        .is_some_and(|id| Uuid::parse_str(id).is_ok()),
                    "INVALID_REQUEST"
                );
            }
            if let Some(status) = value.get("requestStatus").filter(|value| !value.is_null()) {
                ensure!(
                    status
                        .as_str()
                        .is_some_and(|status| !status.is_empty() && status.len() <= 32),
                    "INVALID_REQUEST"
                );
            }
        }
        "start" => {
            ensure!(
                object
                    .keys()
                    .all(|key| ["kind", "schemaVersion", "handoffRef"].contains(&key.as_str())),
                "INVALID_REQUEST"
            );
            ensure!(
                required(value, "schemaVersion")? == "loomex.start-continuation/v1",
                "INVALID_REQUEST"
            );
            required_uuid(value, "handoffRef")?;
        }
        "persona_chat" => {
            ensure!(
                object.len() == 6
                    && object.keys().all(|key| [
                        "kind",
                        "personId",
                        "organizationId",
                        "conversationId",
                        "chatId",
                        "configDigest"
                    ]
                    .contains(&key.as_str())),
                "INVALID_REQUEST"
            );
            for key in ["personId", "organizationId", "conversationId", "chatId"] {
                required_uuid(value, key)?;
            }
            let digest = required(value, "configDigest")?;
            ensure!(
                digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit()),
                "INVALID_REQUEST"
            );
        }
        "question" => {
            ensure!(
                object.keys().all(|key| {
                    ["kind", "schemaVersion", "requestId", "schemaDigest"].contains(&key.as_str())
                }),
                "INVALID_REQUEST"
            );
            ensure!(
                required(value, "schemaVersion")? == "loomex.question-continuation/v1",
                "INVALID_REQUEST"
            );
            required_uuid(value, "requestId")?;
            let digest = required(value, "schemaDigest")?;
            ensure!(
                digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit()),
                "INVALID_REQUEST"
            );
        }
        _ => bail!("INVALID_REQUEST"),
    }
    ensure!(serde_json::to_vec(value)?.len() <= 4096, "INVALID_REQUEST");
    Ok(())
}

fn validate_kind(kind: &str) -> Result<()> {
    ensure!(
        [
            "browser",
            "authoring",
            "prepare",
            "monitor",
            "interaction",
            "runs",
            "connection",
            "organizations",
            "personas",
            "personaChat"
        ]
        .contains(&kind),
        "INVALID_REQUEST"
    );
    Ok(())
}

fn validate_entity(session_kind: &str, entity_type: &str, id: &str) -> Result<()> {
    ensure!(
        [
            "catalog",
            "workflow",
            "request",
            "execution",
            "builderSession",
            "preparation",
            "personaRole",
            "persona",
            "personaConversation"
        ]
        .contains(&entity_type),
        "INVALID_REQUEST"
    );
    Uuid::parse_str(id).map_err(|_| anyhow::anyhow!("INVALID_REQUEST"))?;
    ensure!(
        entity_type == "catalog" || id != NIL_UUID,
        "INVALID_REQUEST"
    );
    ensure!(
        entity_type != "catalog" || id == NIL_UUID,
        "INVALID_REQUEST"
    );
    // The run-list view is a workspace-wide catalog projection.  Keeping its
    // binding at the nil catalog UUID prevents it from being confused with a
    // single execution or workflow session during restore.
    ensure!(
        session_kind != "runs" || entity_type == "catalog",
        "INVALID_REQUEST"
    );
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
        let contract: Value =
            serde_json::from_str(include_str!("../contracts/mutation-recovery.json"))?;
        if let Some(rule) = contract["reconciliation"].get(mutation) {
            let identity = rule["identity"].as_str().context("INTERNAL")?;
            ensure!(
                reconciliation["method"] == rule["method"]
                    && reconciliation["params"][identity] == value["params"][identity]
                    && value["params"][identity].is_string()
                    && rule
                        .get("operation")
                        .is_none_or(|operation| reconciliation["params"]["operation"] == *operation)
                    && (identity != "idempotencyKey"
                        || value["params"][identity] == value["idempotencyKey"]),
                "INVALID_REQUEST"
            );
        }
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
        "capability",
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
        "prompt",
        "toolinstructions",
        "effectiveconfig",
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

    fn delivery_continuation(run: &str) -> Value {
        json!({
            "kind":"follow",
            "schemaVersion":"loomex.follow-session.continuation/v1",
            "runId":run,
            "receipt":"abcdefghijklmnop",
            "trigger":"accepted_interaction",
            "requestId":Uuid::new_v4(),
            "requestStatus":"resolved",
        })
    }

    fn domain_journal(
        store: &PresentationStore,
        method: &str,
        params: Value,
        route: &str,
        operation: &str,
    ) -> Value {
        let session = create(store);
        let key = params["idempotencyKey"].clone();
        store.update(scope(),&json!({"viewSessionId":session["viewSessionId"],"expectedRevision":0,"state":{},"operation":{"method":method,"params":params,"idempotencyKey":key,"reconciliation":{"method":route,"params":{"operation":operation,"idempotencyKey":key}}},"idempotencyKey":Uuid::new_v4()})).unwrap();
        let mut request = store.maintenance_operation_candidates().unwrap().remove(0);
        request["idempotencyKey"] = json!(Uuid::new_v4());
        request
    }
    fn publish_receipt(request: &Value) -> Value {
        json!({"operation":"workflows.publish","idempotencyKey":request["operationKey"],"status":"completed","response":{"workflow":{"id":request["params"]["workflowId"]},"version":{"id":Uuid::new_v4(),"number":2}}})
    }

    #[test]
    fn maintenance_patch_receipt_requires_original_native_journal_target_and_payload() {
        let t = tempfile::tempdir().unwrap();
        let store = PresentationStore::open(t.path()).unwrap();
        let params = json!({"workflowId":Uuid::new_v4(),"expectedVersion":2,"expectedDefinitionChecksum":"a".repeat(64),"operations":[{"nodeKey":"node","op":"replace","path":"/prompt","value":"private replacement"}],"idempotencyKey":Uuid::new_v4()});
        let mut candidate = domain_journal(
            &store,
            "workflows.patch",
            params,
            "workflow.operations.get",
            "workflows.update",
        );
        let body = json!({"definition":{"nodes":[{"key":"node","prompt":"private replacement"}]},"expectedVersion":2});
        let identity = crate::state::json_digest(
            &json!({"organizationId":candidate["organizationId"],"accountSubject":candidate["accountSubject"],"workflowId":candidate["params"]["workflowId"],"expectedVersion":2,"expectedDefinitionChecksum":"a".repeat(64),"operations":candidate["params"]["operations"],"requestedNotes":null,"idempotencyKey":candidate["operationKey"]}),
        );
        let journal = json!({"identity":identity,"workflowId":candidate["params"]["workflowId"],"expectedVersion":2,"expectedDefinitionChecksum":"a".repeat(64),"updateBody":body,"updateDigest":crate::state::json_digest(&body["definition"]),"payloadDigest":crate::state::json_digest(&body),"notesProvided":false,"expectedNotes":"original notes","status":"submitted"});
        let receipt = json!({"operation":"workflows.update","idempotencyKey":candidate["operationKey"],"status":"completed","response":{"workflow":{"id":candidate["params"]["workflowId"]},"draft":{"definition":body["definition"],"notes":"original notes"}}});
        assert_eq!(
            maintenance_operation_plan(&candidate).unwrap(),
            json!({"method":"workflow.operations.get","params":{"operation":"workflows.update","idempotencyKey":candidate["operationKey"]}})
        );
        assert!(
            store
                .maintenance_operation_settle(&candidate, &receipt)
                .is_err()
        );
        candidate["nativePatchJournal"] = journal;
        for field in ["identity", "workflowId", "updateDigest", "payloadDigest"] {
            let mut wrong = candidate.clone();
            wrong["nativePatchJournal"][field] = json!("wrong");
            assert!(
                store
                    .maintenance_operation_settle(&wrong, &receipt)
                    .is_err()
            );
        }
        let mut wrong = receipt.clone();
        wrong["response"]["draft"]["definition"] = json!({"nodes":[]});
        assert!(
            store
                .maintenance_operation_settle(&candidate, &wrong)
                .is_err()
        );
        let mut native = candidate["nativePatchJournal"].clone();
        assert!(!maintenance_native_patch_resolved(&native).unwrap());
        native["maintenanceResolution"] = json!({"schema":"loomex.native-patch-reconciliation/v1","originalJournalDigest":crate::state::json_digest(&candidate["nativePatchJournal"]),"candidate":candidate,"canonicalReceipt":receipt,"receiptDigest":crate::state::json_digest(&receipt)});
        assert!(maintenance_native_patch_resolved(&native).unwrap());
        let mut changed = native.clone();
        changed["maintenanceResolution"]["receiptDigest"] = json!("wrong");
        assert!(maintenance_native_patch_resolved(&changed).is_err());
        let mut changed = native.clone();
        changed["updateDigest"] = json!("wrong");
        assert!(maintenance_native_patch_resolved(&changed).is_err());
        let mut changed = native.clone();
        changed["maintenanceResolution"]["candidate"]["params"]["idempotencyKey"] =
            json!(Uuid::new_v4());
        assert!(maintenance_native_patch_resolved(&changed).is_err());
        let mut changed = native;
        changed["maintenanceResolution"] = json!({});
        assert!(maintenance_native_patch_resolved(&changed).is_err());
        let settled = store
            .maintenance_operation_settle(&candidate, &receipt)
            .unwrap();
        assert_eq!(settled["state"], "reconciled");
        assert_eq!(settled["method"], "workflows.patch");
        assert!(!settled.to_string().contains("private replacement"));
        let historical = tempfile::tempdir().unwrap();
        let second = PresentationStore::open(historical.path()).unwrap();
        let mut historical_request = domain_journal(
            &second,
            "workflows.patch",
            candidate["params"].clone(),
            "workflow.operations.get",
            "workflows.update",
        );
        historical_request["nativePatchJournal"] = candidate["nativePatchJournal"].clone();
        second.operation_settle(scope(),&json!({"viewSessionId":historical_request["viewSessionId"],"operationId":historical_request["operationId"],"status":"completed","resultReference":{"originalResult":"preserve historical outcome"},"idempotencyKey":Uuid::new_v4()})).unwrap();
        let original=second.operation_get(scope(),&json!({"viewSessionId":historical_request["viewSessionId"],"operationId":historical_request["operationId"]})).unwrap();
        let mut completed = second.maintenance_operation_candidates().unwrap().remove(0);
        completed["nativePatchJournal"] = historical_request["nativePatchJournal"].clone();
        completed["idempotencyKey"] = json!(Uuid::new_v4());
        let proof = second
            .maintenance_operation_settle(&completed, &receipt)
            .unwrap();
        assert_eq!(
            proof,
            maintenance_operation_summary(&completed, &receipt).unwrap()
        );
        assert_eq!(
            second
                .maintenance_operation_settle(&completed, &receipt)
                .unwrap(),
            proof
        );
        assert_eq!(second.operation_get(scope(),&json!({"viewSessionId":completed["viewSessionId"],"operationId":completed["operationId"]})).unwrap(),original);
    }

    #[test]
    fn maintenance_domain_summary_never_contains_private_arguments_responses_or_keys() {
        let t = tempfile::tempdir().unwrap();
        let store = PresentationStore::open(t.path()).unwrap();
        let request = domain_journal(
            &store,
            "workflows.publish",
            json!({"workflowId":Uuid::new_v4(),"expectedVersion":1,"notes":"PRIVATE_ARGUMENT_SENTINEL","idempotencyKey":Uuid::new_v4()}),
            "workflow.operations.get",
            "workflows.publish",
        );
        let mut receipt = publish_receipt(&request);
        receipt["response"]["workflow"]["name"] = json!("PRIVATE_RESPONSE_SENTINEL");
        let summary = store
            .maintenance_operation_settle(&request, &receipt)
            .unwrap();
        let candidate = store.maintenance_operation_candidates().unwrap().remove(0);
        assert_eq!(candidate["resolution"], summary);
        let encoded = serde_json::to_string(&summary).unwrap();
        for forbidden in [
            "PRIVATE_ARGUMENT_SENTINEL",
            "PRIVATE_RESPONSE_SENTINEL",
            request["operationKey"].as_str().unwrap(),
            request["operationId"].as_str().unwrap(),
            request["viewSessionId"].as_str().unwrap(),
            request["accountSubject"].as_str().unwrap(),
        ] {
            assert!(!encoded.contains(forbidden));
        }
        assert_eq!(
            summary["receiptDigest"],
            crate::state::json_digest(&receipt)
        );
    }

    #[test]
    fn maintenance_domain_descriptor_never_replays_unsupported_mutations() {
        let t = tempfile::tempdir().unwrap();
        let store = PresentationStore::open(t.path()).unwrap();
        let session = create(&store);
        store.update(scope(),&json!({"viewSessionId":session["viewSessionId"],"expectedRevision":0,"state":{},"operation":{"method":"runs.commit","params":{"preparationId":Uuid::new_v4(),"confirmationKey":"PRIVATE_CAPABILITY"},"idempotencyKey":Uuid::new_v4()},"idempotencyKey":Uuid::new_v4()})).unwrap();
        let mut candidate = store.maintenance_operation_candidates().unwrap().remove(0);
        assert_eq!(candidate["reconciliationSupported"], false);
        candidate["idempotencyKey"] = json!(Uuid::new_v4());
        assert!(
            store
                .maintenance_operation_settle(
                    &candidate,
                    &json!({"status":"completed","response":{}})
                )
                .is_err()
        );
        assert_eq!(
            store.maintenance_operation_candidates().unwrap()[0]["status"],
            "pending"
        );
    }

    #[test]
    fn maintenance_domain_receipt_settlement_uses_exact_journal_and_replays_owner_receipt() {
        let t = tempfile::tempdir().unwrap();
        let store = PresentationStore::open(t.path()).unwrap();
        let request = domain_journal(
            &store,
            "workflows.publish",
            json!({"workflowId":Uuid::new_v4(),"expectedVersion":1,"idempotencyKey":Uuid::new_v4()}),
            "workflow.operations.get",
            "workflows.publish",
        );
        let receipt = publish_receipt(&request);
        let settled = store
            .maintenance_operation_settle(&request, &receipt)
            .unwrap();
        assert_eq!(settled["status"], "completed");
        assert_eq!(
            store
                .maintenance_operation_settle(&request, &receipt)
                .unwrap(),
            settled
        );
        let mut changed = request.clone();
        changed["params"]["notes"] = json!("changed after settlement");
        assert!(
            store
                .maintenance_operation_settle(&changed, &receipt)
                .is_err()
        );
        let current = store.maintenance_operation_candidates().unwrap().remove(0);
        assert_eq!(current["recordDigest"], request["recordDigest"]);
        assert_eq!(current["resolution"]["state"], "reconciled");
        assert_eq!(current["operationKey"], request["operationKey"]);
        let journal=store.operation_get(scope(),&json!({"viewSessionId":request["viewSessionId"],"operationId":request["operationId"]})).unwrap();
        assert_eq!(journal["params"], request["params"]);
        assert_eq!(
            journal["resultReference"]["maintenanceDomainReceipt"]["responseDigest"],
            crate::state::json_digest(&receipt["response"])
        );
        assert!(store.operation_settle(scope(),&json!({"viewSessionId":request["viewSessionId"],"operationId":request["operationId"],"status":"completed","idempotencyKey":Uuid::new_v4()})).is_err());
    }

    #[test]
    fn maintenance_domain_receipt_never_settles_wrong_pending_or_spooled_outcome() {
        let t = tempfile::tempdir().unwrap();
        let store = PresentationStore::open(t.path()).unwrap();
        let request = domain_journal(
            &store,
            "workflows.publish",
            json!({"workflowId":Uuid::new_v4(),"expectedVersion":1,"idempotencyKey":Uuid::new_v4()}),
            "workflow.operations.get",
            "workflows.publish",
        );
        let valid = publish_receipt(&request);
        for (field, value) in [
            ("operation", json!("workflows.update")),
            ("idempotencyKey", json!(Uuid::new_v4())),
            ("status", json!("pending")),
            ("status", json!("not_found")),
            ("response", json!({})),
            ("responseRef", json!(Uuid::new_v4())),
        ] {
            let mut wrong = valid.clone();
            wrong[field] = value;
            assert!(
                store
                    .maintenance_operation_settle(&request, &wrong)
                    .is_err()
            );
        }
        let mut wrong = valid;
        wrong["response"]["workflow"]["id"] = json!(Uuid::new_v4());
        assert!(
            store
                .maintenance_operation_settle(&request, &wrong)
                .is_err()
        );
        assert_eq!(
            store.maintenance_operation_candidates().unwrap()[0]["status"],
            "pending"
        );
    }

    #[test]
    fn maintenance_domain_journal_revision_arguments_and_scope_are_fenced() {
        for changed in ["revision", "params", "operationKey", "accountSubject"] {
            let t = tempfile::tempdir().unwrap();
            let store = PresentationStore::open(t.path()).unwrap();
            let mut request = domain_journal(
                &store,
                "workflows.publish",
                json!({"workflowId":Uuid::new_v4(),"expectedVersion":1,"idempotencyKey":Uuid::new_v4()}),
                "workflow.operations.get",
                "workflows.publish",
            );
            let receipt = publish_receipt(&request);
            let c = store.connection.lock().unwrap();
            match changed {
                "revision" => {
                    c.execute("UPDATE presentation_sessions SET revision=revision+1", [])
                        .unwrap();
                }
                "params" => {
                    let mut changed = request["params"].clone();
                    changed["expectedVersion"] = json!(2);
                    c.execute(
                        "UPDATE presentation_operations SET params_json=?1",
                        params![serde_json::to_vec(&changed).unwrap()],
                    )
                    .unwrap();
                }
                "operationKey" => {
                    c.execute(
                        "UPDATE presentation_operations SET operation_key=?1",
                        params![Uuid::new_v4().to_string()],
                    )
                    .unwrap();
                }
                _ => {
                    request["accountSubject"] = json!("another-account");
                }
            }
            drop(c);
            assert!(
                store
                    .maintenance_operation_settle(&request, &receipt)
                    .is_err()
            );
            assert_eq!(
                store.maintenance_operation_candidates().unwrap()[0]["status"],
                "pending"
            );
        }
    }

    #[test]
    fn maintenance_persona_receipt_uses_existing_strict_shape_validation() {
        let t = tempfile::tempdir().unwrap();
        let store = PresentationStore::open(t.path()).unwrap();
        let request = domain_journal(
            &store,
            "personas.memory.write",
            json!({"personId":Uuid::new_v4(),"conversationId":Uuid::new_v4(),"chatId":Uuid::new_v4(),"arguments":{"content":"private durable fact"},"idempotencyKey":Uuid::new_v4()}),
            "personas.operations.get",
            "memory.write",
        );
        let mut receipt = json!({"operation":"memory.write","key":request["operationKey"],"status":"completed","requestDigest":"bad","response":{"result":{"candidateId":Uuid::new_v4()}}});
        assert!(
            store
                .maintenance_operation_settle(&request, &receipt)
                .is_err()
        );
        receipt["requestDigest"] = json!("a".repeat(64));
        assert_eq!(
            store
                .maintenance_operation_settle(&request, &receipt)
                .unwrap()["status"],
            "completed"
        );
    }

    #[test]
    fn maintenance_native_authoring_receipt_only_settles_acceptance_journal() {
        let t = tempfile::tempdir().unwrap();
        let store = PresentationStore::open(t.path()).unwrap();
        let request = domain_journal(
            &store,
            "builder.start",
            json!({"prompt":"private workflow idea","idempotencyKey":Uuid::new_v4()}),
            "workflow.operations.get",
            "builder.start",
        );
        let session = Uuid::new_v4();
        let receipt = json!({"operation":"builder.start","idempotencyKey":request["operationKey"],"status":"completed","response":{"schemaVersion":"loomex.native-authoring-session/v1","sessionId":session,"builderSessionId":session,"executionId":Uuid::new_v4(),"status":"queued","systemWorkflowKey":"workflow_builder","systemWorkflowVersionId":Uuid::new_v4(),"systemWorkflowDefinitionChecksum":"a".repeat(64),"nextAction":"run_get"}});
        assert_eq!(
            store
                .maintenance_operation_settle(&request, &receipt)
                .unwrap()["status"],
            "completed"
        );
        assert!(store.maintenance_candidates().unwrap().is_empty());
        let encoded = serde_json::to_string(
            &store.maintenance_operation_candidates().unwrap()[0]["resultReference"],
        )
        .unwrap();
        assert!(!encoded.contains("private workflow idea"));
        assert!(!encoded.contains("terminal"));
    }

    #[test]
    fn terminal_backend_fact_preserves_unknown_delivery_until_explicit_retirement() {
        let t = tempfile::tempdir().unwrap();
        let store = PresentationStore::open(t.path()).unwrap();
        let run = Uuid::new_v4().to_string();
        let identity = format!("follow:{run}:run_started");
        store
            .register_delivery("org-a", "user-a", &identity, &delivery_continuation(&run))
            .unwrap();
        let attempt = Uuid::new_v4();
        let begin = json!({"identity":identity,"expectedRevision":0,"attemptId":attempt,"idempotencyKey":Uuid::new_v4()});
        store.delivery_begin(scope(), &begin).unwrap();
        let settle = json!({"identity":identity,"expectedRevision":1,"attemptId":attempt,"status":"unknown","idempotencyKey":Uuid::new_v4()});
        store.delivery_settle(scope(), &settle).unwrap();
        let candidate = store.maintenance_candidates().unwrap().remove(0);
        let mut request = candidate.clone();
        request["idempotencyKey"] = json!(Uuid::new_v4());
        let observation = json!({"snapshot":{"execution":{"id":run,"status":"completed"},"hasMoreEvents":false},"terminalResult":{"execution":{"id":run,"status":"completed"},"hasMoreEvents":false}});
        store.maintenance_reconcile(&request, &observation).unwrap();
        let projected = store
            .delivery_get(scope(), &json!({"identity":identity}))
            .unwrap();
        assert_eq!(projected["status"], "unknown");
        assert_eq!(projected["resolution"]["state"], "unresolved");
        let closed = store.maintenance_retire(&request).unwrap();
        assert_eq!(closed, store.maintenance_retire(&request).unwrap());
        let projected = store
            .delivery_get(scope(), &json!({"identity":identity}))
            .unwrap();
        assert_eq!(projected["status"], "unknown");
        assert_eq!(projected["attemptId"], attempt.to_string());
        assert_eq!(projected["continuationEligible"], false);
        assert!(store.delivery_begin(scope(), &begin).is_err());
        assert!(store.delivery_settle(scope(), &settle).is_err());
        store
            .import_legacy_delivery("org-a", "user-a", &identity)
            .unwrap();
        let registered =
            store.register_delivery("org-a", "user-a", &identity, &delivery_continuation(&run));
        assert!(registered.is_err()); // different request identity cannot replace authority
        let c = store.connection.lock().unwrap();
        assert!(maintenance_resolved(&c, &candidate).unwrap());
    }

    #[test]
    fn retirement_rejects_stale_attempt_and_does_not_rearm_after_sweep() {
        let t = tempfile::tempdir().unwrap();
        let store = PresentationStore::open(t.path()).unwrap();
        let run = Uuid::new_v4().to_string();
        let identity = format!("follow:{run}:run_started");
        let continuation = delivery_continuation(&run);
        store
            .register_delivery("org-a", "user-a", &identity, &continuation)
            .unwrap();
        let candidate = store.maintenance_candidates().unwrap().remove(0);
        let mut request = candidate.clone();
        request["idempotencyKey"] = json!(Uuid::new_v4());
        store.maintenance_reconcile(&request,&json!({"snapshot":{"execution":{"id":run,"status":"running"},"hasMoreEvents":false}})).unwrap();
        store.delivery_begin(scope(),&json!({"identity":identity,"expectedRevision":0,"attemptId":Uuid::new_v4(),"idempotencyKey":Uuid::new_v4()})).unwrap();
        assert_eq!(
            store.maintenance_retire(&request).unwrap_err().to_string(),
            "MANAGED_WORK_CHANGED"
        );
        let candidate = store.maintenance_candidates().unwrap().remove(0);
        let mut request = candidate.clone();
        request["idempotencyKey"] = json!(Uuid::new_v4());
        store.maintenance_reconcile(&request,&json!({"snapshot":{"execution":{"id":run,"status":"running"},"hasMoreEvents":false}})).unwrap();
        store.maintenance_retire(&request).unwrap();
        store
            .sweep(crate::state::now() + RETENTION_SECONDS * 2)
            .unwrap();
        drop(store);
        let store = PresentationStore::open(t.path()).unwrap();
        assert_eq!(
            store
                .register_delivery("org-a", "user-a", &identity, &continuation)
                .unwrap()["continuationEligible"],
            false
        );
    }

    #[test]
    fn delivery_is_owner_scoped_fenced_idempotent_and_durable() {
        let temp = tempfile::tempdir().unwrap();
        let identity = format!("follow:{}:{}", Uuid::new_v4(), Uuid::new_v4());
        let begin_key = Uuid::new_v4();
        let settle_key = Uuid::new_v4();
        let attempt = Uuid::new_v4();
        let store = PresentationStore::open(temp.path()).unwrap();
        let registered = store
            .register_delivery(
                scope().organization,
                scope().account,
                &identity,
                &delivery_continuation(&Uuid::new_v4().to_string()),
            )
            .unwrap();
        assert_eq!(registered["status"], "ready");
        assert_eq!(registered["attemptId"], Value::Null);
        assert_eq!(
            store
                .delivery_get(
                    Scope {
                        organization: scope().organization,
                        account: "other-user",
                    },
                    &json!({"identity":identity}),
                )
                .unwrap_err()
                .to_string(),
            "DELIVERY_NOT_READY"
        );
        let begin = json!({"identity":identity,"expectedRevision":0,"attemptId":attempt,"idempotencyKey":begin_key});
        let sending = store.delivery_begin(scope(), &begin).unwrap();
        assert_eq!(sending["status"], "sending");
        assert_eq!(store.delivery_begin(scope(), &begin).unwrap(), sending);
        assert_eq!(
            store
                .delivery_begin(scope(), &json!({"identity":identity,"expectedRevision":1,"attemptId":Uuid::new_v4(),"idempotencyKey":Uuid::new_v4()}))
                .unwrap_err()
                .to_string(),
            "DELIVERY_NOT_READY"
        );
        let settle = json!({"identity":identity,"expectedRevision":1,"attemptId":attempt,"status":"acknowledged","idempotencyKey":settle_key});
        let acknowledged = store.delivery_settle(scope(), &settle).unwrap();
        assert_eq!(acknowledged["revision"], 2);
        assert_eq!(
            store.delivery_settle(scope(), &settle).unwrap(),
            acknowledged
        );
        drop(store);
        let reopened = PresentationStore::open(temp.path()).unwrap();
        assert_eq!(
            reopened
                .delivery_get(scope(), &json!({"identity":identity}))
                .unwrap(),
            acknowledged
        );
        assert_eq!(
            reopened
                .delivery_begin(scope(), &json!({"identity":identity,"expectedRevision":2,"attemptId":Uuid::new_v4(),"idempotencyKey":Uuid::new_v4()}))
                .unwrap_err()
                .to_string(),
            "DELIVERY_NOT_READY"
        );
    }

    #[test]
    fn delivery_outcomes_have_exact_retry_rules_and_attempt_fences() {
        let temp = tempfile::tempdir().unwrap();
        let store = PresentationStore::open(temp.path()).unwrap();
        for (outcome, retryable) in [
            ("not_sent", true),
            ("rejected", true),
            ("acknowledged", false),
            ("unknown", false),
        ] {
            let run = Uuid::new_v4().to_string();
            let identity = format!("follow:{run}:follow_requested");
            store
                .register_delivery(
                    scope().organization,
                    scope().account,
                    &identity,
                    &delivery_continuation(&run),
                )
                .unwrap();
            let attempt = Uuid::new_v4();
            store
                .delivery_begin(scope(), &json!({"identity":identity,"expectedRevision":0,"attemptId":attempt,"idempotencyKey":Uuid::new_v4()}))
                .unwrap();
            assert_eq!(
                store
                    .delivery_settle(scope(), &json!({"identity":identity,"expectedRevision":1,"attemptId":Uuid::new_v4(),"status":outcome,"idempotencyKey":Uuid::new_v4()}))
                    .unwrap_err()
                    .to_string(),
                "DELIVERY_ATTEMPT_CONFLICT"
            );
            let settled = store
                .delivery_settle(scope(), &json!({"identity":identity,"expectedRevision":1,"attemptId":attempt,"status":outcome,"idempotencyKey":Uuid::new_v4()}))
                .unwrap();
            assert_eq!(settled["status"], outcome);
            let retry = store.delivery_begin(scope(), &json!({"identity":identity,"expectedRevision":2,"attemptId":Uuid::new_v4(),"idempotencyKey":Uuid::new_v4()}));
            assert_eq!(retry.is_ok(), retryable, "outcome {outcome}");
        }
    }

    #[test]
    fn delivery_begin_allows_only_one_concurrent_card() {
        use std::sync::{Arc, Barrier};
        let temp = tempfile::tempdir().unwrap();
        let store = Arc::new(PresentationStore::open(temp.path()).unwrap());
        let run = Uuid::new_v4().to_string();
        let identity = format!("follow:{run}:run_started");
        store
            .register_delivery(
                scope().organization,
                scope().account,
                &identity,
                &delivery_continuation(&run),
            )
            .unwrap();
        let barrier = Arc::new(Barrier::new(3));
        let mut threads = Vec::new();
        for _ in 0..2 {
            let store = Arc::clone(&store);
            let barrier = Arc::clone(&barrier);
            let identity = identity.clone();
            threads.push(std::thread::spawn(move || {
                barrier.wait();
                store.delivery_begin(scope(), &json!({"identity":identity,"expectedRevision":0,"attemptId":Uuid::new_v4(),"idempotencyKey":Uuid::new_v4()}))
            }));
        }
        barrier.wait();
        let results = threads
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter_map(|result| result.as_ref().err())
                .next()
                .unwrap()
                .to_string(),
            "REVISION_CONFLICT"
        );
    }

    #[test]
    fn legacy_delivery_import_never_replays_or_copies_prompt_text() {
        let temp = tempfile::tempdir().unwrap();
        let store = PresentationStore::open(temp.path()).unwrap();
        let run = Uuid::new_v4().to_string();
        let request = Uuid::new_v4().to_string();
        let identity = format!("follow:{run}:{request}");
        store
            .create(
                scope(),
                &json!({
                    "kind":"interaction","entityType":"request","entityId":request,
                    "state":{"continuationDelivery":{"schemaVersion":1,"identity":identity,"purpose":"accepted_interaction","text":"secret answer and full prompt","status":"acknowledged","attemptId":Uuid::new_v4()}},
                    "idempotencyKey":Uuid::new_v4(),
                }),
            )
            .unwrap();
        store
            .register_delivery(
                scope().organization,
                scope().account,
                &identity,
                &delivery_continuation(&run),
            )
            .unwrap();
        store
            .import_legacy_delivery(scope().organization, scope().account, &identity)
            .unwrap();
        let imported = store
            .delivery_get(scope(), &json!({"identity":identity}))
            .unwrap();
        assert_eq!(imported["status"], "acknowledged");
        assert_eq!(imported["revision"], 1);
        assert!(!imported.to_string().contains("secret answer"));
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
    fn restore_is_owner_checked_and_exposes_only_the_safe_display_projection() {
        let temp = tempfile::tempdir().unwrap();
        let store = PresentationStore::open(temp.path()).unwrap();
        let session = create(&store);
        let id = session["viewSessionId"].as_str().unwrap();
        let updated = store
            .update(
                scope(),
                &json!({
                    "viewSessionId":id,
                    "expectedRevision":0,
                    "state":{
                        "schemaVersion":1,
                        "screen":"monitor",
                        "display":{"screen":"monitor","workflowName":"Safe workflow","status":"running"},
                        "controls":{"run-workspace":"/private/workspace"},
                        "answers":{"value":"draft-answer"}
                    },
                    "operation":{
                        "method":"runs.commit",
                        "params":{"confirmationKey":"must-not-leak","preparationId":Uuid::new_v4()},
                        "idempotencyKey":Uuid::new_v4()
                    },
                    "idempotencyKey":Uuid::new_v4()
                }),
            )
            .unwrap();
        let restored = store
            .restore(scope(), &json!({"viewSessionId":id}))
            .unwrap();
        assert_eq!(
            restored,
            json!({
                "restoreVersion":"presentation.sessions.restore/v1",
                "viewSessionId":id,
                "kind":"monitor",
                "entityType":"execution",
                "entityId":session["entityId"],
                "revision":updated["revision"],
                "state":{"schemaVersion":1,"screen":"monitor","display":{"screen":"monitor","workflowName":"Safe workflow","status":"running"}},
                "status":"active",
                "pendingOperation":{
                    "operationId":updated["operation"]["operationId"],
                    "status":"pending"
                },
                "details":{}
            })
        );
        let encoded = restored.to_string();
        for forbidden in [
            "confirmationKey",
            "must-not-leak",
            "idempotencyKey",
            "createdAt",
            "updatedAt",
            "expiresAt",
            "params",
            "reconciliation",
            "private/workspace",
            "answers",
            "draft-answer",
        ] {
            assert!(!encoded.contains(forbidden), "restore leaked {forbidden}");
        }
        assert_eq!(
            store
                .restore(
                    Scope {
                        organization: "org-a",
                        account: "user-b",
                    },
                    &json!({"viewSessionId":id}),
                )
                .unwrap_err()
                .to_string(),
            "VIEW_SESSION_NOT_FOUND"
        );
        assert_eq!(
            store
                .restore(scope(), &json!({"viewSessionId":Uuid::new_v4()}))
                .unwrap_err()
                .to_string(),
            "VIEW_SESSION_NOT_FOUND"
        );

        // `get` remains the legacy full projection, including timestamps and
        // the compatible `operation` key.
        let legacy = store.get(scope(), &json!({"viewSessionId":id})).unwrap();
        assert!(legacy["createdAt"].is_u64());
        assert_eq!(legacy["operation"], restored["pendingOperation"]);
    }

    #[test]
    fn restore_revalidates_state_before_returning_it() {
        let temp = tempfile::tempdir().unwrap();
        let store = PresentationStore::open(temp.path()).unwrap();
        let session = create(&store);
        let id = session["viewSessionId"].as_str().unwrap();
        {
            let connection = store.connection.lock().unwrap();
            connection
                .execute(
                    "UPDATE presentation_sessions SET state_json=?1 WHERE view_session_id=?2",
                    params![encode(&json!({"confirmationKey":"unsafe"})).unwrap(), id],
                )
                .unwrap();
        }
        assert_eq!(
            store
                .restore(scope(), &json!({"viewSessionId":id}))
                .unwrap_err()
                .to_string(),
            "UNSAFE_PRESENTATION_STATE"
        );
    }

    #[test]
    fn runs_session_uses_catalog_binding_and_restores_safe_run_list_state() {
        let temp = tempfile::tempdir().unwrap();
        let store = PresentationStore::open(temp.path()).unwrap();
        let session = store
            .create(
                scope(),
                &json!({
                    "kind":"runs",
                    "entityType":"catalog",
                    "entityId":NIL_UUID,
                    "state":{
                        "schemaVersion":1,
                        "screen":"runs",
                        "display":{
                            "screen":"runs",
                            "title":"Recent runs",
                            "latestSequence":7,
                            "rows":[{"id":Uuid::new_v4(),"name":"Example run","status":"succeeded"}]
                        },
                        "controls":{"workspacePath":"/private/workspace"}
                    },
                    "idempotencyKey":Uuid::new_v4()
                }),
            )
            .unwrap();
        let restored = store
            .restore(scope(), &json!({"viewSessionId":session["viewSessionId"]}))
            .unwrap();
        assert_eq!(restored["kind"], "runs");
        assert_eq!(restored["entityType"], "catalog");
        assert_eq!(restored["entityId"], NIL_UUID);
        assert_eq!(restored["state"]["screen"], "runs");
        assert_eq!(restored["state"]["display"]["title"], "Recent runs");
        assert_eq!(
            restored["state"]["display"]["rows"][0]["status"],
            "succeeded"
        );
        assert!(!restored.to_string().contains("private/workspace"));
        assert!(!restored.to_string().contains("controls"));
    }

    #[test]
    fn runs_session_rejects_non_catalog_entity_binding() {
        let temp = tempfile::tempdir().unwrap();
        let store = PresentationStore::open(temp.path()).unwrap();
        let error = store
            .create(
                scope(),
                &json!({
                    "kind":"runs",
                    "entityType":"execution",
                    "entityId":Uuid::new_v4(),
                    "state":{},
                    "idempotencyKey":Uuid::new_v4()
                }),
            )
            .unwrap_err();
        assert_eq!(error.to_string(), "INVALID_REQUEST");
    }

    #[test]
    fn reconciliation_contract_fences_the_mutation_identity() {
        let request = Uuid::new_v4();
        let mut operation = json!({"method":"interactions.respond","params":{"requestId":request},"idempotencyKey":Uuid::new_v4(),"reconciliation":{"method":"interactions.get","params":{"requestId":request}}});
        validate_operation(&operation).unwrap();
        operation["reconciliation"]["params"]["requestId"] = json!(Uuid::new_v4());
        assert_eq!(
            validate_operation(&operation).unwrap_err().to_string(),
            "INVALID_REQUEST"
        );
        operation["reconciliation"]["params"]["requestId"] = json!(request);
        operation["reconciliation"]["method"] = json!("runs.get");
        assert_eq!(
            validate_operation(&operation).unwrap_err().to_string(),
            "INVALID_REQUEST"
        );
    }

    #[test]
    fn publish_reconciliation_is_bound_to_exact_operation_and_key() {
        let key = Uuid::new_v4();
        let mut operation = json!({"method":"workflows.publish","params":{"workflowId":Uuid::new_v4(),"expectedVersion":2,"idempotencyKey":key},"idempotencyKey":key,"reconciliation":{"method":"workflow.operations.get","params":{"operation":"workflows.publish","idempotencyKey":key}}});
        validate_operation(&operation).unwrap();
        operation["reconciliation"]["params"]["operation"] = json!("workflows.update");
        assert_eq!(
            validate_operation(&operation).unwrap_err().to_string(),
            "INVALID_REQUEST"
        );
        operation["reconciliation"]["params"]["operation"] = json!("workflows.publish");
        operation["reconciliation"]["params"]["idempotencyKey"] = json!(Uuid::new_v4());
        assert_eq!(
            validate_operation(&operation).unwrap_err().to_string(),
            "INVALID_REQUEST"
        );
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
        let request_id = Uuid::new_v4();
        let pending = store.update(scope(), &json!({"viewSessionId":active_id,"expectedRevision":0,"state":{},"operation":{"method":"interactions.respond","params":{"requestId":request_id},"idempotencyKey":Uuid::new_v4(),"reconciliation":{"method":"interactions.get","params":{"requestId":request_id}}},"idempotencyKey":Uuid::new_v4()})).unwrap();
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
            json!({"browserApproval":{"capability":"x"}}),
            json!({"idempotencyKey":"x"}),
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
