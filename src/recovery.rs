//! Durable, owner-scoped coordination for host recovery schedules.
//!
//! This store never creates or inspects a host automation.  It only records the
//! exact intent before the host call and preserves an uncertain outcome so a
//! later process cannot accidentally create a second automation.

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

/// Only a fully removed recovery record is retired automatically.  All other
/// states can still affect a host automation or require reconciliation, so
/// they remain durable until an explicit lifecycle action resolves them.
const RETENTION_SECONDS: u64 = 30 * 24 * 60 * 60;
const MAX_JSON_BYTES: usize = 128 * 1024;
const SCHEMA_VERSION: u64 = 1;
const MAX_MONITORING_RECORDS: usize = 32;

pub struct RecoveryStore {
    connection: Mutex<Connection>,
}

#[derive(Clone, Copy)]
struct Scope<'a> {
    organization: &'a str,
    account: &'a str,
    installation: &'a str,
}

#[derive(Clone)]
struct Binding {
    host: String,
    task: String,
    run: String,
}

impl RecoveryStore {
    pub fn open(dir: &Path) -> Result<Self> {
        crate::state::private_dir(dir)?;
        let path = dir.join("recovery.sqlite3");
        for candidate in [
            &path,
            &dir.join("recovery.sqlite3-wal"),
            &dir.join("recovery.sqlite3-shm"),
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
        let version: u32 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
        ensure!(version <= 1, "UNSUPPORTED_STATE_VERSION");
        connection.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS recovery_records (
              recovery_id TEXT PRIMARY KEY,
              organization_id TEXT NOT NULL,
              account_subject TEXT NOT NULL,
              installation_id TEXT NOT NULL,
              host_id TEXT NOT NULL,
              host_task_id TEXT NOT NULL,
              run_id TEXT NOT NULL,
              marker TEXT NOT NULL,
              schema_version INTEGER NOT NULL,
              revision INTEGER NOT NULL,
              monitoring_intent TEXT NOT NULL,
              initialization TEXT,
              registration_state TEXT NOT NULL,
              lifecycle TEXT NOT NULL,
              automation_id TEXT,
              evidence_json BLOB,
              observed_at INTEGER,
              last_event_sequence INTEGER,
              pending_request_id TEXT,
              presentation_reference TEXT,
              cleanup_status TEXT,
              diagnostic_reason TEXT,
              current_operation_id TEXT,
              created_at INTEGER NOT NULL,
              updated_at INTEGER NOT NULL,
              expires_at INTEGER,
              UNIQUE(organization_id, account_subject, installation_id, host_id, host_task_id, run_id)
            );
            CREATE INDEX IF NOT EXISTS recovery_scope ON recovery_records(organization_id, account_subject, installation_id, updated_at);
            CREATE INDEX IF NOT EXISTS recovery_expiry ON recovery_records(expires_at);
            CREATE TABLE IF NOT EXISTS recovery_operations (
              operation_id TEXT PRIMARY KEY,
              recovery_id TEXT NOT NULL REFERENCES recovery_records(recovery_id),
              operation_kind TEXT NOT NULL,
              arguments_json BLOB NOT NULL,
              operation_key TEXT NOT NULL,
              status TEXT NOT NULL,
              result_json BLOB,
              created_at INTEGER NOT NULL,
              updated_at INTEGER NOT NULL,
              expires_at INTEGER,
              UNIQUE(recovery_id, operation_key)
            );
            CREATE INDEX IF NOT EXISTS recovery_operation_record ON recovery_operations(recovery_id, created_at);
            CREATE TABLE IF NOT EXISTS recovery_receipts (
              organization_id TEXT NOT NULL,
              account_subject TEXT NOT NULL,
              installation_id TEXT NOT NULL,
              method TEXT NOT NULL,
              idempotency_key TEXT NOT NULL,
              request_digest TEXT NOT NULL,
              result_json BLOB NOT NULL,
              created_at INTEGER NOT NULL,
              expires_at INTEGER NOT NULL,
              PRIMARY KEY(organization_id, account_subject, installation_id, method, idempotency_key)
            );
            PRAGMA user_version = 1;
            ",
        )?;
        for candidate in [
            path,
            dir.join("recovery.sqlite3-wal"),
            dir.join("recovery.sqlite3-shm"),
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

    pub fn dispatch(
        &self,
        org: &str,
        account: &str,
        installation: &str,
        method: &str,
        p: &Value,
    ) -> Result<Value> {
        let scope = Scope {
            organization: org,
            account,
            installation,
        };
        self.sweep(crate::state::now())?;
        match method {
            "recovery.get" => self.get(scope, p),
            "recovery.update" => self.update(scope, p),
            "recovery.operations.begin" => self.operation_begin(scope, p),
            "recovery.operations.settle" => self.operation_settle(scope, p),
            _ => bail!("METHOD_NOT_FOUND"),
        }
    }

    /// Return prior runner-journal observations for one exact run. A record
    /// can say that a host automation was previously verified, but this read
    /// never inspects the host and therefore cannot establish current delivery.
    pub fn monitoring_observation(
        &self,
        org: &str,
        account: &str,
        installation: &str,
        run: &str,
    ) -> Result<Value> {
        Uuid::parse_str(run).map_err(|_| anyhow::anyhow!("INVALID_REQUEST"))?;
        self.sweep(crate::state::now())?;
        let connection = self
            .connection
            .lock()
            .map_err(|_| anyhow::anyhow!("INTERNAL"))?;
        let total: u64 = connection.query_row(
            "SELECT COUNT(*) FROM recovery_records
             WHERE organization_id=?1 AND account_subject=?2
               AND installation_id=?3 AND run_id=?4",
            params![org, account, installation, run],
            |row| row.get(0),
        )?;
        let mut statement = connection.prepare(
            "SELECT monitoring_intent,registration_state,lifecycle,
                    automation_id,evidence_json,observed_at,current_operation_id,
                    updated_at
             FROM recovery_records
             WHERE organization_id=?1 AND account_subject=?2
               AND installation_id=?3 AND run_id=?4
             ORDER BY updated_at DESC, recovery_id DESC LIMIT ?5",
        )?;
        let records = statement
            .query_map(
                params![
                    org,
                    account,
                    installation,
                    run,
                    (MAX_MONITORING_RECORDS + 1) as u64
                ],
                |row| {
                    let monitoring_intent: String = row.get(0)?;
                    let registration_state: String = row.get(1)?;
                    let lifecycle: String = row.get(2)?;
                    let automation_id: Option<String> = row.get(3)?;
                    let evidence: Option<Vec<u8>> = row.get(4)?;
                    let observed_at: Option<u64> = row.get(5)?;
                    let operation_id: Option<String> = row.get(6)?;
                    let updated_at: u64 = row.get(7)?;
                    let evidence_recorded = evidence.is_some() && observed_at.is_some();
                    let previously_verified = registration_state == "registered"
                        && lifecycle == "verified"
                        && automation_id.is_some()
                        && evidence_recorded;
                    Ok(json!({
                        // Recovery records are admitted only for verified host
                        // tasks. Keep the exact host/task binding in the
                        // private journal, but never expose it through run
                        // monitoring output.
                        "binding": {"authority":"verified_host_task", "verified":true},
                        "monitoringIntent": monitoring_intent,
                        "registrationState": registration_state,
                        "recordedLifecycle": lifecycle,
                        "automationIdRecorded": automation_id.is_some(),
                        "hostEvidenceRecorded": evidence_recorded,
                        "previouslyVerified": previously_verified,
                        "operationPending": operation_id.is_some(),
                        "observedAt": observed_at,
                        "updatedAt": updated_at,
                        "freshHostVerificationRequired": true,
                    }))
                },
            )?
            .take(MAX_MONITORING_RECORDS)
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(json!({
            "records": records,
            "recordCount": total,
            "truncated": total > MAX_MONITORING_RECORDS as u64,
            "hostSchedulingGuaranteed": false,
        }))
    }

    fn get(&self, scope: Scope<'_>, p: &Value) -> Result<Value> {
        let binding = binding(p)?;
        let connection = self
            .connection
            .lock()
            .map_err(|_| anyhow::anyhow!("INTERNAL"))?;
        match find(&connection, scope, &binding)? {
            Some(record) => Ok(json!({"found":true,"recovery":record})),
            None => Ok(json!({"found":false,"binding":public_binding(scope, &binding)})),
        }
    }

    fn update(&self, scope: Scope<'_>, p: &Value) -> Result<Value> {
        let binding = binding(p)?;
        let expected = required_u64(p, "expectedRevision")?;
        validate_update(p)?;
        let key = required_uuid(p, "idempotencyKey")?;
        let digest = crate::state::json_digest(p);
        let now = crate::state::now();
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| anyhow::anyhow!("INTERNAL"))?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(result) = receipt(&tx, scope, "recovery.update", key, &digest)? {
            tx.commit()?;
            return Ok(result);
        }
        let result = match find(&tx, scope, &binding)? {
            Some(mut record) => {
                ensure!(
                    record["revision"].as_u64() == Some(expected),
                    "REVISION_CONFLICT"
                );
                ensure!(
                    record["operation"].is_null()
                        || !matches!(record["operation"]["status"].as_str(), Some("in_flight")),
                    "OPERATION_PENDING"
                );
                update_fields(&mut record, p, now)?;
                write_record(&tx, scope, &mut record, now)?;
                json!({"recovery":record})
            }
            None => {
                ensure!(expected == 0, "REVISION_CONFLICT");
                let mut record = new_record(scope, &binding, p, now)?;
                update_fields(&mut record, p, now)?;
                insert_record(&tx, scope, &record)?;
                json!({"recovery":record})
            }
        };
        save_receipt(&tx, scope, "recovery.update", key, &digest, &result, now)?;
        tx.commit()?;
        Ok(result)
    }

    fn operation_begin(&self, scope: Scope<'_>, p: &Value) -> Result<Value> {
        let binding = binding(p)?;
        let expected = required_u64(p, "expectedRevision")?;
        let operation = p["operation"].as_object().context("INVALID_REQUEST")?;
        let kind = operation
            .get("kind")
            .and_then(Value::as_str)
            .filter(|s| ["create", "update", "pause", "remove"].contains(s))
            .context("INVALID_REQUEST")?;
        let arguments = operation
            .get("arguments")
            .filter(|v| v.is_object())
            .context("INVALID_REQUEST")?;
        validate_json(arguments)?;
        let operation_key = required_uuid(&p["operation"], "idempotencyKey")?;
        let key = required_uuid(p, "idempotencyKey")?;
        let digest = crate::state::json_digest(p);
        let now = crate::state::now();
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| anyhow::anyhow!("INTERNAL"))?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(result) = receipt(&tx, scope, "recovery.operations.begin", key, &digest)? {
            tx.commit()?;
            // A receipt proves the local journal entry, not host delivery. A
            // replay may follow a lost response after the host mutation, so it
            // must reconcile the recorded operation instead of invoking it.
            return Ok(reconciliation_required(result));
        }
        let mut record = find(&tx, scope, &binding)?.context("RECOVERY_NOT_FOUND")?;
        ensure!(
            record["revision"].as_u64() == Some(expected),
            "REVISION_CONFLICT"
        );
        if let Some(existing) = record["operation"].as_object() {
            if existing["operationKey"] == operation_key {
                let result = json!({"recovery":record,"operation":existing,"attemptPermitted":false,"reconciliationRequired":true});
                save_receipt(
                    &tx,
                    scope,
                    "recovery.operations.begin",
                    key,
                    &digest,
                    &result,
                    now,
                )?;
                tx.commit()?;
                return Ok(result);
            }
            bail!(if existing["status"] == "ambiguous" {
                "RECOVERY_AMBIGUOUS"
            } else {
                "OPERATION_PENDING"
            });
        }
        if record["monitoringIntent"] == "stopped" {
            ensure!(["pause", "remove"].contains(&kind), "RECOVERY_STOPPED");
        }
        ensure!(
            record["registrationState"] != "ambiguous",
            "RECOVERY_AMBIGUOUS"
        );
        match kind {
            "create" => ensure!(
                record["registrationState"] == "not_attempted",
                "RECOVERY_REGISTRATION_EXISTS"
            ),
            _ => ensure!(
                record["registrationState"] == "registered" && record["automationId"].is_string(),
                "RECOVERY_REGISTRATION_REQUIRED"
            ),
        }
        let operation_id = Uuid::new_v4().to_string();
        tx.execute("INSERT INTO recovery_operations(operation_id,recovery_id,operation_kind,arguments_json,operation_key,status,created_at,updated_at) VALUES (?1,?2,?3,?4,?5,'in_flight',?6,?6)", params![operation_id, record["recoveryId"].as_str(), kind, encode(arguments)?, operation_key, now])?;
        record["revision"] = json!(expected + 1);
        record["registrationState"] = json!("attempt_in_flight");
        record["currentOperationId"] = json!(operation_id);
        record["updatedAt"] = json!(now);
        write_record(&tx, scope, &mut record, now)?;
        let summary = operation_value(&tx, &operation_id)?.context("INTERNAL")?;
        let result = json!({"recovery":record,"operation":summary,"attemptPermitted":true});
        // Store a safe replay projection.  The immediate creator may perform the
        // host mutation once, but a later delivery of this same request cannot.
        let replay = reconciliation_required(result.clone());
        save_receipt(
            &tx,
            scope,
            "recovery.operations.begin",
            key,
            &digest,
            &replay,
            now,
        )?;
        tx.commit()?;
        Ok(result)
    }

    fn operation_settle(&self, scope: Scope<'_>, p: &Value) -> Result<Value> {
        let binding = binding(p)?;
        let expected = required_u64(p, "expectedRevision")?;
        let operation_id = required_uuid(p, "operationId")?;
        let status = required(p, "status")?;
        ensure!(
            ["succeeded", "ambiguous"].contains(&status),
            "INVALID_REQUEST"
        );
        if let Some(evidence) = p.get("hostEvidence") {
            validate_json(evidence)?;
        }
        if let Some(id) = p.get("automationId").and_then(Value::as_str) {
            validate_short(id)?;
        }
        let lifecycle = p
            .get("lifecycle")
            .and_then(Value::as_str)
            .unwrap_or("unchecked");
        ensure!(
            [
                "unchecked",
                "verified",
                "unavailable",
                "ambiguous",
                "paused",
                "removed"
            ]
            .contains(&lifecycle),
            "INVALID_REQUEST"
        );
        let key = required_uuid(p, "idempotencyKey")?;
        let digest = crate::state::json_digest(p);
        let now = crate::state::now();
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| anyhow::anyhow!("INTERNAL"))?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(result) = receipt(&tx, scope, "recovery.operations.settle", key, &digest)? {
            tx.commit()?;
            return Ok(result);
        }
        let mut record = find(&tx, scope, &binding)?.context("RECOVERY_NOT_FOUND")?;
        ensure!(
            record["revision"].as_u64() == Some(expected),
            "REVISION_CONFLICT"
        );
        ensure!(
            record["currentOperationId"] == operation_id,
            "OPERATION_NOT_FOUND"
        );
        let operation = operation_value(&tx, operation_id)?.context("OPERATION_NOT_FOUND")?;
        ensure!(operation["status"] == "in_flight", "OPERATION_NOT_PENDING");
        if status == "succeeded" && operation["kind"] == "create" {
            ensure!(
                p.get("automationId").and_then(Value::as_str).is_some(),
                "AUTOMATION_ID_REQUIRED"
            );
        }
        let result = json!({"status":status,"automationId":p.get("automationId"),"hostEvidence":p.get("hostEvidence"),"lifecycle":lifecycle});
        tx.execute("UPDATE recovery_operations SET status=?1,result_json=?2,updated_at=?3,expires_at=?4 WHERE operation_id=?5", params![status, encode(&result)?, now, now.saturating_add(RETENTION_SECONDS), operation_id])?;
        record["revision"] = json!(expected + 1);
        record["currentOperationId"] = Value::Null;
        record["updatedAt"] = json!(now);
        if status == "ambiguous" {
            record["registrationState"] = json!("ambiguous");
            record["lifecycle"] = json!("ambiguous");
        } else {
            if let Some(id) = p.get("automationId") {
                record["automationId"] = id.clone();
            }
            record["registrationState"] = if operation["kind"] == "remove" {
                json!("removed")
            } else {
                json!("registered")
            };
            record["lifecycle"] = if operation["kind"] == "remove" {
                json!("removed")
            } else {
                json!(lifecycle)
            };
        }
        if let Some(evidence) = p.get("hostEvidence") {
            record["hostEvidence"] = evidence.clone();
            record["observedAt"] = json!(now);
        }
        write_record(&tx, scope, &mut record, now)?;
        let result = json!({"recovery":record,"operation":operation_value(&tx, operation_id)?});
        save_receipt(
            &tx,
            scope,
            "recovery.operations.settle",
            key,
            &digest,
            &result,
            now,
        )?;
        tx.commit()?;
        Ok(result)
    }

    fn sweep(&self, now: u64) -> Result<()> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| anyhow::anyhow!("INTERNAL"))?;
        connection.execute(
            "DELETE FROM recovery_receipts WHERE expires_at < ?1",
            params![now],
        )?;
        // In-flight and ambiguous rows intentionally never expire: expiry must
        // never restore permission to create an automation after a lost reply.
        connection.execute("DELETE FROM recovery_operations WHERE expires_at IS NOT NULL AND expires_at <= ?1 AND status='succeeded'", params![now])?;
        connection.execute("DELETE FROM recovery_records WHERE expires_at IS NOT NULL AND expires_at <= ?1 AND registration_state='removed' AND lifecycle='removed' AND current_operation_id IS NULL AND pending_request_id IS NULL", params![now])?;
        Ok(())
    }
}

fn binding(p: &Value) -> Result<Binding> {
    let b = p.get("binding").unwrap_or(p);
    let host = required(b, "hostId")?.to_owned();
    let task = required(b, "hostTaskId")?.to_owned();
    let run = required_uuid(b, "runId")?.to_owned();
    validate_short(&host)?;
    validate_short(&task)?;
    // UI handoff rows and a workspace are not a host scheduling authority.
    // Recovery can only be journaled under a host identity supplied by the
    // scheduler integration. Rejecting these values here prevents an
    // unavailable task lookup from leaving a durable, misleading record that
    // later looks eligible for automation creation.
    ensure!(
        host != "codex-ui"
            && host != "unverified"
            && task != "unverified"
            && !std::path::Path::new(&task).is_absolute(),
        "VERIFIED_HOST_TASK_REQUIRED"
    );
    Ok(Binding { host, task, run })
}
fn public_binding(scope: Scope<'_>, b: &Binding) -> Value {
    json!({"organizationId":scope.organization,"installationId":scope.installation,"hostId":b.host,"hostTaskId":b.task,"runId":b.run,"marker":format!("loomex-follow-recovery:{}:{}",b.task,b.run)})
}
fn new_record(scope: Scope<'_>, b: &Binding, p: &Value, now: u64) -> Result<Value> {
    let initialization = p
        .get("initialization")
        .and_then(Value::as_str)
        .unwrap_or("run_started");
    validate_short(initialization)?;
    let intent = p
        .get("monitoringIntent")
        .and_then(Value::as_str)
        .unwrap_or("enabled");
    ensure!(["enabled", "stopped"].contains(&intent), "INVALID_REQUEST");
    Ok(
        json!({"recoveryId":Uuid::new_v4().to_string(),"schemaVersion":SCHEMA_VERSION,"revision":0,"binding":public_binding(scope,b),"monitoringIntent":intent,"initialization":initialization,"registrationState":"not_attempted","lifecycle":"unchecked","automationId":Value::Null,"hostEvidence":Value::Null,"observedAt":Value::Null,"lastEventSequence":Value::Null,"pendingRequestId":Value::Null,"presentationReference":Value::Null,"cleanupStatus":Value::Null,"diagnosticReason":Value::Null,"currentOperationId":Value::Null,"operation":Value::Null,"createdAt":now,"updatedAt":now,"expiresAt":Value::Null}),
    )
}
fn validate_update(p: &Value) -> Result<()> {
    for key in [
        "initialization",
        "monitoringIntent",
        "presentationReference",
        "cleanupStatus",
        "diagnosticReason",
    ] {
        if let Some(v) = p.get(key) {
            validate_short(v.as_str().context("INVALID_REQUEST")?)?;
        }
    }
    if let Some(intent) = p.get("monitoringIntent").and_then(Value::as_str) {
        ensure!(["enabled", "stopped"].contains(&intent), "INVALID_REQUEST");
    }
    if let Some(sequence) = p.get("lastEventSequence") {
        ensure!(sequence.as_u64().is_some(), "INVALID_REQUEST");
    }
    if let Some(request) = p.get("pendingRequestId") {
        if !request.is_null() {
            Uuid::parse_str(request.as_str().context("INVALID_REQUEST")?)
                .map_err(|_| anyhow::anyhow!("INVALID_REQUEST"))?;
        }
    }
    Ok(())
}
fn update_fields(record: &mut Value, p: &Value, now: u64) -> Result<()> {
    for (request, field) in [
        ("initialization", "initialization"),
        ("monitoringIntent", "monitoringIntent"),
        ("lastEventSequence", "lastEventSequence"),
        ("pendingRequestId", "pendingRequestId"),
        ("presentationReference", "presentationReference"),
        ("cleanupStatus", "cleanupStatus"),
        ("diagnosticReason", "diagnosticReason"),
    ] {
        if let Some(value) = p.get(request) {
            record[field] = value.clone();
        }
    }
    record["revision"] = json!(record["revision"].as_u64().context("INTERNAL")? + 1);
    record["updatedAt"] = json!(now);
    Ok(())
}
fn insert_record(connection: &Connection, scope: Scope<'_>, record: &Value) -> Result<()> {
    connection.execute("INSERT INTO recovery_records(recovery_id,organization_id,account_subject,installation_id,host_id,host_task_id,run_id,marker,schema_version,revision,monitoring_intent,initialization,registration_state,lifecycle,automation_id,evidence_json,observed_at,last_event_sequence,pending_request_id,presentation_reference,cleanup_status,diagnostic_reason,current_operation_id,created_at,updated_at,expires_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21,?22,?23,?24,?25,?26)", rusqlite::params_from_iter(record_params(scope, record)))?;
    Ok(())
}
fn write_record(
    connection: &Connection,
    scope: Scope<'_>,
    record: &mut Value,
    _now: u64,
) -> Result<()> {
    record["expiresAt"] = recovery_expiry(record)
        .map(Value::from)
        .unwrap_or(Value::Null);
    let changed=connection.execute("UPDATE recovery_records SET revision=?10,monitoring_intent=?11,initialization=?12,registration_state=?13,lifecycle=?14,automation_id=?15,evidence_json=?16,observed_at=?17,last_event_sequence=?18,pending_request_id=?19,presentation_reference=?20,cleanup_status=?21,diagnostic_reason=?22,current_operation_id=?23,updated_at=?25,expires_at=?26 WHERE recovery_id=?1 AND organization_id=?2 AND account_subject=?3 AND installation_id=?4 AND host_id=?5 AND host_task_id=?6 AND run_id=?7 AND marker=?8 AND schema_version=?9", rusqlite::params_from_iter(record_params(scope, record)))?;
    ensure!(changed == 1, "RECOVERY_NOT_FOUND");
    Ok(())
}
fn record_params(scope: Scope<'_>, record: &Value) -> Vec<rusqlite::types::Value> {
    let b = &record["binding"];
    vec![
        record["recoveryId"].as_str().unwrap().to_owned().into(),
        b["organizationId"].as_str().unwrap().to_owned().into(),
        scope.account.to_owned().into(),
        b["installationId"].as_str().unwrap().to_owned().into(),
        b["hostId"].as_str().unwrap().to_owned().into(),
        b["hostTaskId"].as_str().unwrap().to_owned().into(),
        b["runId"].as_str().unwrap().to_owned().into(),
        b["marker"].as_str().unwrap().to_owned().into(),
        (SCHEMA_VERSION as i64).into(),
        (record["revision"].as_u64().unwrap() as i64).into(),
        record["monitoringIntent"]
            .as_str()
            .unwrap()
            .to_owned()
            .into(),
        record["initialization"]
            .as_str()
            .map(|v| v.to_owned().into())
            .unwrap_or(rusqlite::types::Value::Null),
        record["registrationState"]
            .as_str()
            .unwrap()
            .to_owned()
            .into(),
        record["lifecycle"].as_str().unwrap().to_owned().into(),
        record["automationId"]
            .as_str()
            .map(|v| v.to_owned().into())
            .unwrap_or(rusqlite::types::Value::Null),
        if record["hostEvidence"].is_null() {
            rusqlite::types::Value::Null
        } else {
            encode(&record["hostEvidence"]).unwrap().into()
        },
        record["observedAt"]
            .as_u64()
            .map(|n| (n as i64).into())
            .unwrap_or(rusqlite::types::Value::Null),
        record["lastEventSequence"]
            .as_u64()
            .map(|n| (n as i64).into())
            .unwrap_or(rusqlite::types::Value::Null),
        record["pendingRequestId"]
            .as_str()
            .map(|v| v.to_owned().into())
            .unwrap_or(rusqlite::types::Value::Null),
        record["presentationReference"]
            .as_str()
            .map(|v| v.to_owned().into())
            .unwrap_or(rusqlite::types::Value::Null),
        record["cleanupStatus"]
            .as_str()
            .map(|v| v.to_owned().into())
            .unwrap_or(rusqlite::types::Value::Null),
        record["diagnosticReason"]
            .as_str()
            .map(|v| v.to_owned().into())
            .unwrap_or(rusqlite::types::Value::Null),
        record["currentOperationId"]
            .as_str()
            .map(|v| v.to_owned().into())
            .unwrap_or(rusqlite::types::Value::Null),
        (record["createdAt"].as_u64().unwrap() as i64).into(),
        (record["updatedAt"].as_u64().unwrap() as i64).into(),
        recovery_expiry(record)
            .map(|expiry| (expiry as i64).into())
            .unwrap_or(rusqlite::types::Value::Null),
    ]
}

fn recovery_expiry(record: &Value) -> Option<u64> {
    // `removed` is the one terminal local fact: the exact host remove operation
    // settled successfully, no operation is in flight, and no human request is
    // waiting.  A verified registration is still a live recovery schedule and
    // must not age out with its credentials or execution lease.
    (record["registrationState"] == "removed"
        && record["lifecycle"] == "removed"
        && record["currentOperationId"].is_null()
        && record["pendingRequestId"].is_null())
    .then(|| {
        record["updatedAt"]
            .as_u64()
            .unwrap_or(0)
            .saturating_add(RETENTION_SECONDS)
    })
}
fn find(connection: &Connection, scope: Scope<'_>, b: &Binding) -> Result<Option<Value>> {
    let mut record: Option<Value> = connection.query_row("SELECT recovery_id,marker,schema_version,revision,monitoring_intent,initialization,registration_state,lifecycle,automation_id,evidence_json,observed_at,last_event_sequence,pending_request_id,presentation_reference,cleanup_status,diagnostic_reason,current_operation_id,created_at,updated_at,expires_at FROM recovery_records WHERE organization_id=?1 AND account_subject=?2 AND installation_id=?3 AND host_id=?4 AND host_task_id=?5 AND run_id=?6", params![scope.organization,scope.account,scope.installation,b.host,b.task,b.run], |r| { let evidence:Option<Vec<u8>>=r.get(9)?; let operation_id:Option<String>=r.get(16)?; Ok(json!({"recoveryId":r.get::<_,String>(0)?,"schemaVersion":r.get::<_,u64>(2)?,"revision":r.get::<_,u64>(3)?,"binding":json!({"organizationId":scope.organization,"installationId":scope.installation,"hostId":b.host,"hostTaskId":b.task,"runId":b.run,"marker":r.get::<_,String>(1)?}),"monitoringIntent":r.get::<_,String>(4)?,"initialization":r.get::<_,Option<String>>(5)?,"registrationState":r.get::<_,String>(6)?,"lifecycle":r.get::<_,String>(7)?,"automationId":r.get::<_,Option<String>>(8)?,"hostEvidence":evidence.map(|v|decode_sql(&v)).transpose()?,"observedAt":r.get::<_,Option<u64>>(10)?,"lastEventSequence":r.get::<_,Option<u64>>(11)?,"pendingRequestId":r.get::<_,Option<String>>(12)?,"presentationReference":r.get::<_,Option<String>>(13)?,"cleanupStatus":r.get::<_,Option<String>>(14)?,"diagnosticReason":r.get::<_,Option<String>>(15)?,"currentOperationId":operation_id,"operation":Value::Null,"createdAt":r.get::<_,u64>(17)?,"updatedAt":r.get::<_,u64>(18)?,"expiresAt":r.get::<_,Option<u64>>(19)?})) }).optional()?;
    if let Some(value) = record.as_mut() {
        if let Some(operation_id) = value["currentOperationId"].as_str() {
            value["operation"] = operation_value(connection, operation_id)?.unwrap_or(Value::Null);
        }
    }
    Ok(record)
}
fn operation_value(connection: &Connection, id: &str) -> Result<Option<Value>> {
    connection.query_row("SELECT operation_kind,arguments_json,operation_key,status,result_json,created_at,updated_at FROM recovery_operations WHERE operation_id=?1",params![id],|r| { let args:Vec<u8>=r.get(1)?; let result:Option<Vec<u8>>=r.get(4)?; Ok(json!({"operationId":id,"kind":r.get::<_,String>(0)?,"arguments":decode_sql(&args)?,"operationKey":r.get::<_,String>(2)?,"status":r.get::<_,String>(3)?,"result":result.map(|v|decode_sql(&v)).transpose()?,"createdAt":r.get::<_,u64>(5)?,"updatedAt":r.get::<_,u64>(6)?})) }).optional().map_err(Into::into)
}
fn reconciliation_required(mut result: Value) -> Value {
    if let Some(object) = result.as_object_mut() {
        object.insert("attemptPermitted".into(), Value::Bool(false));
        object.insert("reconciliationRequired".into(), Value::Bool(true));
    }
    result
}
fn receipt(
    connection: &Connection,
    scope: Scope<'_>,
    method: &str,
    key: &str,
    digest: &str,
) -> Result<Option<Value>> {
    let row:Option<(String,Vec<u8>)>=connection.query_row("SELECT request_digest,result_json FROM recovery_receipts WHERE organization_id=?1 AND account_subject=?2 AND installation_id=?3 AND method=?4 AND idempotency_key=?5",params![scope.organization,scope.account,scope.installation,method,key],|r|Ok((r.get(0)?,r.get(1)?))).optional()?;
    match row {
        None => Ok(None),
        Some((stored, result)) => {
            ensure!(stored == digest, "IDEMPOTENCY_CONFLICT");
            Ok(Some(decode_sql(&result)?))
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
        "INSERT INTO recovery_receipts VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",
        params![
            scope.organization,
            scope.account,
            scope.installation,
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
fn required<'a>(p: &'a Value, key: &str) -> Result<&'a str> {
    p[key]
        .as_str()
        .filter(|v| !v.is_empty())
        .context("INVALID_REQUEST")
}
fn required_uuid<'a>(p: &'a Value, key: &str) -> Result<&'a str> {
    let value = required(p, key)?;
    Uuid::parse_str(value).map_err(|_| anyhow::anyhow!("INVALID_REQUEST"))?;
    Ok(value)
}
fn required_u64(p: &Value, key: &str) -> Result<u64> {
    p[key].as_u64().context("INVALID_REQUEST")
}
fn validate_short(value: &str) -> Result<()> {
    ensure!(value.len() <= 512 && !value.is_empty(), "INVALID_REQUEST");
    Ok(())
}
fn validate_json(value: &Value) -> Result<()> {
    ensure!(
        serde_json::to_vec(value)?.len() <= MAX_JSON_BYTES,
        "INVALID_REQUEST"
    );
    Ok(())
}
fn encode(value: &Value) -> Result<Vec<u8>> {
    Ok(serde_json::to_vec(value)?)
}
fn decode_sql(bytes: &[u8]) -> rusqlite::Result<Value> {
    serde_json::from_slice(bytes).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(
            bytes.len(),
            rusqlite::types::Type::Blob,
            Box::new(e),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn scope<'a>() -> Scope<'a> {
        Scope {
            organization: "org",
            account: "owner",
            installation: "install",
        }
    }
    fn binding() -> Value {
        json!({"binding":{"hostId":"local","hostTaskId":"task-1","runId":Uuid::new_v4()}})
    }
    fn update(store: &RecoveryStore, b: &Value, revision: u64) -> Value {
        let mut p = b.clone();
        p["expectedRevision"] = json!(revision);
        p["initialization"] = json!("run_started");
        p["idempotencyKey"] = json!(Uuid::new_v4());
        store.update(scope(), &p).unwrap()
    }
    fn settle_create(store: &RecoveryStore, b: &Value, host_evidence: Option<Value>) {
        update(store, b, 0);
        let mut begin = b.clone();
        begin["expectedRevision"] = json!(1);
        begin["operation"] =
            json!({"kind":"create","arguments":{},"idempotencyKey":Uuid::new_v4()});
        begin["idempotencyKey"] = json!(Uuid::new_v4());
        let started = store.operation_begin(scope(), &begin).unwrap();
        let mut settled = b.clone();
        settled["expectedRevision"] = json!(2);
        settled["operationId"] = started["operation"]["operationId"].clone();
        settled["status"] = json!("succeeded");
        settled["automationId"] = json!(format!(
            "automation-{}",
            b["binding"]["hostTaskId"].as_str().unwrap()
        ));
        settled["lifecycle"] = json!("verified");
        if let Some(evidence) = host_evidence {
            settled["hostEvidence"] = evidence;
        }
        settled["idempotencyKey"] = json!(Uuid::new_v4());
        store.operation_settle(scope(), &settled).unwrap();
    }
    #[test]
    fn initial_then_first_registration_and_restart_are_durable() {
        let d = tempfile::tempdir().unwrap();
        let b = binding();
        let first = RecoveryStore::open(d.path()).unwrap();
        let r = update(&first, &b, 0)["recovery"].clone();
        assert_eq!(r["registrationState"], "not_attempted");
        let mut begin = b.clone();
        begin["expectedRevision"] = json!(1);
        begin["operation"] = json!({"kind":"create","arguments":{"marker":r["binding"]["marker"]},"idempotencyKey":Uuid::new_v4()});
        begin["idempotencyKey"] = json!(Uuid::new_v4());
        let started = first.operation_begin(scope(), &begin).unwrap();
        assert!(started["attemptPermitted"].as_bool().unwrap());
        drop(first);
        let reopened = RecoveryStore::open(d.path()).unwrap();
        let read = reopened.get(scope(), &b).unwrap();
        assert_eq!(read["recovery"]["registrationState"], "attempt_in_flight");
        assert_eq!(read["recovery"]["operation"]["status"], "in_flight");
    }
    #[test]
    fn monitoring_reports_prior_verification_without_exposing_task_bindings() {
        let d = tempfile::tempdir().unwrap();
        let store = RecoveryStore::open(d.path()).unwrap();
        let run = Uuid::new_v4();
        let without_evidence =
            json!({"binding":{"hostId":"local","hostTaskId":"task-without-evidence","runId":run}});
        let with_evidence =
            json!({"binding":{"hostId":"local","hostTaskId":"task-with-evidence","runId":run}});
        settle_create(&store, &without_evidence, None);
        settle_create(
            &store,
            &with_evidence,
            Some(json!({"automationId":"observed-on-host"})),
        );

        let observation = store
            .monitoring_observation("org", "owner", "install", &run.to_string())
            .unwrap();
        assert_eq!(observation["recordCount"], 2);
        assert_eq!(observation["hostSchedulingGuaranteed"], false);
        let records = observation["records"].as_array().unwrap();
        let serialized = observation.to_string();
        assert!(!serialized.contains("task-without-evidence"));
        assert!(!serialized.contains("task-with-evidence"));
        assert!(!serialized.contains("\"hostId\""));
        assert!(!serialized.contains("\"hostTaskId\""));
        assert!(records.iter().all(|record| {
            record["binding"] == json!({"authority":"verified_host_task", "verified":true})
        }));
        let recorded_only = records
            .iter()
            .find(|record| record["previouslyVerified"] == false)
            .unwrap();
        assert_eq!(recorded_only["registrationState"], "registered");
        assert_eq!(recorded_only["recordedLifecycle"], "verified");
        assert_eq!(recorded_only["previouslyVerified"], false);
        let prior_evidence = records
            .iter()
            .find(|record| record["previouslyVerified"] == true)
            .unwrap();
        assert_eq!(prior_evidence["previouslyVerified"], true);
        assert_eq!(prior_evidence["freshHostVerificationRequired"], true);
    }
    #[test]
    fn begin_replay_requires_reconciliation_and_cannot_duplicate_host_create() {
        let d = tempfile::tempdir().unwrap();
        let s = RecoveryStore::open(d.path()).unwrap();
        let b = binding();
        update(&s, &b, 0);
        let mut p = b.clone();
        p["expectedRevision"] = json!(1);
        p["operation"] = json!({"kind":"create","arguments":{},"idempotencyKey":Uuid::new_v4()});
        p["idempotencyKey"] = json!(Uuid::new_v4());
        let first = s.operation_begin(scope(), &p).unwrap();
        assert!(first["attemptPermitted"].as_bool().unwrap());
        let same_request = s.operation_begin(scope(), &p).unwrap();
        assert!(!same_request["attemptPermitted"].as_bool().unwrap());
        assert!(same_request["reconciliationRequired"].as_bool().unwrap());
        // A lost response can be retried with a distinct outer idempotency key.
        // It must see the prior in-flight creation and reconcile it, never call
        // the non-idempotent host automation create a second time.
        p["expectedRevision"] = json!(2);
        p["idempotencyKey"] = json!(Uuid::new_v4());
        let retry = s.operation_begin(scope(), &p).unwrap();
        assert!(!retry["attemptPermitted"].as_bool().unwrap());
        assert!(retry["reconciliationRequired"].as_bool().unwrap());
        assert_eq!(
            retry["operation"]["operationId"],
            first["operation"]["operationId"]
        );
    }
    #[test]
    fn settle_ambiguity_prevents_replay_and_owner_or_binding_substitution() {
        let d = tempfile::tempdir().unwrap();
        let s = RecoveryStore::open(d.path()).unwrap();
        let b = binding();
        update(&s, &b, 0);
        let mut begin = b.clone();
        begin["expectedRevision"] = json!(1);
        begin["operation"] =
            json!({"kind":"create","arguments":{},"idempotencyKey":Uuid::new_v4()});
        begin["idempotencyKey"] = json!(Uuid::new_v4());
        let start = s.operation_begin(scope(), &begin).unwrap();
        let mut settle = b.clone();
        settle["expectedRevision"] = json!(2);
        settle["operationId"] = start["operation"]["operationId"].clone();
        settle["status"] = json!("ambiguous");
        settle["idempotencyKey"] = json!(Uuid::new_v4());
        s.operation_settle(scope(), &settle).unwrap();
        let mut retry = begin.clone();
        retry["expectedRevision"] = json!(3);
        retry["idempotencyKey"] = json!(Uuid::new_v4());
        assert_eq!(
            s.operation_begin(scope(), &retry).unwrap_err().to_string(),
            "RECOVERY_AMBIGUOUS"
        );
        assert_eq!(
            s.get(
                Scope {
                    organization: "org",
                    account: "other",
                    installation: "install"
                },
                &b
            )
            .unwrap()["found"],
            false
        );
        let mut swapped = b.clone();
        swapped["binding"]["runId"] = json!(Uuid::new_v4());
        assert_eq!(s.get(scope(), &swapped).unwrap()["found"], false);
    }
    #[test]
    fn explicit_stop_allows_a_cleanup_pause_but_not_new_registration() {
        let d = tempfile::tempdir().unwrap();
        let s = RecoveryStore::open(d.path()).unwrap();
        let b = binding();
        update(&s, &b, 0);
        let mut create = b.clone();
        create["expectedRevision"] = json!(1);
        create["operation"] =
            json!({"kind":"create","arguments":{},"idempotencyKey":Uuid::new_v4()});
        create["idempotencyKey"] = json!(Uuid::new_v4());
        let started = s.operation_begin(scope(), &create).unwrap();
        let mut settled = b.clone();
        settled["expectedRevision"] = json!(2);
        settled["operationId"] = started["operation"]["operationId"].clone();
        settled["status"] = json!("succeeded");
        settled["automationId"] = json!("automation-1");
        settled["lifecycle"] = json!("verified");
        settled["idempotencyKey"] = json!(Uuid::new_v4());
        s.operation_settle(scope(), &settled).unwrap();
        let mut stop = b.clone();
        stop["expectedRevision"] = json!(3);
        stop["monitoringIntent"] = json!("stopped");
        stop["idempotencyKey"] = json!(Uuid::new_v4());
        let stopped = s.update(scope(), &stop).unwrap();
        let mut create_again = b.clone();
        create_again["expectedRevision"] = stopped["recovery"]["revision"].clone();
        create_again["operation"] =
            json!({"kind":"create","arguments":{},"idempotencyKey":Uuid::new_v4()});
        create_again["idempotencyKey"] = json!(Uuid::new_v4());
        assert_eq!(
            s.operation_begin(scope(), &create_again)
                .unwrap_err()
                .to_string(),
            "RECOVERY_STOPPED"
        );
        let mut pause = create_again;
        pause["operation"] = json!({"kind":"pause","arguments":{},"idempotencyKey":Uuid::new_v4()});
        pause["idempotencyKey"] = json!(Uuid::new_v4());
        assert!(
            s.operation_begin(scope(), &pause).unwrap()["attemptPermitted"]
                .as_bool()
                .unwrap()
        );
    }
    #[test]
    fn stale_update_is_rejected() {
        let d = tempfile::tempdir().unwrap();
        let s = RecoveryStore::open(d.path()).unwrap();
        let b = binding();
        update(&s, &b, 0);
        let mut p = b.clone();
        p["expectedRevision"] = json!(0);
        p["idempotencyKey"] = json!(Uuid::new_v4());
        assert_eq!(
            s.update(scope(), &p).unwrap_err().to_string(),
            "REVISION_CONFLICT"
        );
    }

    #[test]
    fn live_unverified_task_cannot_create_recovery_record() {
        let d = tempfile::tempdir().unwrap();
        let s = RecoveryStore::open(d.path()).unwrap();
        let mut b = binding();
        b["binding"]["hostTaskId"] = json!("unverified");
        let mut p = b;
        p["expectedRevision"] = json!(0);
        p["idempotencyKey"] = json!(Uuid::new_v4());
        assert_eq!(
            s.update(scope(), &p).unwrap_err().to_string(),
            "VERIFIED_HOST_TASK_REQUIRED"
        );
    }

    #[test]
    fn ui_workspace_handoff_cannot_create_a_recovery_record() {
        let d = tempfile::tempdir().unwrap();
        let s = RecoveryStore::open(d.path()).unwrap();
        let mut p = binding();
        p["binding"]["hostId"] = json!("codex-ui");
        p["binding"]["hostTaskId"] = json!("/Users/example/workspace");
        p["expectedRevision"] = json!(0);
        p["idempotencyKey"] = json!(Uuid::new_v4());
        assert_eq!(
            s.update(scope(), &p).unwrap_err().to_string(),
            "VERIFIED_HOST_TASK_REQUIRED"
        );
    }

    #[test]
    fn only_clean_removed_recovery_records_expire_after_thirty_days() {
        let d = tempfile::tempdir().unwrap();
        let s = RecoveryStore::open(d.path()).unwrap();
        let b = binding();
        update(&s, &b, 0);

        let mut create = b.clone();
        create["expectedRevision"] = json!(1);
        create["operation"] =
            json!({"kind":"create","arguments":{},"idempotencyKey":Uuid::new_v4()});
        create["idempotencyKey"] = json!(Uuid::new_v4());
        let started = s.operation_begin(scope(), &create).unwrap();
        let mut created = b.clone();
        created["expectedRevision"] = json!(2);
        created["operationId"] = started["operation"]["operationId"].clone();
        created["status"] = json!("succeeded");
        created["automationId"] = json!("automation-1");
        created["lifecycle"] = json!("verified");
        created["idempotencyKey"] = json!(Uuid::new_v4());
        s.operation_settle(scope(), &created).unwrap();

        let mut stopped = b.clone();
        stopped["expectedRevision"] = json!(3);
        stopped["monitoringIntent"] = json!("stopped");
        stopped["idempotencyKey"] = json!(Uuid::new_v4());
        let stopped = s.update(scope(), &stopped).unwrap();
        let mut remove = b.clone();
        remove["expectedRevision"] = stopped["recovery"]["revision"].clone();
        remove["operation"] =
            json!({"kind":"remove","arguments":{},"idempotencyKey":Uuid::new_v4()});
        remove["idempotencyKey"] = json!(Uuid::new_v4());
        let remove_started = s.operation_begin(scope(), &remove).unwrap();
        let mut removed = b.clone();
        removed["expectedRevision"] = remove_started["recovery"]["revision"].clone();
        removed["operationId"] = remove_started["operation"]["operationId"].clone();
        removed["status"] = json!("succeeded");
        removed["lifecycle"] = json!("verified");
        removed["idempotencyKey"] = json!(Uuid::new_v4());
        let removed = s.operation_settle(scope(), &removed).unwrap();
        let expiry = removed["recovery"]["expiresAt"].as_u64().unwrap();
        s.sweep(expiry - 1).unwrap();
        assert!(s.get(scope(), &b).unwrap()["found"].as_bool().unwrap());
        s.sweep(expiry).unwrap();
        assert!(!s.get(scope(), &b).unwrap()["found"].as_bool().unwrap());

        let unresolved = binding();
        update(&s, &unresolved, 0);
        let unresolved_run = unresolved["binding"]["runId"].as_str().unwrap();
        {
            let connection = s.connection.lock().unwrap();
            connection
                .execute(
                    "UPDATE recovery_records SET expires_at=?1 WHERE run_id=?2",
                    params![1_u64, unresolved_run],
                )
                .unwrap();
        }
        s.sweep(2).unwrap();
        assert!(
            s.get(scope(), &unresolved).unwrap()["found"]
                .as_bool()
                .unwrap()
        );
    }
}
