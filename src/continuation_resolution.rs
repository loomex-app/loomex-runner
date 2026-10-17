//! Immutable local continuation closure. It never asserts backend terminality or host delivery.
use anyhow::{Context, Result, ensure};
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::{Value, json};
use uuid::Uuid;

pub(crate) fn initialize(c: &Connection) -> Result<()> {
    c.execute_batch("CREATE TABLE IF NOT EXISTS continuation_resolutions (
      kind TEXT NOT NULL, organization_id TEXT NOT NULL, account_subject TEXT NOT NULL,
      installation_id TEXT NOT NULL, record_id TEXT NOT NULL, request_digest TEXT NOT NULL,
      receipt_json BLOB NOT NULL,
      PRIMARY KEY(kind,organization_id,account_subject,installation_id,record_id));
      CREATE TABLE IF NOT EXISTS continuation_observations(kind TEXT NOT NULL,organization_id TEXT NOT NULL,account_subject TEXT NOT NULL,installation_id TEXT NOT NULL,record_id TEXT NOT NULL,observation_json BLOB NOT NULL,PRIMARY KEY(kind,organization_id,account_subject,installation_id,record_id));")?;
    Ok(())
}

pub(crate) fn projection(
    c: &Connection,
    kind: &str,
    org: &str,
    account: &str,
    install: &str,
    id: &str,
) -> Result<Value> {
    let exists:bool=c.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='continuation_resolutions')",[],|r|r.get(0))?;
    if !exists {
        return Ok(json!({"state":"unresolved"}));
    }
    let bytes: Option<Vec<u8>> = c.query_row("SELECT receipt_json FROM continuation_resolutions WHERE kind=?1 AND organization_id=?2 AND account_subject=?3 AND installation_id=?4 AND record_id=?5",params![kind,org,account,install,id],|r|r.get(0)).optional()?;
    bytes
        .map(|v| serde_json::from_slice(&v).map_err(Into::into))
        .unwrap_or_else(|| Ok(json!({"state":"unresolved"})))
}

pub(crate) fn eligible(
    c: &Connection,
    kind: &str,
    org: &str,
    account: &str,
    install: &str,
    id: &str,
) -> Result<()> {
    ensure!(
        projection(c, kind, org, account, install, id)?["state"] == "unresolved",
        "CONTINUATION_RESOLVED"
    );
    Ok(())
}

pub(crate) fn replay(c: &Connection, candidate: &Value, request: &Value) -> Result<Option<Value>> {
    let prior:Option<(String,Vec<u8>)>=c.query_row("SELECT request_digest,receipt_json FROM continuation_resolutions WHERE kind=?1 AND organization_id=?2 AND account_subject=?3 AND installation_id=?4 AND record_id=?5",params![candidate["kind"].as_str(),candidate["organizationId"].as_str(),candidate["accountSubject"].as_str(),candidate["installationId"].as_str().unwrap_or(""),candidate["recordId"].as_str()],|r|Ok((r.get(0)?,r.get(1)?))).optional()?;
    if let Some((digest, bytes)) = prior {
        ensure!(
            digest == crate::state::json_digest(request),
            "CONTINUATION_RESOLVED"
        );
        return Ok(Some(serde_json::from_slice(&bytes)?));
    }
    Ok(None)
}

/// Caller holds its store's immediate transaction and has matched all original row fences.
pub(crate) fn close(
    c: &Connection,
    candidate: &Value,
    request: &Value,
    state: &str,
    evidence: Value,
) -> Result<Value> {
    let kind = candidate["kind"].as_str().context("INVALID_REQUEST")?;
    let org = candidate["organizationId"]
        .as_str()
        .context("INVALID_REQUEST")?;
    let account = candidate["accountSubject"]
        .as_str()
        .context("INVALID_REQUEST")?;
    let install = candidate["installationId"].as_str().unwrap_or("");
    let id = candidate["recordId"].as_str().context("INVALID_REQUEST")?;
    let key = request["idempotencyKey"]
        .as_str()
        .context("INVALID_REQUEST")?;
    Uuid::parse_str(key).map_err(|_| anyhow::anyhow!("INVALID_REQUEST"))?;
    let digest = crate::state::json_digest(request);
    let prior: Option<(String,Vec<u8>)> = c.query_row("SELECT request_digest,receipt_json FROM continuation_resolutions WHERE kind=?1 AND organization_id=?2 AND account_subject=?3 AND installation_id=?4 AND record_id=?5",params![kind,org,account,install,id],|r|Ok((r.get(0)?,r.get(1)?))).optional()?;
    if let Some((old, bytes)) = prior {
        ensure!(old == digest, "CONTINUATION_RESOLVED");
        return Ok(serde_json::from_slice(&bytes)?);
    }
    let receipt = json!({"schemaVersion":"loomex.continuation-resolution/v1","state":state,"receiptId":Uuid::new_v4(),"idempotencyKey":key,"candidate":candidate,"evidence":evidence,"resolvedAt":crate::state::now()});
    c.execute(
        "INSERT INTO continuation_resolutions VALUES(?1,?2,?3,?4,?5,?6,?7)",
        params![
            kind,
            org,
            account,
            install,
            id,
            digest,
            serde_json::to_vec(&receipt)?
        ],
    )?;
    Ok(receipt)
}

pub(crate) fn matches(candidate: &Value, request: &Value) -> Result<()> {
    for key in [
        "kind",
        "organizationId",
        "accountSubject",
        "installationId",
        "recordId",
        "runId",
        "revision",
        "generation",
        "attemptId",
        "recordDigest",
    ] {
        ensure!(
            candidate.get(key) == request.get(key),
            "MANAGED_WORK_CHANGED"
        );
    }
    Ok(())
}

pub(crate) fn terminal_evidence(candidate: &Value, observation: &Value) -> Result<()> {
    let snapshot = &observation["snapshot"];
    let result = &observation["terminalResult"];
    let run = candidate["runId"].as_str().context("INVALID_REQUEST")?;
    ensure!(
        snapshot.pointer("/execution/id").and_then(Value::as_str) == Some(run)
            && result.pointer("/execution/id").and_then(Value::as_str) == Some(run)
            && crate::follow::FollowStore::terminal_snapshot(snapshot)
            && result.get("hasMoreEvents").and_then(Value::as_bool) != Some(true)
            && result.get("hasMore").and_then(Value::as_bool) != Some(true)
            && result.get("responseRef").is_none()
            && result.get("nextOffset").is_none_or(Value::is_null),
        "MANAGED_WORK_OBSERVATION_INCOMPLETE"
    );
    ensure!(
        result.pointer("/execution/status") == snapshot.pointer("/execution/status"),
        "MANAGED_WORK_OBSERVATION_INCOMPLETE"
    );
    Ok(())
}

/// Validate a persisted closure against the exact unchanged canonical candidate.
/// Missing legacy proof is unresolved, never an inferred successful delivery.
pub(crate) fn resolved(c: &Connection, candidate: &Value) -> Result<bool> {
    let kind = candidate["kind"].as_str().context("INVALID_REQUEST")?;
    let org = candidate["organizationId"]
        .as_str()
        .context("INVALID_REQUEST")?;
    let account = candidate["accountSubject"]
        .as_str()
        .context("INVALID_REQUEST")?;
    let install = candidate["installationId"].as_str().unwrap_or("");
    let id = candidate["recordId"].as_str().context("INVALID_REQUEST")?;
    let exists: bool=c.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='continuation_resolutions')",[],|r|r.get(0))?;
    if !exists {
        return Ok(false);
    }
    let receipt = projection(c, kind, org, account, install, id)?;
    if !matches!(
        receipt["state"].as_str(),
        Some("retired_by_owner" | "verified_terminal" | "superseded_by_verified_successor")
    ) {
        return Ok(false);
    }
    if receipt["schemaVersion"] != "loomex.continuation-resolution/v1"
        || receipt["receiptId"]
            .as_str()
            .and_then(|s| Uuid::parse_str(s).ok())
            .is_none()
    {
        return Ok(false);
    }
    if receipt["idempotencyKey"]
        .as_str()
        .and_then(|s| Uuid::parse_str(s).ok())
        .is_none()
        || receipt["resolvedAt"].as_u64().is_none()
    {
        return Ok(false);
    }
    let digest = |v: &Value| {
        v.as_str()
            .is_some_and(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()))
    };
    let evidence_ok = match receipt["state"].as_str() {
        Some("retired_by_owner") => {
            let fact = observation(c, candidate)?;
            receipt["evidence"]["reasonCode"] == "OWNER_RETIRED_LOCAL_CONTINUATION"
                && !fact.is_null()
        }
        Some("verified_terminal") => {
            let fact = observation(c, candidate)?;
            kind == "follow_session"
                && fact["terminal"] == true
                && receipt["evidence"]["runId"] == candidate["runId"]
                && digest(&receipt["evidence"]["observationDigest"])
                && receipt["evidence"]["observationDigest"] == fact["observationDigest"]
        }
        Some("superseded_by_verified_successor") => {
            let evidence = &receipt["evidence"];
            if evidence["successorId"]
                .as_str()
                .and_then(|s| Uuid::parse_str(s).ok())
                .is_none()
                || evidence["successorGeneration"].as_u64().is_none()
            {
                false
            } else {
                let lineage_generation = evidence["lineageSuccessorGeneration"]
                    .as_u64()
                    .or_else(|| evidence["successorGeneration"].as_u64())
                    .context("MANAGED_WORK_CHANGED")?;
                let exact:Option<(Vec<u8>,String)>=c.query_row("SELECT s.terminal_receipt_json,s.run_id FROM follow_lineage l JOIN follow_sessions s ON s.follow_session_id=l.successor_id AND s.organization_id=l.organization_id AND s.account_subject=l.account_subject AND s.installation_id=l.installation_id WHERE l.organization_id=?1 AND l.account_subject=?2 AND l.installation_id=?3 AND l.predecessor_id=?4 AND l.predecessor_generation=?5 AND l.successor_id=?6 AND l.successor_generation=?7 AND s.generation=?8 AND s.lifecycle='terminal' AND s.required_action='none' AND s.pending_handoff_json IS NULL",params![org,account,install,id,candidate["generation"].as_u64(),evidence["successorId"].as_str(),lineage_generation,evidence["successorGeneration"].as_u64()],|r|Ok((r.get(0)?,r.get(1)?))).optional()?;
                if let Some((bytes, run)) = exact {
                    let successor = json!({"organizationId":org,"accountSubject":account,"installationId":install,"followSessionId":evidence["successorId"],"runId":run});
                    crate::follow::maintenance_generation_path(
                        c,
                        &successor,
                        lineage_generation,
                        evidence["successorGeneration"].as_u64().unwrap(),
                    )? && serde_json::from_slice::<Value>(&bytes)
                        .ok()
                        .is_some_and(|v| {
                            v == evidence["terminalReceipt"]
                                && v["generation"] == evidence["successorGeneration"]
                                && !v["receiptId"].is_null()
                        })
                } else {
                    false
                }
            }
        }
        _ => false,
    };
    Ok(evidence_ok && matches(&receipt["candidate"], candidate).is_ok())
}

pub(crate) fn observe(c: &Connection, candidate: &Value, observation: &Value) -> Result<Value> {
    let snapshot = observation.get("snapshot").unwrap_or(observation);
    ensure!(
        snapshot.pointer("/execution/id") == Some(&candidate["runId"])
            && snapshot["hasMoreEvents"] == false,
        "MANAGED_WORK_OBSERVATION_INCOMPLETE"
    );
    let status = snapshot
        .pointer("/execution/status")
        .and_then(Value::as_str)
        .context("MANAGED_WORK_OBSERVATION_INCOMPLETE")?;
    ensure!(
        [
            "queued",
            "running",
            "waiting_for_human",
            "waiting",
            "pending",
            "active",
            "paused",
            "completed",
            "failed",
            "cancelled",
            "canceled",
            "deleted",
            "succeeded",
            "error"
        ]
        .contains(&status),
        "MANAGED_WORK_OBSERVATION_INCOMPLETE"
    );
    let terminal = crate::follow::FollowStore::terminal_snapshot(snapshot);
    if terminal {
        terminal_evidence(candidate, observation)?;
    }
    let fact = json!({"schemaVersion":"loomex.continuation-observation/v1","runId":candidate["runId"],"recordDigest":candidate["recordDigest"],"status":status,"terminal":terminal,"observationDigest":crate::state::json_digest(observation),"observedAt":crate::state::now()});
    c.execute("INSERT INTO continuation_observations VALUES(?1,?2,?3,?4,?5,?6) ON CONFLICT(kind,organization_id,account_subject,installation_id,record_id) DO UPDATE SET observation_json=excluded.observation_json",params![candidate["kind"].as_str(),candidate["organizationId"].as_str(),candidate["accountSubject"].as_str(),candidate["installationId"].as_str().unwrap_or(""),candidate["recordId"].as_str(),serde_json::to_vec(&fact)?])?;
    Ok(fact)
}

pub(crate) fn observation(c: &Connection, candidate: &Value) -> Result<Value> {
    let exists:bool=c.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='continuation_observations')",[],|r|r.get(0))?;
    if !exists {
        return Ok(Value::Null);
    }
    let bytes:Option<Vec<u8>>=c.query_row("SELECT observation_json FROM continuation_observations WHERE kind=?1 AND organization_id=?2 AND account_subject=?3 AND installation_id=?4 AND record_id=?5",params![candidate["kind"].as_str(),candidate["organizationId"].as_str(),candidate["accountSubject"].as_str(),candidate["installationId"].as_str().unwrap_or(""),candidate["recordId"].as_str()],|r|r.get(0)).optional()?;
    let fact: Value = bytes
        .map(|v| serde_json::from_slice(&v).map_err(anyhow::Error::from))
        .unwrap_or(Ok(Value::Null))?;
    if fact.is_null() {
        return Ok(fact);
    }
    if fact["recordDigest"] != candidate["recordDigest"] {
        return Ok(Value::Null);
    }
    let valid = fact["schemaVersion"] == "loomex.continuation-observation/v1"
        && fact["runId"] == candidate["runId"]
        && fact["recordDigest"] == candidate["recordDigest"]
        && fact["terminal"].is_boolean()
        && fact["observedAt"].as_u64().is_some()
        && fact["observationDigest"]
            .as_str()
            .is_some_and(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()));
    let terminal_status = fact["status"].as_str().is_some_and(|s| {
        [
            "completed",
            "failed",
            "cancelled",
            "canceled",
            "deleted",
            "succeeded",
            "error",
        ]
        .contains(&s)
    });
    ensure!(
        valid && fact["terminal"].as_bool() == Some(terminal_status),
        "MANAGED_WORK_CHANGED"
    );
    Ok(fact)
}
