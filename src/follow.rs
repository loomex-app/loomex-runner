//! Durable, scoped lifecycle-follow state for host stop hooks.
//!
//! The hook supplies only a compact structured signal.  This store does not
//! start a workflow, read a transcript, or create host scheduling.  Generations
//! fence callbacks from an earlier host session or continuation anchor.

use anyhow::{Context, Result, bail, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::Path,
    sync::Mutex,
};
use uuid::Uuid;

/// Follow state is execution evidence.  An active, blocked, suspended, or
/// handoff-pending session never expires automatically; only a terminal
/// session with its required result receipt gets the 30-day retirement window.
const RETENTION_SECONDS: u64 = 30 * 24 * 60 * 60;
const SCHEMA_VERSION: u64 = 1;
const MAX_JSON_BYTES: usize = 128 * 1024;
const MAX_MONITORING_RECORDS: usize = 32;
const MAX_HOOK_DIAGNOSTICS: usize = 8;

pub struct FollowStore {
    connection: Mutex<Connection>,
}

#[derive(Debug)]
pub struct FollowTarget {
    pub run_id: String,
    pub event_cursor: Option<u64>,
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
    host_session: String,
    task: String,
    run: String,
}

struct Continuation {
    run: String,
    receipt: String,
}

struct ToolProgress {
    kind: String,
    receipt: String,
    association_request_id: Option<String>,
    request_request_id: Option<String>,
    response_request_id: Option<String>,
}

struct ToolReceipt<'a> {
    kind: &'a str,
    receipt: &'a str,
    association_request_id: Option<&'a str>,
    request_request_id: Option<&'a str>,
    response_request_id: Option<&'a str>,
}

impl FollowStore {
    pub fn open(dir: &Path) -> Result<Self> {
        crate::state::private_dir(dir)?;
        let path = dir.join("follow.sqlite3");
        for candidate in [
            &path,
            &dir.join("follow.sqlite3-wal"),
            &dir.join("follow.sqlite3-shm"),
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
        ensure!(
            version <= SCHEMA_VERSION as u32,
            "UNSUPPORTED_STATE_VERSION"
        );
        connection.execute_batch("\
          CREATE TABLE IF NOT EXISTS follow_sessions (
            follow_session_id TEXT PRIMARY KEY,
            organization_id TEXT NOT NULL,
            account_subject TEXT NOT NULL,
            installation_id TEXT NOT NULL,
            host_id TEXT NOT NULL,
            host_session_id TEXT NOT NULL,
            host_task_id TEXT NOT NULL,
            run_id TEXT NOT NULL,
            anchor_digest TEXT NOT NULL,
            schema_version INTEGER NOT NULL,
            generation INTEGER NOT NULL,
            revision INTEGER NOT NULL,
            mode TEXT NOT NULL,
            lifecycle TEXT NOT NULL,
            event_cursor INTEGER,
            pending_handoff_json BLOB,
            terminal_receipt_json BLOB,
            recovery_json BLOB,
            cleanup_json BLOB,
            action_progress_json BLOB NOT NULL,
            required_action TEXT NOT NULL,
            missed_action_count INTEGER NOT NULL,
            hook_count INTEGER NOT NULL,
            last_error TEXT,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL,
            expires_at INTEGER,
            UNIQUE(organization_id, account_subject, installation_id, host_id, host_session_id, host_task_id, run_id)
          );
          CREATE INDEX IF NOT EXISTS follow_scope ON follow_sessions(organization_id, account_subject, installation_id, updated_at);
          CREATE TABLE IF NOT EXISTS follow_receipts (
            organization_id TEXT NOT NULL, account_subject TEXT NOT NULL, installation_id TEXT NOT NULL,
            method TEXT NOT NULL, idempotency_key TEXT NOT NULL, request_digest TEXT NOT NULL,
            result_json BLOB NOT NULL, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
            PRIMARY KEY(organization_id, account_subject, installation_id, method, idempotency_key)
          );
          CREATE TABLE IF NOT EXISTS follow_continuations (
            receipt TEXT PRIMARY KEY,
            organization_id TEXT NOT NULL, account_subject TEXT NOT NULL, installation_id TEXT NOT NULL,
            run_id TEXT NOT NULL, trigger TEXT NOT NULL, request_id TEXT,
            created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL
          );
          CREATE INDEX IF NOT EXISTS follow_continuation_scope ON follow_continuations(organization_id, account_subject, installation_id, run_id);
          -- Lifecycle diagnostics are intentionally identity-minimal. They
          -- establish whether the installed host reached this runner without
          -- retaining prompts, paths, tool bodies, or session identifiers.
          CREATE TABLE IF NOT EXISTS follow_hook_diagnostics (
            diagnostic_id INTEGER PRIMARY KEY AUTOINCREMENT,
            organization_id TEXT NOT NULL,
            account_subject TEXT NOT NULL,
            installation_id TEXT NOT NULL,
            run_id TEXT,
            event_id_digest TEXT NOT NULL,
            event TEXT NOT NULL,
            outcome TEXT NOT NULL,
            code TEXT NOT NULL,
            observed_at INTEGER NOT NULL
          );
          CREATE INDEX IF NOT EXISTS follow_hook_diagnostics_run
            ON follow_hook_diagnostics(organization_id, account_subject, installation_id, run_id, observed_at DESC);
          PRAGMA user_version = 1;")?;
        // Older releases represented an app-originated handoff as `active`.
        // Those records lack a native host-session identity and must not retain
        // workspace-derived Stop authority after this semantic change. Keep the
        // receipt for exact wait-based promotion, but make every such record
        // explicitly pending on startup.
        connection.execute(
            "UPDATE follow_sessions SET lifecycle='handoff_pending', required_action='none', updated_at=?1, expires_at=NULL
             WHERE host_id='codex-ui' AND host_session_id='unbound' AND lifecycle='active'",
            params![crate::state::now()],
        )?;
        for candidate in [
            path,
            dir.join("follow.sqlite3-wal"),
            dir.join("follow.sqlite3-shm"),
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
        self.dispatch_observed(org, account, installation, method, p, None)
    }

    /// Minted only from a runner-authoritative commit or accepted interaction
    /// response. The UI can format it, but cannot make a generated marker
    /// follow a run it has not received from this runner.
    pub fn issue_continuation(
        &self,
        org: &str,
        account: &str,
        installation: &str,
        run: &str,
        trigger: &str,
        request_id: Option<&str>,
    ) -> Result<String> {
        Uuid::parse_str(run).map_err(|_| anyhow::anyhow!("INVALID_REQUEST"))?;
        ensure!(
            ["run_commit", "accepted_interaction"].contains(&trigger),
            "INVALID_REQUEST"
        );
        if let Some(request_id) = request_id {
            Uuid::parse_str(request_id).map_err(|_| anyhow::anyhow!("INVALID_REQUEST"))?;
        }
        let receipt = URL_SAFE_NO_PAD.encode(Uuid::new_v4().as_bytes());
        let now = crate::state::now();
        let connection = self
            .connection
            .lock()
            .map_err(|_| anyhow::anyhow!("INTERNAL"))?;
        connection.execute(
            "INSERT INTO follow_continuations VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",
            params![
                receipt,
                org,
                account,
                installation,
                run,
                trigger,
                request_id,
                now,
                now.saturating_add(RETENTION_SECONDS)
            ],
        )?;
        Ok(receipt)
    }

    /// Return an already-issued continuation only within the exact runner
    /// identity that created it. This is recovery for a lost local response,
    /// never a way to mint a new capability from a read or a UI action.
    pub fn issued_continuation(
        &self,
        org: &str,
        account: &str,
        installation: &str,
        run: &str,
        trigger: &str,
        request_id: Option<&str>,
    ) -> Result<Option<String>> {
        Uuid::parse_str(run).map_err(|_| anyhow::anyhow!("INVALID_REQUEST"))?;
        let now = crate::state::now();
        let connection = self
            .connection
            .lock()
            .map_err(|_| anyhow::anyhow!("INTERNAL"))?;
        connection
            .query_row(
                "SELECT receipt FROM follow_continuations
                 WHERE organization_id = ?1 AND account_subject = ?2
                   AND installation_id = ?3 AND run_id = ?4 AND trigger = ?5
                   AND request_id IS ?6 AND expires_at > ?7
                 ORDER BY created_at DESC LIMIT 1",
                params![org, account, installation, run, trigger, request_id, now],
                |row| row.get(0),
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn dispatch_observed(
        &self,
        org: &str,
        account: &str,
        installation: &str,
        method: &str,
        p: &Value,
        observation: Option<&Value>,
    ) -> Result<Value> {
        let scope = Scope {
            organization: org,
            account,
            installation,
        };
        self.sweep(crate::state::now())?;
        match method {
            "follow.session.lifecycle" => {
                let result = self.lifecycle(scope, p, observation);
                let (outcome, code) = match &result {
                    Ok(_) => ("accepted", lifecycle_diagnostic_code(p)),
                    Err(_) => ("rejected", "LIFECYCLE_REJECTED"),
                };
                // Diagnostics must never change lifecycle behavior. A full or
                // unavailable local diagnostic store therefore cannot turn a
                // valid host hook into an allow-to-stop decision.
                let _ = self.record_lifecycle_diagnostic(scope, p, outcome, code);
                result
            }
            _ => bail!("METHOD_NOT_FOUND"),
        }
    }

    pub fn lifecycle_target(
        &self,
        org: &str,
        account: &str,
        installation: &str,
        p: &Value,
    ) -> Result<Option<FollowTarget>> {
        validate_lifecycle(p)?;
        if !matches!(required(p, "event")?, "PostToolUse" | "Stop") {
            return Ok(None);
        }
        let scope = Scope {
            organization: org,
            account,
            installation,
        };
        let Some(binding) = self.binding_for_event(scope, &p["session"], p)? else {
            return Ok(None);
        };
        let record = self.get(scope, &json!({"binding":public_binding(&binding)}))?;
        Ok(Some(FollowTarget {
            run_id: binding.run,
            event_cursor: record["session"]["eventCursor"].as_u64(),
        }))
    }

    /// Record a pending, runner-issued UI handoff. MCP Apps can ask the host
    /// to create a chat message, but the bridge does not expose a verified
    /// host-session identity. This record is therefore evidence that the
    /// runner issued a continuation, not authority for an unrelated hook in
    /// the same workspace to follow the run.
    ///
    /// A later exact `loomex_run_wait` tool association can atomically consume
    /// this pending handoff and bind it to the host session that actually began
    /// following the run. Until then it is deliberately not lifecycle-hook
    /// eligible.
    pub fn activate_ui_handoff(
        &self,
        org: &str,
        account: &str,
        installation: &str,
        run: &str,
        receipt: &str,
        request_id: Option<&str>,
    ) -> Result<()> {
        Uuid::parse_str(run).map_err(|_| anyhow::anyhow!("INVALID_REQUEST"))?;
        ensure!(
            !receipt.is_empty()
                && receipt.len() <= 2048
                && receipt
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'),
            "INVALID_REQUEST"
        );
        if let Some(request_id) = request_id {
            Uuid::parse_str(request_id).map_err(|_| anyhow::anyhow!("INVALID_REQUEST"))?;
        }
        // The opaque receipt is runner-issued. Its deterministic UUID makes a
        // duplicate mutation delivery replay the original activation instead
        // of resetting the generation and losing an in-flight wait.
        let mut bytes: [u8; 16] = Sha256::digest(receipt.as_bytes())[..16]
            .try_into()
            .expect("SHA-256 prefix has sixteen bytes");
        // Version 8 marks this application-defined deterministic UUID.
        bytes[6] = (bytes[6] & 0x0f) | 0x80;
        bytes[8] = (bytes[8] & 0x3f) | 0x80;
        let key = Uuid::from_bytes(bytes).to_string();
        let scope = Scope {
            organization: org,
            account,
            installation,
        };
        let binding = Binding {
            host: "codex-ui".into(),
            host_session: "unbound".into(),
            // An MCP App bridge has no verified Codex task identity. A
            // receipt-scoped placeholder keeps independently issued handoffs
            // distinguishable without ever mistaking a workspace path for a
            // host task identity.
            task: format!("ui-handoff:{key}"),
            run: run.into(),
        };
        let anchor = if let Some(request_id) = request_id {
            json!({"kind":"accepted_interaction","receiptId":key,"requestId":request_id})
        } else {
            json!({"kind":"explicit_follow","receiptId":key})
        };
        let existing = self.get(scope, &json!({"binding":public_binding(&binding)}))?;
        if existing["found"] == true
            && existing["session"]["anchor"]["receiptId"] == key
            && existing["session"]["anchor"]["requestId"]
                == request_id.map(Value::from).unwrap_or(Value::Null)
            && matches!(
                existing["session"]["lifecycle"].as_str(),
                Some("handoff_pending") | Some("active")
            )
        {
            return Ok(());
        }
        let generation = existing["session"]["generation"].as_u64().unwrap_or(0);
        self.activate(
            scope,
            &json!({
                "binding":public_binding(&binding),
                "anchor":anchor,
                "expectedGeneration":generation,
                "idempotencyKey":key,
            }),
        )?;
        // `activate` is shared with native host bindings and initializes an
        // active record. A UI bridge has no host-session authority, so retain
        // the durable receipt while making the record non-enforceable.
        let connection = self
            .connection
            .lock()
            .map_err(|_| anyhow::anyhow!("INTERNAL"))?;
        connection.execute(
            "UPDATE follow_sessions SET lifecycle='handoff_pending', required_action='none', updated_at=?1, expires_at=NULL
             WHERE organization_id=?2 AND account_subject=?3 AND installation_id=?4
               AND host_id='codex-ui' AND host_session_id='unbound' AND host_task_id=?5 AND run_id=?6",
            params![crate::state::now(), org, account, installation, binding.task, run],
        )?;
        Ok(())
    }

    pub fn terminal_snapshot(snapshot: &Value) -> bool {
        snapshot.get("hasMoreEvents") == Some(&Value::Bool(false))
            && snapshot
                .get("execution")
                .and_then(|value| value.get("status"))
                .and_then(Value::as_str)
                .is_some_and(|status| {
                    [
                        "completed",
                        "failed",
                        "cancelled",
                        "canceled",
                        "deleted",
                        "succeeded",
                        "error",
                    ]
                    .contains(&status.to_ascii_lowercase().as_str())
                })
    }

    /// Return compact, owner-scoped evidence for one run without implying
    /// that the host will deliver another lifecycle hook. Multiple bindings
    /// remain separate because a UI workspace handoff, an unverified host
    /// session, and a verified host task are different authorities.
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
            "SELECT COUNT(*) FROM follow_sessions
             WHERE organization_id=?1 AND account_subject=?2
               AND installation_id=?3 AND run_id=?4",
            params![org, account, installation, run],
            |row| row.get(0),
        )?;
        let mut statement = connection.prepare(
            "SELECT host_id,host_session_id,host_task_id,lifecycle,hook_count,
                    required_action,last_error,updated_at
             FROM follow_sessions
             WHERE organization_id=?1 AND account_subject=?2
               AND installation_id=?3 AND run_id=?4
             ORDER BY updated_at DESC, follow_session_id DESC LIMIT ?5",
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
                    let host: String = row.get(0)?;
                    let session: String = row.get(1)?;
                    let task: String = row.get(2)?;
                    let lifecycle: String = row.get(3)?;
                    let hook_count: u64 = row.get(4)?;
                    let required_action: String = row.get(5)?;
                    let diagnostic_code: Option<String> = row.get(6)?;
                    let updated_at: u64 = row.get(7)?;
                    let ui_handoff = host == "codex-ui" && session == "unbound";
                    let verified_task = task != "unverified" && !ui_handoff;
                    let binding_kind = if ui_handoff {
                        "ui_workspace_handoff"
                    } else if verified_task {
                        "verified_host_task"
                    } else {
                        "host_session_unverified_task"
                    };
                    // A row created at handoff time is not hook-delivery
                    // evidence. Count only a processed hook on an actual Codex
                    // host-session binding.
                    let hook_observed = host == "codex" && session != "unbound" && hook_count > 0;
                    Ok(json!({
                        "binding": {
                            // Monitoring output is an operational summary, not
                            // a host-identity export. The stored binding stays
                            // exact for lifecycle ownership, while callers see
                            // only its authority category and verification.
                            "state": binding_kind,
                            "verified": verified_task,
                        },
                        "lifecycle": lifecycle,
                        "hookCount": hook_count,
                        "hostHookObserved": hook_observed,
                        "uiHandoffRecorded": ui_handoff,
                        "activationState": if ui_handoff {
                            "handoff_pending"
                        } else if hook_observed {
                            "hook_observed"
                        } else {
                            "hook_not_observed"
                        },
                        "requiredAction": required_action,
                        "diagnosticCode": diagnostic_code,
                        "updatedAt": updated_at,
                    }))
                },
            )?
            .take(MAX_MONITORING_RECORDS)
            .collect::<rusqlite::Result<Vec<_>>>()?;
        drop(statement);
        let diagnostic_total: u64 = connection.query_row(
            "SELECT COUNT(*) FROM follow_hook_diagnostics
             WHERE organization_id=?1 AND account_subject=?2
               AND installation_id=?3 AND run_id=?4",
            params![org, account, installation, run],
            |row| row.get(0),
        )?;
        let mut diagnostics_statement = connection.prepare(
            "SELECT event,outcome,code,observed_at FROM follow_hook_diagnostics
             WHERE organization_id=?1 AND account_subject=?2
               AND installation_id=?3 AND run_id=?4
             ORDER BY diagnostic_id DESC LIMIT ?5",
        )?;
        let diagnostics = diagnostics_statement
            .query_map(
                params![org, account, installation, run, MAX_HOOK_DIAGNOSTICS as u64],
                |row| {
                    Ok(json!({
                        "event": row.get::<_, String>(0)?,
                        "outcome": row.get::<_, String>(1)?,
                        "code": row.get::<_, String>(2)?,
                        "observedAt": row.get::<_, u64>(3)?,
                    }))
                },
            )?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(json!({
            "records": records,
            "recordCount": total,
            "truncated": total > MAX_MONITORING_RECORDS as u64,
            "hostHookDeliveryGuaranteed": false,
            "hookDiagnostics": {
                "records": diagnostics,
                "recordCount": diagnostic_total,
                "truncated": diagnostic_total > MAX_HOOK_DIAGNOSTICS as u64,
            },
        }))
    }

    /// The only hook-facing entrypoint. The adapter supplies a compact
    /// continuation record and a normalized, identity-only projection of a
    /// documented tool request/response. It never sends a transcript, raw tool
    /// payload, or an adapter-authored digest.
    fn lifecycle(&self, scope: Scope<'_>, p: &Value, observation: Option<&Value>) -> Result<Value> {
        validate_lifecycle(p)?;
        let event = required(p, "event")?;
        let session = &p["session"];
        let result = match event {
            "SessionStart" | "UserPromptSubmit" => {
                let Some(continuation) = continuation(p)? else {
                    // A restart only restores an already active exact session;
                    // it cannot invent a run from prompt text or task metadata.
                    if event == "SessionStart"
                        && self
                            .binding_for_unique_active_host(scope, session)?
                            .is_some()
                    {
                        return Ok(
                            json!({"schemaVersion":"loomex.follow-session.decision/v1","decision":"continue"}),
                        );
                    }
                    return Ok(
                        json!({"schemaVersion":"loomex.follow-session.decision/v1","decision":"allow"}),
                    );
                };
                // A lifecycle hook may activate a new follow only from the
                // capability issued with an authoritative runner result.
                // Prompt text and legacy command-shaped records cannot name a
                // run into an active session.
                self.verify_continuation(scope, &continuation)?;
                let run = continuation.run;
                let binding = lifecycle_binding(session, &run)?;
                let existing = self.get(scope, &json!({"binding":public_binding(&binding)}))?;
                let idempotency_key = lifecycle_key(p, "activate")?;
                if existing["session"]["anchor"]["receiptId"] == idempotency_key {
                    return Ok(
                        json!({"schemaVersion":"loomex.follow-session.decision/v1","decision":"continue"}),
                    );
                }
                let generation = existing["session"]["generation"].as_u64().unwrap_or(0);
                self.activate(
                    scope,
                    &json!({
                        "binding":public_binding(&binding),
                        "anchor":{"kind":"explicit_follow","receiptId":idempotency_key},
                        "expectedGeneration":generation,"idempotencyKey":idempotency_key
                    }),
                )?;
                json!({"schemaVersion":"loomex.follow-session.decision/v1","decision":"continue"})
            }
            "PostToolUse" => {
                let Some(binding) = self.binding_for_event(scope, session, p)? else {
                    return Ok(
                        json!({"schemaVersion":"loomex.follow-session.decision/v1","decision":"allow"}),
                    );
                };
                let Some(mut current) = self
                    .get(scope, &json!({"binding":public_binding(&binding)}))?["session"]
                    .as_object()
                    .cloned()
                else {
                    return Ok(
                        json!({"schemaVersion":"loomex.follow-session.decision/v1","decision":"allow"}),
                    );
                };
                let Some(progress) = tool_progress(&p["tool"], &binding) else {
                    // A successful unrelated tool is never follow progress.
                    return Ok(
                        json!({"schemaVersion":"loomex.follow-session.decision/v1","decision":"allow"}),
                    );
                };
                let Some(signal) = observation.and_then(|value| {
                    signal_from_observation(
                        value,
                        &binding,
                        Some(ToolReceipt {
                            kind: &progress.kind,
                            receipt: &progress.receipt,
                            association_request_id: progress.association_request_id.as_deref(),
                            request_request_id: progress.request_request_id.as_deref(),
                            response_request_id: progress.response_request_id.as_deref(),
                        }),
                    )
                }) else {
                    return Ok(
                        json!({"schemaVersion":"loomex.follow-session.decision/v1","decision":"allow"}),
                    );
                };
                // Delivery transitions require this exact normalized tool
                // response, rather than a snapshot that merely contains the
                // same pending interaction or terminal state.
                let action_kind = if matches!(progress.kind.as_str(), "handoff" | "result_read")
                    && signal.get("receiptId").and_then(Value::as_str)
                        != Some(progress.receipt.as_str())
                {
                    "none"
                } else {
                    progress.kind.as_str()
                };
                let decision = self.decide(scope, &json!({"binding":public_binding(&binding),"generation":current.remove("generation").unwrap(),"expectedRevision":current.remove("revision").unwrap(),"signal":signal,"actionProgress":{"kind":action_kind,"attempted":true},"idempotencyKey":lifecycle_key(p, "tool")?}))?;
                public_hook_decision(&decision)?
            }
            "Stop" => self.lifecycle_stop(scope, session, p, observation, false)?,
            "Interrupt" => self.lifecycle_stop(scope, session, p, None, true)?,
            _ => bail!("INVALID_REQUEST"),
        };
        Ok(result)
    }

    fn lifecycle_stop(
        &self,
        scope: Scope<'_>,
        session: &Value,
        p: &Value,
        observation: Option<&Value>,
        interrupted: bool,
    ) -> Result<Value> {
        let Some(binding) = self.binding_for_event(scope, session, p)? else {
            return Ok(
                json!({"schemaVersion":"loomex.follow-session.decision/v1","decision":"allow"}),
            );
        };
        let found = self.get(scope, &json!({"binding":public_binding(&binding)}))?;
        let Some(current) = found.get("session") else {
            return Ok(
                json!({"schemaVersion":"loomex.follow-session.decision/v1","decision":"allow"}),
            );
        };
        let signal = if interrupted {
            json!({"kind":"interrupted","code":"HOST_INTERRUPT"})
        } else {
            match observation.and_then(|value| signal_from_observation(value, &binding, None)) {
                Some(signal) => signal,
                None => {
                    // This is an already-authorized, active native follow. A
                    // missing or malformed observation cannot establish that
                    // the run is terminal, so it must not let the host end
                    // the chat turn. The next bounded wait reconciles the
                    // authoritative execution state. This remains scoped to
                    // the exact active binding; unrelated sessions still
                    // receive `allow` above.
                    json!({"kind":"active","code":"OBSERVATION_UNAVAILABLE"})
                }
            }
        };
        let decision = self.decide(scope, &json!({"binding":public_binding(&binding),"generation":current["generation"],"expectedRevision":current["revision"],"signal":signal,"actionProgress":{"kind":"none","attempted":false},"idempotencyKey":lifecycle_key(p, "stop")?}))?;
        public_hook_decision(&decision)
    }

    fn binding_for_event(
        &self,
        scope: Scope<'_>,
        session: &Value,
        p: &Value,
    ) -> Result<Option<Binding>> {
        if let Some(run) = p.pointer("/tool/association/runId").and_then(Value::as_str) {
            let binding = lifecycle_binding(session, run)?;
            let found = self.get(scope, &json!({"binding":public_binding(&binding)}))?;
            if found["found"] == true && found["session"]["lifecycle"] == "active" {
                return Ok(Some(binding));
            }
            // A status/detail read can carry a valid run association, but it
            // must never turn a UI card into a live chat follow. Only the
            // bounded wait tool proves that this host session has started the
            // explicit monitoring protocol for this exact run.
            if p["event"] == "PostToolUse"
                && p.pointer("/tool/name").and_then(Value::as_str)
                    == Some("mcp__loomex__loomex_run_wait")
                && tool_progress(&p["tool"], &binding).is_some()
            {
                return self.promote_pending_ui_handoff(scope, &binding);
            }
            return Ok(None);
        }
        self.binding_for_unique_active_host(scope, session)
    }

    /// Promote exactly one runner-issued UI handoff only after the native
    /// session has made an associated run-wait call. The transaction consumes
    /// the UI record, so another host session cannot later claim the same
    /// handoff. The native task remains `unverified`: this is sufficient for
    /// hook scoping, never for durable recovery scheduling.
    fn promote_pending_ui_handoff(
        &self,
        scope: Scope<'_>,
        native: &Binding,
    ) -> Result<Option<Binding>> {
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| anyhow::anyhow!("INTERNAL"))?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing_native = find(&tx, scope, native)?;
        let mut statement = tx.prepare(
            "SELECT host_task_id FROM follow_sessions
             WHERE organization_id=?1 AND account_subject=?2 AND installation_id=?3
               AND host_id='codex-ui' AND host_session_id='unbound' AND run_id=?4
               AND lifecycle='handoff_pending'",
        )?;
        let tasks = statement
            .query_map(
                params![
                    scope.organization,
                    scope.account,
                    scope.installation,
                    native.run
                ],
                |row| row.get::<_, String>(0),
            )?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        drop(statement);
        // More than one record means the runner cannot prove which handoff
        // this session received. Keep every record pending for explicit
        // continuation instead of guessing from a workspace path.
        if tasks.len() != 1 {
            tx.commit()?;
            return Ok(None);
        }
        let pending = Binding {
            host: "codex-ui".into(),
            host_session: "unbound".into(),
            task: tasks[0].clone(),
            run: native.run.clone(),
        };
        let pending_session = find(&tx, scope, &pending)?.context("FOLLOW_SESSION_NOT_FOUND")?;
        ensure!(
            matches!(
                pending_session["anchor"]["kind"].as_str(),
                Some("explicit_follow") | Some("accepted_interaction")
            ),
            "FOLLOW_SESSION_NOT_FOUND"
        );
        let now = crate::state::now();
        if let Some(mut existing) = existing_native {
            if existing["lifecycle"] == "active" {
                tx.commit()?;
                return Ok(Some(native.clone()));
            }
            // An interaction request deliberately pauses the native follow. Its
            // accepted response can resume only when this newly issued UI
            // receipt names the exact request that put the native session into
            // input_pending. This avoids letting an older or unrelated card
            // reactivate a stopped follow.
            ensure!(
                existing["lifecycle"] == "input_pending"
                    && existing["pendingHandoffReceipt"]["requestId"]
                        == pending_session["anchor"]["requestId"],
                "FOLLOW_HANDOFF_MISMATCH"
            );
            let generation = existing["generation"]
                .as_u64()
                .context("FOLLOW_SESSION_NOT_FOUND")?
                .checked_add(1)
                .context("INVALID_REQUEST")?;
            reset_generation(&mut existing, generation, &pending_session["anchor"], now);
            existing["lifecycle"] = json!("active");
            existing["pendingHandoffReceipt"] = Value::Null;
            existing["requiredAction"] = json!("none");
            existing["updatedAt"] = json!(now);
            existing["expiresAt"] = Value::Null;
            write(&tx, scope, &existing)?;
        } else {
            // An accepted response never creates a new native follow. It may
            // only resume the exact input_pending session that displayed the
            // request; otherwise an old or detached UI card could turn a
            // response into unsolicited monitoring work.
            ensure!(
                pending_session["anchor"]["kind"] != "accepted_interaction",
                "FOLLOW_HANDOFF_MISMATCH"
            );
            let promoted = new_session(scope, native, &pending_session["anchor"], now);
            insert(&tx, scope, &promoted)?;
        }
        let changed = tx.execute(
            "UPDATE follow_sessions SET lifecycle='superseded', required_action='none', updated_at=?1, expires_at=NULL
             WHERE organization_id=?2 AND account_subject=?3 AND installation_id=?4
               AND host_id='codex-ui' AND host_session_id='unbound' AND host_task_id=?5 AND run_id=?6
               AND lifecycle='handoff_pending'",
            params![
                now, scope.organization, scope.account, scope.installation,
                pending.task, pending.run,
            ],
        )?;
        ensure!(changed == 1, "FOLLOW_SESSION_NOT_FOUND");
        tx.commit()?;
        Ok(Some(native.clone()))
    }

    fn binding_for_unique_active_host(
        &self,
        scope: Scope<'_>,
        session: &Value,
    ) -> Result<Option<Binding>> {
        let id = short(session, "id")?;
        let task = "unverified";
        let connection = self
            .connection
            .lock()
            .map_err(|_| anyhow::anyhow!("INTERNAL"))?;
        let rows = connection.prepare(
            "SELECT run_id,lifecycle FROM follow_sessions WHERE organization_id=?1 AND account_subject=?2 AND installation_id=?3 AND host_id='codex' AND host_session_id=?4 AND host_task_id=?5",
        )?.query_map(
            params![scope.organization, scope.account, scope.installation, id, task],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )?.collect::<rusqlite::Result<Vec<_>>>()?;
        if rows.len() == 1 && rows[0].1 == "active" {
            return Ok(Some(Binding {
                host: "codex".into(),
                host_session: id,
                task: task.into(),
                run: rows[0].0.clone(),
            }));
        }

        // `ui/message` has no documented host-session identity. Never use a
        // workspace or cwd as a substitute: a list-only turn in the same
        // project must not inherit a prior UI handoff. Pending UI handoffs are
        // promoted only by `binding_for_event` after an exact run-wait call.
        Ok(None)
    }

    fn get(&self, scope: Scope<'_>, p: &Value) -> Result<Value> {
        let binding = binding(p)?;
        let connection = self
            .connection
            .lock()
            .map_err(|_| anyhow::anyhow!("INTERNAL"))?;
        match find(&connection, scope, &binding)? {
            Some(session) => Ok(json!({"found": true, "session": session})),
            None => Ok(json!({"found": false, "binding": public_binding(&binding)})),
        }
    }

    fn activate(&self, scope: Scope<'_>, p: &Value) -> Result<Value> {
        let binding = binding(p)?;
        let anchor = anchor(&p["anchor"])?;
        let expected_generation = required_u64(p, "expectedGeneration")?;
        let key = required_uuid(p, "idempotencyKey")?;
        let digest = crate::state::json_digest(p);
        let now = crate::state::now();
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| anyhow::anyhow!("INTERNAL"))?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(result) = receipt(&tx, scope, "follow.session.activate", key, &digest)? {
            tx.commit()?;
            return Ok(result);
        }
        let session = match find(&tx, scope, &binding)? {
            Some(mut old) => {
                ensure!(
                    old["generation"].as_u64() == Some(expected_generation),
                    "STALE_FOLLOW_GENERATION"
                );
                let generation = expected_generation
                    .checked_add(1)
                    .context("INVALID_REQUEST")?;
                reset_generation(&mut old, generation, &anchor, now);
                write(&tx, scope, &old)?;
                old
            }
            None => {
                ensure!(expected_generation == 0, "STALE_FOLLOW_GENERATION");
                let session = new_session(scope, &binding, &anchor, now);
                // A later explicit anchor in the same host session replaces
                // prior active follows. Late callbacks can only resolve their
                // exact result digest and therefore cannot mutate this record.
                tx.execute(
                    "UPDATE follow_sessions SET lifecycle='superseded', required_action='none', updated_at=?1, expires_at=NULL WHERE organization_id=?2 AND account_subject=?3 AND installation_id=?4 AND host_id=?5 AND host_session_id=?6 AND host_task_id=?7 AND run_id<>?8 AND lifecycle='active' AND required_action='none'",
                    params![now, scope.organization, scope.account, scope.installation, binding.host, binding.host_session, binding.task, binding.run],
                )?;
                insert(&tx, scope, &session)?;
                session
            }
        };
        let result = json!({"session": session});
        save_receipt(
            &tx,
            scope,
            "follow.session.activate",
            key,
            &digest,
            &result,
            now,
        )?;
        tx.commit()?;
        Ok(result)
    }

    fn decide(&self, scope: Scope<'_>, p: &Value) -> Result<Value> {
        let binding = binding(p)?;
        let generation = required_u64(p, "generation")?;
        let expected_revision = required_u64(p, "expectedRevision")?;
        let signal = signal(&p["signal"])?;
        let action = action(&p["actionProgress"])?;
        let key = required_uuid(p, "idempotencyKey")?;
        let digest = crate::state::json_digest(p);
        let now = crate::state::now();
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| anyhow::anyhow!("INTERNAL"))?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(result) = receipt(&tx, scope, "follow.session.decide", key, &digest)? {
            tx.commit()?;
            return Ok(result);
        }
        let mut session = find(&tx, scope, &binding)?.context("FOLLOW_SESSION_NOT_FOUND")?;
        ensure!(
            session["generation"].as_u64() == Some(generation),
            "STALE_FOLLOW_GENERATION"
        );
        ensure!(
            session["revision"].as_u64() == Some(expected_revision),
            "REVISION_CONFLICT"
        );
        let prior_required = session["requiredAction"].as_str().unwrap_or("none");
        let attempted = action["attempted"].as_bool().unwrap_or(false);
        if attempted && prior_required != "none" {
            ensure!(action["kind"] == prior_required, "INVALID_ACTION_PROGRESS");
        }
        // A healthy follow has no global continuation cap. A Stop repeats the
        // exact required action until its response is attested, rather than
        // turning an active run into an allow-to-stop after arbitrary hooks.
        let missed = if prior_required != "none" && !attempted {
            session["missedActionCount"].as_u64().unwrap_or(0) + 1
        } else {
            0
        };
        let hook_count = session["hookCount"].as_u64().unwrap_or(0) + 1;
        let mut decision = decision_for(&signal, action["kind"].as_str().unwrap_or("none"));
        let lifecycle = match decision["decision"].as_str() {
            Some("allow") => "terminal",
            Some("needs-handoff") => "input_pending",
            Some("suspend") => "suspended",
            _ => "active",
        };
        session["revision"] = json!(expected_revision + 1);
        session["lifecycle"] = json!(lifecycle);
        session["requiredAction"] = decision["requiredAction"].clone();
        session["missedActionCount"] = json!(missed);
        session["hookCount"] = json!(hook_count);
        session["actionProgress"] = action;
        session["updatedAt"] = json!(now);
        if let Some(cursor) = signal.get("eventSequence").and_then(Value::as_u64) {
            session["eventCursor"] = json!(cursor);
        }
        if signal["kind"] == "input" {
            session["pendingHandoffReceipt"] = json!({"requestId":signal["requestId"],"receiptId":signal["receiptId"],"generation":generation});
        }
        if signal["kind"] == "terminal" {
            session["terminalReceipt"] =
                json!({"receiptId":signal["receiptId"],"generation":generation});
        }
        if decision["decision"] == "suspend" {
            session["lastError"] = decision["error"].clone();
        }
        session["expiresAt"] = follow_expiry(&session)
            .map(Value::from)
            .unwrap_or(Value::Null);
        // The wire decision is deliberately compact; the durable session holds
        // all context needed to diagnose or resume it.
        decision["generation"] = json!(generation);
        decision["revision"] = session["revision"].clone();
        write(&tx, scope, &session)?;
        let result = json!({"decision": decision, "session": session});
        save_receipt(
            &tx,
            scope,
            "follow.session.decide",
            key,
            &digest,
            &result,
            now,
        )?;
        tx.commit()?;
        Ok(result)
    }

    fn sweep(&self, at: u64) -> Result<()> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| anyhow::anyhow!("INTERNAL"))?;
        connection.execute(
            "DELETE FROM follow_sessions WHERE expires_at IS NOT NULL AND expires_at <= ?1 AND lifecycle='terminal' AND required_action='none' AND terminal_receipt_json IS NOT NULL",
            params![at],
        )?;
        connection.execute(
            "DELETE FROM follow_receipts WHERE expires_at <= ?1",
            params![at],
        )?;
        connection.execute(
            "DELETE FROM follow_continuations WHERE expires_at <= ?1",
            params![at],
        )?;
        connection.execute(
            "DELETE FROM follow_hook_diagnostics WHERE observed_at <= ?1",
            params![at.saturating_sub(RETENTION_SECONDS)],
        )?;
        Ok(())
    }

    fn record_lifecycle_diagnostic(
        &self,
        scope: Scope<'_>,
        p: &Value,
        outcome: &str,
        code: &str,
    ) -> Result<()> {
        let event = p.get("event").and_then(Value::as_str).unwrap_or("unknown");
        let event_id = p.get("eventId").and_then(Value::as_str).unwrap_or("");
        let event_id_digest = hex::encode(Sha256::digest(event_id.as_bytes()))[..24].to_owned();
        let run = lifecycle_diagnostic_run(p).map(str::to_owned);
        let connection = self
            .connection
            .lock()
            .map_err(|_| anyhow::anyhow!("INTERNAL"))?;
        connection.execute(
            "INSERT INTO follow_hook_diagnostics
             (organization_id,account_subject,installation_id,run_id,event_id_digest,event,outcome,code,observed_at)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
            params![scope.organization, scope.account, scope.installation, run, event_id_digest, event, outcome, code, crate::state::now()],
        )?;
        Ok(())
    }

    fn verify_continuation(&self, scope: Scope<'_>, continuation: &Continuation) -> Result<()> {
        let receipt = &continuation.receipt;
        let connection = self
            .connection
            .lock()
            .map_err(|_| anyhow::anyhow!("INTERNAL"))?;
        let found = connection.query_row(
            "SELECT 1 FROM follow_continuations WHERE receipt=?1 AND organization_id=?2 AND account_subject=?3 AND installation_id=?4 AND run_id=?5 AND expires_at>?6",
            params![receipt, scope.organization, scope.account, scope.installation, continuation.run, crate::state::now()], |_| Ok(()),
        ).optional()?;
        ensure!(found.is_some(), "FOLLOW_RECEIPT_INVALID");
        Ok(())
    }
}

fn decision_for(signal: &Value, delivered_action: &str) -> Value {
    match signal["kind"].as_str().unwrap_or("") {
        "event_page" => {
            json!({"decision":"continue","instruction":"Drain the required event page before requesting another wait.","requiredAction":"drain_events"})
        }
        "active" => {
            json!({"decision":"continue","instruction":"Continue this exact follow session with one bounded wait after the current event cursor.","requiredAction":"wait"})
        }
        "input" => {
            if delivered_action == "handoff" {
                json!({"decision":"needs-handoff","instruction":"The verified pending interaction was handed off; pause this follow session.","requiredAction":"none"})
            } else {
                json!({"decision":"continue","instruction":"Deliver the verified pending interaction with its exact request ID before stopping.","requiredAction":"handoff"})
            }
        }
        "terminal" => {
            if delivered_action == "result_read" {
                json!({"decision":"allow","instruction":"The verified terminal result response is recorded; allow the host stop.","requiredAction":"none"})
            } else {
                json!({"decision":"continue","instruction":"Read the exact terminal result response before stopping.","requiredAction":"result_read"})
            }
        }
        "interrupted" => {
            json!({"decision":"suspend","instruction":"Suspend follow and surface the interruption for a fresh authoritative read.","error":"FOLLOW_INTERRUPTED","requiredAction":"none"})
        }
        _ => {
            json!({"decision":"suspend","instruction":"Suspend follow because the hook signal is invalid.","error":"INVALID_FOLLOW_SIGNAL","requiredAction":"none"})
        }
    }
}

/// Classify an authenticated execution projection.  This mirrors the public
/// runner projection rules and deliberately ignores hook text and tool output.
/// A terminal receipt is recorded only after the server says there are no more
/// event pages, so a Stop cannot bypass required event/result consumption.
fn signal_from_observation(
    observation: &Value,
    binding: &Binding,
    tool_receipt: Option<ToolReceipt<'_>>,
) -> Option<Value> {
    let snapshot = observation.get("snapshot").unwrap_or(observation);
    let execution = snapshot.get("execution")?.as_object()?;
    if execution.get("id")?.as_str()? != binding.run {
        return None;
    }
    let latest = snapshot.get("latestSequence").and_then(Value::as_u64)?;
    if snapshot.get("hasMoreEvents") == Some(&Value::Bool(true)) {
        let events = snapshot.get("events")?.as_array()?;
        let last = events.last()?.get("sequence")?.as_u64()?;
        if last >= latest
            || !events.iter().enumerate().all(|(index, event)| {
                event
                    .get("sequence")
                    .and_then(Value::as_u64)
                    .is_some_and(|sequence| {
                        index == 0
                            || sequence > events[index - 1]["sequence"].as_u64().unwrap_or(u64::MAX)
                    })
            })
        {
            return None;
        }
        return Some(json!({"kind":"event_page","eventSequence":last}));
    }
    let receipt = snapshot_receipt(snapshot)?;
    if let Some(request) = snapshot.get("humanRequest").and_then(Value::as_object) {
        if request.get("status").and_then(Value::as_str) == Some("pending")
            && request
                .get("id")
                .and_then(Value::as_str)
                .is_some_and(|id| Uuid::parse_str(id).is_ok())
            && request
                .get("execution")
                .and_then(|value| value.get("id"))
                .and_then(Value::as_str)
                == Some(binding.run.as_str())
        {
            if let Some(tool_receipt) = tool_receipt
                && tool_receipt.kind == "handoff"
            {
                if request["id"].as_str() == tool_receipt.association_request_id
                    && request["id"].as_str() == tool_receipt.request_request_id
                    && request["id"].as_str() == tool_receipt.response_request_id
                {
                    return Some(json!({
                        "kind":"input",
                        "requestId":request["id"],
                        "receiptId":tool_receipt.receipt
                    }));
                }
                // A relevant interaction tool with a different request is inert.
                // It must not turn another pending request into follow progress.
                return None;
            }
            return Some(json!({"kind":"input","requestId":request["id"],"receiptId":receipt}));
        }
        if request.get("status").and_then(Value::as_str) == Some("pending") {
            return None;
        }
    }
    let status = execution
        .get("status")
        .and_then(Value::as_str)?
        .to_ascii_lowercase();
    if [
        "completed",
        "failed",
        "cancelled",
        "canceled",
        "deleted",
        "succeeded",
        "error",
    ]
    .contains(&status.as_str())
    {
        if let Some(tool_receipt) = tool_receipt
            && tool_receipt.kind == "result_read"
            && terminal_result_matches(observation.get("terminalResult")?, binding)
        {
            return Some(json!({"kind":"terminal","receiptId":tool_receipt.receipt}));
        }
        return Some(json!({"kind":"terminal","receiptId":receipt}));
    }
    if [
        "queued",
        "running",
        "waiting",
        "waiting_for_human",
        "active",
        "in_progress",
    ]
    .contains(&status.as_str())
    {
        return Some(json!({"kind":"active","eventSequence":latest}));
    }
    None
}

fn terminal_result_matches(result: &Value, binding: &Binding) -> bool {
    // Documented runner result projections may expose the execution under the
    // result envelope or as runId. Never infer identity from result text.
    result.pointer("/execution/id").and_then(Value::as_str) == Some(binding.run.as_str())
        || result.get("runId").and_then(Value::as_str) == Some(binding.run.as_str())
        || result
            .pointer("/result/execution/id")
            .and_then(Value::as_str)
            == Some(binding.run.as_str())
}

fn snapshot_receipt(snapshot: &Value) -> Option<String> {
    let digest = crate::state::json_digest(snapshot);
    let key = format!(
        "{}-{}-{}-{}-{}",
        &digest[..8],
        &digest[8..12],
        &digest[12..16],
        &digest[16..20],
        &digest[20..32]
    );
    Uuid::parse_str(&key).ok().map(|value| value.to_string())
}

fn public_hook_decision(decision: &Value) -> Result<Value> {
    let local = decision["decision"]["decision"]
        .as_str()
        .context("INTERNAL")?;
    // `suspend` and `needs-handoff` must let the hook return.  Continuing here
    // would create a host-side stop loop after the runner has already recorded
    // the actionable state.  Runner/socket errors are likewise distinguishable
    // by their JSON-safe public error codes and are not converted to continue.
    let hook = if local == "continue" {
        "continue"
    } else {
        "allow"
    };
    Ok(json!({"schemaVersion":"loomex.follow-session.decision/v1","decision":hook}))
}

/// Stable, non-sensitive outcome labels for installed hook diagnostics.  They
/// are deliberately derived from the normalized lifecycle envelope rather
/// than runner/backend error text.
fn lifecycle_diagnostic_code(p: &Value) -> &'static str {
    match p.get("event").and_then(Value::as_str) {
        Some("UserPromptSubmit") => {
            if p.get("continuation").is_some() {
                "CONTINUATION_RECEIVED"
            } else {
                "NO_CONTINUATION"
            }
        }
        Some("PostToolUse") => {
            if p.pointer("/tool/association/runId")
                .and_then(Value::as_str)
                .is_some()
            {
                "RUN_ASSOCIATED"
            } else {
                "RUN_UNASSOCIATED"
            }
        }
        Some("Stop") => "STOP_RECEIVED",
        Some("Interrupt") => "INTERRUPT_RECEIVED",
        Some("SessionStart") => "SESSION_START_RECEIVED",
        _ => "LIFECYCLE_RECEIVED",
    }
}

/// Only direct, schema-validated run identities are retained for a
/// monitoring diagnostic. Stop and session events intentionally remain
/// unscoped because they do not carry a run association in the host contract.
fn lifecycle_diagnostic_run(p: &Value) -> Option<&str> {
    let candidate = p
        .pointer("/continuation/runId")
        .and_then(Value::as_str)
        .or_else(|| p.pointer("/tool/association/runId").and_then(Value::as_str));
    candidate.filter(|value| Uuid::parse_str(value).is_ok())
}

fn validate_lifecycle(p: &Value) -> Result<()> {
    let object = p.as_object().context("INVALID_REQUEST")?;
    ensure!(
        object.keys().all(|key| [
            "schemaVersion",
            "event",
            "eventId",
            "session",
            "continuation",
            "tool"
        ]
        .contains(&key.as_str())),
        "INVALID_REQUEST"
    );
    ensure!(
        p["schemaVersion"] == "loomex.follow-session.lifecycle/v1",
        "INVALID_REQUEST"
    );
    let event = required(p, "event")?;
    uuid(p, "eventId")?;
    ensure!(
        [
            "SessionStart",
            "UserPromptSubmit",
            "PostToolUse",
            "Stop",
            "Interrupt"
        ]
        .contains(&event),
        "INVALID_REQUEST"
    );
    let session = p["session"].as_object().context("INVALID_REQUEST")?;
    ensure!(
        (2..=3).contains(&session.len())
            && session
                .keys()
                .all(|key| ["id", "cwd", "turnId"].contains(&key.as_str())),
        "INVALID_REQUEST"
    );
    short(&p["session"], "id")?;
    short(&p["session"], "cwd")?;
    if session.contains_key("turnId") {
        short(&p["session"], "turnId")?;
    }
    match event {
        "SessionStart" => {
            ensure!(
                (object.len() == 4 && continuation(p)?.is_none())
                    || (object.len() == 5 && continuation(p)?.is_some()),
                "INVALID_REQUEST"
            );
        }
        "UserPromptSubmit" => {
            ensure!(
                object.len() == 5 && continuation(p)?.is_some(),
                "INVALID_REQUEST"
            );
        }
        "PostToolUse" => {
            let valid_tool = p["tool"].as_object().is_some_and(|tool| {
                tool.len() == 3
                    && tool["name"]
                        .as_str()
                        .is_some_and(|text| !text.is_empty() && text.len() <= 256)
                    && tool["useId"]
                        .as_str()
                        .is_some_and(|text| !text.is_empty() && text.len() <= 256)
                    && tool.get("association").is_some_and(|association| {
                        valid_association(tool["name"].as_str().unwrap_or_default(), association)
                    })
            });
            ensure!(object.len() == 5 && valid_tool, "INVALID_REQUEST");
        }
        _ => ensure!(object.len() == 4, "INVALID_REQUEST"),
    }
    Ok(())
}

fn continuation(p: &Value) -> Result<Option<Continuation>> {
    let Some(value) = p.get("continuation") else {
        return Ok(None);
    };
    let object = value.as_object().context("INVALID_REQUEST")?;
    ensure!(
        value["schemaVersion"] == "loomex.follow-session.continuation/v1",
        "INVALID_REQUEST"
    );
    let run = uuid(value, "runId")?;
    let source = value["source"].as_str().context("INVALID_REQUEST")?;
    ensure!(source == "generated_markdown", "INVALID_REQUEST");
    let receipt = value
        .get("receipt")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let receipt = receipt.context("INVALID_REQUEST")?;
    ensure!(
        object.len() == 4
            && receipt.len() <= 256
            && !receipt.is_empty()
            && receipt
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
            && URL_SAFE_NO_PAD.decode(&receipt).is_ok(),
        "INVALID_REQUEST"
    );
    Ok(Some(Continuation { run, receipt }))
}

fn lifecycle_key(p: &Value, purpose: &str) -> Result<String> {
    let use_id = p["tool"]["useId"].as_str().unwrap_or("");
    let digest = crate::state::json_digest(
        &json!({"purpose":purpose,"event":p["event"],"eventId":p["eventId"],"session":p["session"],"continuation":p["continuation"],"toolUseId":use_id}),
    );
    // SHA-256 hex has enough entropy for a deterministic UUID-shaped receipt.
    // This lets a duplicate hook delivery replay the exact stored result.
    let bytes = digest.as_bytes();
    ensure!(bytes.len() >= 32, "INTERNAL");
    let key = format!(
        "{}-{}-{}-{}-{}",
        &digest[..8],
        &digest[8..12],
        &digest[12..16],
        &digest[16..20],
        &digest[20..32]
    );
    Uuid::parse_str(&key).map_err(|_| anyhow::anyhow!("INTERNAL"))?;
    Ok(key)
}

fn lifecycle_binding(session: &Value, run: &str) -> Result<Binding> {
    let id = short(session, "id")?;
    // Codex hook `turnId` identifies a turn, not a verified durable task.  Do
    // not promote it into the task binding: the session ID plus this explicit
    // sentinel scopes an unverified host task until a future contract provides
    // an owner-verified task identifier.
    Ok(Binding {
        host: "codex".into(),
        host_session: id,
        task: "unverified".into(),
        run: run.into(),
    })
}

fn tool_kind(name: &str) -> Option<&'static str> {
    match name {
        "mcp__loomex__loomex_run_events" | "loomex_run_events" => Some("drain_events"),
        "mcp__loomex__loomex_run_wait"
        | "mcp__loomex__loomex_run_get"
        | "loomex_run_wait"
        | "loomex_run_get" => Some("wait"),
        "mcp__loomex__loomex_interaction_view"
        | "mcp__loomex__loomex_interaction_get"
        | "loomex_interaction_view"
        | "loomex_interaction_get" => Some("handoff"),
        "mcp__loomex__loomex_run_result" | "loomex_run_result" => Some("result_read"),
        _ => None,
    }
}

fn valid_association(name: &str, value: &Value) -> bool {
    let Some(object) = value.as_object() else {
        return false;
    };
    let valid_run = value["runId"]
        .as_str()
        .is_some_and(|run| Uuid::parse_str(run).is_ok());
    let is_interaction = tool_kind(name) == Some("handoff");
    if is_interaction {
        return object.len() == 5
            && object.keys().all(|key| {
                ["schemaVersion", "runId", "requestId", "request", "response"]
                    .contains(&key.as_str())
            })
            && value["schemaVersion"] == "loomex.follow-session.tool-association/v1"
            && valid_run
            && value["requestId"]
                .as_str()
                .is_some_and(|id| Uuid::parse_str(id).is_ok())
            && value["request"].as_object().is_some_and(|request| {
                request.len() == 1
                    && request.keys().all(|key| key == "requestId")
                    && request["requestId"] == value["requestId"]
            })
            && value["response"].as_object().is_some_and(|response| {
                response.len() == 2
                    && response
                        .keys()
                        .all(|key| ["runId", "requestId"].contains(&key.as_str()))
                    && response["runId"] == value["runId"]
                    && response["requestId"] == value["requestId"]
            });
    }
    (object.len() == 4 || object.len() == 5)
        && object.keys().all(|key| {
            ["schemaVersion", "runId", "requestId", "request", "response"].contains(&key.as_str())
        })
        && value["schemaVersion"] == "loomex.follow-session.tool-association/v1"
        && valid_run
        && value["request"].as_object().is_some_and(|request| {
            (request.len() == 1 || request.len() == 2)
                && request
                    .keys()
                    .all(|key| ["runId", "requestId"].contains(&key.as_str()))
                && request.get("runId") == Some(&value["runId"])
                && request
                    .get("requestId")
                    .is_none_or(|id| id.as_str().is_some_and(|id| Uuid::parse_str(id).is_ok()))
        })
        && value["response"].as_object().is_some_and(|response| {
            response.len() <= 2
                && response
                    .keys()
                    .all(|key| ["runId", "requestId"].contains(&key.as_str()))
                && response.get("runId") == Some(&value["runId"])
                && response
                    .get("requestId")
                    .is_none_or(|id| id.as_str().is_some_and(|id| Uuid::parse_str(id).is_ok()))
        })
        && value
            .get("requestId")
            .is_none_or(|id| id.as_str().is_some_and(|id| Uuid::parse_str(id).is_ok()))
}

fn tool_progress(tool: &Value, binding: &Binding) -> Option<ToolProgress> {
    let name = tool.get("name")?.as_str()?;
    let association = tool.get("association")?;
    let kind = tool_kind(name)?;
    if !valid_association(name, association)
        || association["runId"].as_str()? != binding.run
        || association
            .pointer("/response/runId")
            .and_then(Value::as_str)?
            != binding.run
        || (kind != "handoff"
            && association
                .pointer("/request/runId")
                .and_then(Value::as_str)?
                != binding.run)
    {
        return None;
    }
    let association_request_id = association
        .get("requestId")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let request_request_id = association
        .pointer("/request/requestId")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let response_request_id = association
        .pointer("/response/requestId")
        .and_then(Value::as_str)
        .map(str::to_owned);
    if kind == "handoff"
        && (association_request_id.is_none()
            || association_request_id != request_request_id
            || association_request_id != response_request_id)
    {
        return None;
    }
    Some(ToolProgress {
        kind: kind.into(),
        receipt: snapshot_receipt(&association["response"])?,
        association_request_id,
        request_request_id,
        response_request_id,
    })
}

fn required<'a>(p: &'a Value, key: &str) -> Result<&'a str> {
    p[key]
        .as_str()
        .filter(|value| !value.is_empty())
        .context("INVALID_REQUEST")
}

fn new_session(scope: Scope<'_>, binding: &Binding, anchor: &Value, now: u64) -> Value {
    json!({"followSessionId":Uuid::new_v4(),"organizationId":scope.organization,"accountSubject":scope.account,"installationId":scope.installation,
        "hostId":binding.host,"hostSessionId":binding.host_session,"hostTaskId":binding.task,"runId":binding.run,"anchor":anchor,"schemaVersion":SCHEMA_VERSION,
        "generation":1,"revision":1,"mode":"follow","lifecycle":"active","eventCursor":null,"pendingHandoffReceipt":null,"terminalReceipt":null,"recovery":null,"cleanup":null,
        "actionProgress":{"kind":"none","attempted":true},"requiredAction":"none","missedActionCount":0,"hookCount":0,"lastError":null,"createdAt":now,"updatedAt":now,"expiresAt":null})
}
fn reset_generation(session: &mut Value, generation: u64, anchor: &Value, now: u64) {
    *session = json!({"followSessionId":session["followSessionId"],"organizationId":session["organizationId"],"accountSubject":session["accountSubject"],"installationId":session["installationId"],
        "hostId":session["hostId"],"hostSessionId":session["hostSessionId"],"hostTaskId":session["hostTaskId"],"runId":session["runId"],"anchor":anchor,"schemaVersion":SCHEMA_VERSION,
        "generation":generation,"revision":session["revision"].as_u64().unwrap_or(0)+1,"mode":"follow","lifecycle":"active","eventCursor":null,"pendingHandoffReceipt":null,"terminalReceipt":null,"recovery":session["recovery"],"cleanup":session["cleanup"],
        "actionProgress":{"kind":"none","attempted":true},"requiredAction":"none","missedActionCount":0,"hookCount":0,"lastError":null,"createdAt":session["createdAt"],"updatedAt":now,"expiresAt":null});
}

fn follow_expiry(session: &Value) -> Option<u64> {
    (session["lifecycle"] == "terminal"
        && session["requiredAction"] == "none"
        && !session["terminalReceipt"].is_null())
    .then(|| {
        session["updatedAt"]
            .as_u64()
            .unwrap_or(0)
            .saturating_add(RETENTION_SECONDS)
    })
}
fn public_binding(b: &Binding) -> Value {
    json!({"hostId":b.host,"hostSessionId":b.host_session,"hostTaskId":b.task,"runId":b.run})
}
fn binding(p: &Value) -> Result<Binding> {
    let b = p["binding"].as_object().context("INVALID_REQUEST")?;
    ensure!(
        b.len() == 4
            && b.keys()
                .all(|k| ["hostId", "hostSessionId", "hostTaskId", "runId"].contains(&k.as_str())),
        "INVALID_REQUEST"
    );
    let host = short(&p["binding"], "hostId")?;
    let host_session = short(&p["binding"], "hostSessionId")?;
    let task = short(&p["binding"], "hostTaskId")?;
    let run = uuid(&p["binding"], "runId")?;
    Ok(Binding {
        host,
        host_session,
        task,
        run,
    })
}
fn anchor(value: &Value) -> Result<Value> {
    let o = value.as_object().context("INVALID_REQUEST")?;
    let kind = o
        .get("kind")
        .and_then(Value::as_str)
        .filter(|k| {
            [
                "explicit_follow",
                "verified_continuation",
                "accepted_interaction",
            ]
            .contains(k)
        })
        .context("INVALID_FOLLOW_ANCHOR")?;
    ensure!(
        o.len() == 2 || (kind == "accepted_interaction" && o.len() == 3),
        "INVALID_FOLLOW_ANCHOR"
    );
    let receipt = uuid(value, "receiptId")?;
    if kind == "accepted_interaction" {
        uuid(value, "requestId")?;
    } else {
        ensure!(!o.contains_key("requestId"), "INVALID_FOLLOW_ANCHOR");
    }
    Ok(
        json!({"kind":kind,"receiptId":receipt,"requestId":value.get("requestId").cloned().unwrap_or(Value::Null)}),
    )
}
fn signal(value: &Value) -> Result<Value> {
    let o = value.as_object().context("INVALID_REQUEST")?;
    let kind = o
        .get("kind")
        .and_then(Value::as_str)
        .filter(|k| ["event_page", "active", "input", "terminal", "interrupted"].contains(k))
        .context("INVALID_FOLLOW_SIGNAL")?;
    match kind {
        "event_page" | "active" => {
            ensure!(o.len() <= 2, "INVALID_FOLLOW_SIGNAL");
            if let Some(v) = o.get("eventSequence") {
                ensure!(v.as_u64().is_some(), "INVALID_FOLLOW_SIGNAL");
            }
        }
        "input" => {
            ensure!(o.len() == 3, "INVALID_FOLLOW_SIGNAL");
            uuid(value, "requestId")?;
            uuid(value, "receiptId")?;
        }
        "terminal" => {
            ensure!(o.len() == 2, "INVALID_FOLLOW_SIGNAL");
            uuid(value, "receiptId")?;
        }
        "interrupted" => {
            ensure!(o.len() == 2, "INVALID_FOLLOW_SIGNAL");
            let code = short(value, "code")?;
            ensure!(
                code.bytes().all(|b| b.is_ascii_uppercase() || b == b'_'),
                "INVALID_FOLLOW_SIGNAL"
            );
        }
        _ => unreachable!(),
    };
    Ok(value.clone())
}
fn action(value: &Value) -> Result<Value> {
    let o = value.as_object().context("INVALID_ACTION_PROGRESS")?;
    ensure!(
        o.len() == 2 && o.get("attempted").and_then(Value::as_bool).is_some(),
        "INVALID_ACTION_PROGRESS"
    );
    let kind = o
        .get("kind")
        .and_then(Value::as_str)
        .filter(|k| ["none", "drain_events", "wait", "handoff", "result_read"].contains(k))
        .context("INVALID_ACTION_PROGRESS")?;
    Ok(json!({"kind":kind,"attempted":o["attempted"]}))
}
fn short(value: &Value, key: &str) -> Result<String> {
    let s = value[key]
        .as_str()
        .filter(|s| !s.is_empty() && s.len() <= 256)
        .context("INVALID_REQUEST")?;
    Ok(s.into())
}
fn uuid(value: &Value, key: &str) -> Result<String> {
    let s = short(value, key)?;
    Uuid::parse_str(&s).map_err(|_| anyhow::anyhow!("INVALID_REQUEST"))?;
    Ok(s)
}
fn required_u64(p: &Value, key: &str) -> Result<u64> {
    p[key].as_u64().context("INVALID_REQUEST")
}
fn required_uuid<'a>(p: &'a Value, key: &str) -> Result<&'a str> {
    let s = p[key]
        .as_str()
        .filter(|s| !s.is_empty())
        .context("INVALID_REQUEST")?;
    Uuid::parse_str(s).map_err(|_| anyhow::anyhow!("INVALID_REQUEST"))?;
    Ok(s)
}
fn encode(value: &Value) -> Result<Vec<u8>> {
    let bytes = serde_json::to_vec(value)?;
    ensure!(bytes.len() <= MAX_JSON_BYTES, "INVALID_REQUEST");
    Ok(bytes)
}
fn decode(bytes: &[u8]) -> rusqlite::Result<Value> {
    serde_json::from_slice(bytes).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(
            bytes.len(),
            rusqlite::types::Type::Blob,
            Box::new(e),
        )
    })
}
fn find(connection: &Connection, scope: Scope<'_>, b: &Binding) -> Result<Option<Value>> {
    connection.query_row("SELECT follow_session_id,anchor_digest,schema_version,generation,revision,mode,lifecycle,event_cursor,pending_handoff_json,terminal_receipt_json,recovery_json,cleanup_json,action_progress_json,required_action,missed_action_count,hook_count,last_error,created_at,updated_at,expires_at FROM follow_sessions WHERE organization_id=?1 AND account_subject=?2 AND installation_id=?3 AND host_id=?4 AND host_session_id=?5 AND host_task_id=?6 AND run_id=?7",params![scope.organization,scope.account,scope.installation,b.host,b.host_session,b.task,b.run],|r|{let action:Vec<u8>=r.get(12)?;Ok(json!({"followSessionId":r.get::<_,String>(0)?,"organizationId":scope.organization,"accountSubject":scope.account,"installationId":scope.installation,"hostId":b.host,"hostSessionId":b.host_session,"hostTaskId":b.task,"runId":b.run,"anchor":serde_json::from_str::<Value>(&r.get::<_,String>(1)?).unwrap_or(Value::Null),"schemaVersion":r.get::<_,u64>(2)?,"generation":r.get::<_,u64>(3)?,"revision":r.get::<_,u64>(4)?,"mode":r.get::<_,String>(5)?,"lifecycle":r.get::<_,String>(6)?,"eventCursor":r.get::<_,Option<u64>>(7)?,"pendingHandoffReceipt":opt_json(r.get(8)?)?,"terminalReceipt":opt_json(r.get(9)?)?,"recovery":opt_json(r.get(10)?)?,"cleanup":opt_json(r.get(11)?)?,"actionProgress":decode(&action)?,"requiredAction":r.get::<_,String>(13)?,"missedActionCount":r.get::<_,u64>(14)?,"hookCount":r.get::<_,u64>(15)?,"lastError":r.get::<_,Option<String>>(16)?,"createdAt":r.get::<_,u64>(17)?,"updatedAt":r.get::<_,u64>(18)?,"expiresAt":r.get::<_,Option<u64>>(19)?}))}).optional().map_err(Into::into)
}
fn opt_json(bytes: Option<Vec<u8>>) -> rusqlite::Result<Value> {
    match bytes {
        Some(b) => decode(&b),
        None => Ok(Value::Null),
    }
}
fn insert(c: &Connection, s: Scope<'_>, v: &Value) -> Result<()> {
    c.execute("INSERT INTO follow_sessions VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21,?22,?23,?24,?25,?26,?27)",params![text(v,"followSessionId")?,s.organization,s.account,s.installation,text(v,"hostId")?,text(v,"hostSessionId")?,text(v,"hostTaskId")?,text(v,"runId")?,serde_json::to_string(&v["anchor"] )?,number(v,"schemaVersion")?,number(v,"generation")?,number(v,"revision")?,text(v,"mode")?,text(v,"lifecycle")?,optional_number(v,"eventCursor")?,null_blob(&v["pendingHandoffReceipt"] )?,null_blob(&v["terminalReceipt"] )?,null_blob(&v["recovery"] )?,null_blob(&v["cleanup"] )?,encode(&v["actionProgress"] )?,text(v,"requiredAction")?,number(v,"missedActionCount")?,number(v,"hookCount")?,optional_text(v,"lastError")?,number(v,"createdAt")?,number(v,"updatedAt")?,optional_number(v,"expiresAt")?])?;
    Ok(())
}
fn write(c: &Connection, s: Scope<'_>, v: &Value) -> Result<()> {
    c.execute("UPDATE follow_sessions SET anchor_digest=?1,schema_version=?2,generation=?3,revision=?4,mode=?5,lifecycle=?6,event_cursor=?7,pending_handoff_json=?8,terminal_receipt_json=?9,recovery_json=?10,cleanup_json=?11,action_progress_json=?12,required_action=?13,missed_action_count=?14,hook_count=?15,last_error=?16,updated_at=?17,expires_at=?18 WHERE follow_session_id=?19 AND organization_id=?20 AND account_subject=?21 AND installation_id=?22",params![serde_json::to_string(&v["anchor"] )?,number(v,"schemaVersion")?,number(v,"generation")?,number(v,"revision")?,text(v,"mode")?,text(v,"lifecycle")?,optional_number(v,"eventCursor")?,null_blob(&v["pendingHandoffReceipt"] )?,null_blob(&v["terminalReceipt"] )?,null_blob(&v["recovery"] )?,null_blob(&v["cleanup"] )?,encode(&v["actionProgress"] )?,text(v,"requiredAction")?,number(v,"missedActionCount")?,number(v,"hookCount")?,optional_text(v,"lastError")?,number(v,"updatedAt")?,optional_number(v,"expiresAt")?,text(v,"followSessionId")?,s.organization,s.account,s.installation])?;
    Ok(())
}
fn null_blob(v: &Value) -> Result<Option<Vec<u8>>> {
    if v.is_null() {
        Ok(None)
    } else {
        Ok(Some(encode(v)?))
    }
}
fn text<'a>(v: &'a Value, key: &str) -> Result<&'a str> {
    v[key].as_str().context("INTERNAL")
}
fn optional_text<'a>(v: &'a Value, key: &str) -> Result<Option<&'a str>> {
    if v[key].is_null() {
        Ok(None)
    } else {
        Ok(Some(text(v, key)?))
    }
}
fn number(v: &Value, key: &str) -> Result<u64> {
    v[key].as_u64().context("INTERNAL")
}
fn optional_number(v: &Value, key: &str) -> Result<Option<u64>> {
    if v[key].is_null() {
        Ok(None)
    } else {
        Ok(Some(number(v, key)?))
    }
}
fn receipt(
    c: &Connection,
    s: Scope<'_>,
    method: &str,
    key: &str,
    digest: &str,
) -> Result<Option<Value>> {
    let r:Option<(String,Vec<u8>)>=c.query_row("SELECT request_digest,result_json FROM follow_receipts WHERE organization_id=?1 AND account_subject=?2 AND installation_id=?3 AND method=?4 AND idempotency_key=?5",params![s.organization,s.account,s.installation,method,key],|r|Ok((r.get(0)?,r.get(1)?))).optional()?;
    match r {
        Some((d, v)) => {
            ensure!(d == digest, "IDEMPOTENCY_CONFLICT");
            Ok(Some(decode(&v)?))
        }
        None => Ok(None),
    }
}
fn save_receipt(
    c: &Connection,
    s: Scope<'_>,
    method: &str,
    key: &str,
    digest: &str,
    result: &Value,
    now: u64,
) -> Result<()> {
    c.execute(
        "INSERT INTO follow_receipts VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",
        params![
            s.organization,
            s.account,
            s.installation,
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

#[cfg(test)]
mod tests {
    use super::*;
    fn scope() -> Scope<'static> {
        Scope {
            organization: "org",
            account: "account",
            installation: "install",
        }
    }
    fn binding() -> Value {
        json!({"hostId":"local","hostSessionId":"session","hostTaskId":"task","runId":Uuid::new_v4()})
    }
    fn anchor() -> Value {
        json!({"kind":"explicit_follow","receiptId":Uuid::new_v4()})
    }
    fn activate(store: &FollowStore, b: &Value, g: u64) -> Value {
        store.activate(scope(),&json!({"binding":b,"anchor":anchor(),"expectedGeneration":g,"idempotencyKey":Uuid::new_v4()})).unwrap()["session"].clone()
    }
    fn decide(
        store: &FollowStore,
        b: &Value,
        s: &Value,
        signal: Value,
        attempted: bool,
        kind: &str,
    ) -> Value {
        store.decide(scope(),&json!({"binding":b,"generation":s["generation"],"expectedRevision":s["revision"],"signal":signal,"actionProgress":{"kind":kind,"attempted":attempted},"idempotencyKey":Uuid::new_v4()})).unwrap()
    }
    #[test]
    fn activation_is_scoped_and_anchor_gated() {
        let t = tempfile::tempdir().unwrap();
        let store = FollowStore::open(t.path()).unwrap();
        let b = binding();
        let s = activate(&store, &b, 0);
        assert_eq!(s["generation"], 1);
        assert!(store.activate(scope(),&json!({"binding":b,"anchor":{"kind":"status","receiptId":Uuid::new_v4()},"expectedGeneration":1,"idempotencyKey":Uuid::new_v4()})).is_err());
        assert!(
            !store
                .get(
                    Scope {
                        organization: "other",
                        ..scope()
                    },
                    &json!({"binding":b})
                )
                .unwrap()["found"]
                .as_bool()
                .unwrap()
        );
    }
    #[test]
    fn monitoring_keeps_handoff_and_delivered_hook_evidence_distinct() {
        let t = tempfile::tempdir().unwrap();
        let store = FollowStore::open(t.path()).unwrap();
        let run = Uuid::new_v4().to_string();
        let receipt = store
            .issue_continuation("org", "account", "install", &run, "run_commit", None)
            .unwrap();
        store
            .activate_ui_handoff("org", "account", "install", &run, &receipt, None)
            .unwrap();
        let bound = json!({
            "hostId":"codex",
            "hostSessionId":"host-session",
            "hostTaskId":"unverified",
            "runId":run,
        });
        let active = activate(&store, &bound, 0);

        let before = store
            .monitoring_observation("org", "account", "install", &run)
            .unwrap();
        assert_eq!(before["recordCount"], 2);
        assert!(before["hostHookDeliveryGuaranteed"] == false);
        let records = before["records"].as_array().unwrap();
        let ui = records
            .iter()
            .find(|record| record["uiHandoffRecorded"] == true)
            .unwrap();
        assert_eq!(ui["hookCount"], 0);
        assert_eq!(ui["hostHookObserved"], false);
        assert_eq!(ui["activationState"], "handoff_pending");
        let host = records
            .iter()
            .find(|record| record["binding"]["state"] == "host_session_unverified_task")
            .unwrap();
        assert_eq!(host["hookCount"], 0);
        assert_eq!(host["hostHookObserved"], false);
        assert_eq!(host["activationState"], "hook_not_observed");
        assert_eq!(host["binding"]["verified"], false);

        decide(
            &store,
            &bound,
            &active,
            json!({"kind":"active"}),
            false,
            "none",
        );
        let after = store
            .monitoring_observation("org", "account", "install", &run)
            .unwrap();
        let host = after["records"]
            .as_array()
            .unwrap()
            .iter()
            .find(|record| record["binding"]["state"] == "host_session_unverified_task")
            .unwrap();
        assert_eq!(host["hookCount"], 1);
        assert_eq!(host["hostHookObserved"], true);
        assert_eq!(host["activationState"], "hook_observed");
    }
    #[test]
    fn monitoring_observation_never_serializes_host_session_or_task_values() {
        let t = tempfile::tempdir().unwrap();
        let store = FollowStore::open(t.path()).unwrap();
        let run = Uuid::new_v4().to_string();
        let session = "session-value-must-not-leak";
        let task = "task-value-must-not-leak";
        let binding = json!({
            "hostId":"codex",
            "hostSessionId":session,
            "hostTaskId":task,
            "runId":run,
        });
        activate(&store, &binding, 0);

        let observation = store
            .monitoring_observation("org", "account", "install", &run)
            .unwrap();
        let serialized = observation.to_string();
        assert!(!serialized.contains(session));
        assert!(!serialized.contains(task));
        assert!(serialized.contains("verified_host_task"));
        assert!(serialized.contains("\"verified\":true"));
    }
    #[test]
    fn stale_generation_cannot_change_newer_session() {
        let t = tempfile::tempdir().unwrap();
        let store = FollowStore::open(t.path()).unwrap();
        let b = binding();
        let old = activate(&store, &b, 0);
        let new = activate(&store, &b, 1);
        assert_eq!(new["generation"], 2);
        let e=store.decide(scope(),&json!({"binding":b,"generation":old["generation"],"expectedRevision":old["revision"],"signal":{"kind":"active"},"actionProgress":{"kind":"none","attempted":true},"idempotencyKey":Uuid::new_v4()})).unwrap_err();
        assert_eq!(e.to_string(), "STALE_FOLLOW_GENERATION");
    }
    #[test]
    fn decision_table_and_loop_guard() {
        let t = tempfile::tempdir().unwrap();
        let store = FollowStore::open(t.path()).unwrap();
        let b = binding();
        let s = activate(&store, &b, 0);
        let page = decide(
            &store,
            &b,
            &s,
            json!({"kind":"event_page","eventSequence":4}),
            true,
            "none",
        );
        assert_eq!(page["decision"]["decision"], "continue");
        let s = page["session"].clone();
        let input = decide(
            &store,
            &b,
            &s,
            json!({"kind":"input","requestId":Uuid::new_v4(),"receiptId":Uuid::new_v4()}),
            true,
            "drain_events",
        );
        assert_eq!(input["decision"]["requiredAction"], "handoff");
        let s = input["session"].clone();
        let handoff = decide(
            &store,
            &b,
            &s,
            json!({"kind":"input","requestId":Uuid::new_v4(),"receiptId":Uuid::new_v4()}),
            true,
            "handoff",
        );
        assert_eq!(handoff["decision"]["decision"], "needs-handoff");
    }
    #[test]
    fn terminal_and_interrupted_decisions_are_distinct() {
        let t = tempfile::tempdir().unwrap();
        let store = FollowStore::open(t.path()).unwrap();
        let b = binding();
        let s = activate(&store, &b, 0);
        let terminal = decide(
            &store,
            &b,
            &s,
            json!({"kind":"terminal","receiptId":Uuid::new_v4()}),
            true,
            "result_read",
        );
        assert_eq!(terminal["decision"]["decision"], "allow");
        let b = binding();
        let s = activate(&store, &b, 0);
        let interrupted = decide(
            &store,
            &b,
            &s,
            json!({"kind":"interrupted","code":"RUNNER_UNAVAILABLE"}),
            true,
            "none",
        );
        assert_eq!(interrupted["decision"]["decision"], "suspend");
    }

    #[test]
    fn only_clean_terminal_sessions_receive_the_thirty_day_expiry() {
        let t = tempfile::tempdir().unwrap();
        let store = FollowStore::open(t.path()).unwrap();
        let terminal_binding = binding();
        let active = activate(&store, &terminal_binding, 0);
        assert!(active["expiresAt"].is_null());
        store
            .sweep(crate::state::now() + RETENTION_SECONDS + 1)
            .unwrap();
        assert!(
            store
                .get(scope(), &json!({"binding":terminal_binding}))
                .unwrap()["found"]
                .as_bool()
                .unwrap()
        );

        let terminal = decide(
            &store,
            &terminal_binding,
            &active,
            json!({"kind":"terminal","receiptId":Uuid::new_v4()}),
            true,
            "result_read",
        );
        let expiry = terminal["session"]["expiresAt"].as_u64().unwrap();
        store.sweep(expiry - 1).unwrap();
        assert!(
            store
                .get(scope(), &json!({"binding":terminal_binding}))
                .unwrap()["found"]
                .as_bool()
                .unwrap()
        );
        store.sweep(expiry).unwrap();
        assert!(
            !store
                .get(scope(), &json!({"binding":terminal_binding}))
                .unwrap()["found"]
                .as_bool()
                .unwrap()
        );

        let suspended_binding = binding();
        let active = activate(&store, &suspended_binding, 0);
        let suspended = decide(
            &store,
            &suspended_binding,
            &active,
            json!({"kind":"interrupted","code":"RUNNER_UNAVAILABLE"}),
            true,
            "none",
        );
        assert!(suspended["session"]["expiresAt"].is_null());
        store
            .sweep(crate::state::now() + RETENTION_SECONDS + 1)
            .unwrap();
        assert!(
            store
                .get(scope(), &json!({"binding":suspended_binding}))
                .unwrap()["found"]
                .as_bool()
                .unwrap()
        );
    }

    fn hook(event: &str, session: &str) -> Value {
        json!({"schemaVersion":"loomex.follow-session.lifecycle/v1","event":event,"eventId":Uuid::new_v4(),"session":{"id":session,"cwd":"/workspace","turnId":"turn-not-a-task"}})
    }

    fn receipt_key(receipt: &str) -> String {
        let mut bytes: [u8; 16] = Sha256::digest(receipt.as_bytes())[..16]
            .try_into()
            .expect("SHA-256 prefix has sixteen bytes");
        bytes[6] = (bytes[6] & 0x0f) | 0x80;
        bytes[8] = (bytes[8] & 0x3f) | 0x80;
        Uuid::from_bytes(bytes).to_string()
    }

    fn snapshot(run: &Uuid, status: &str, has_more: bool) -> Value {
        json!({"execution":{"id":run,"status":status},"events":[],"latestSequence":0,"hasMoreEvents":has_more,"humanRequest":null})
    }

    fn runner_issued_continuation(store: &FollowStore, run: &Uuid) -> Value {
        let run = run.to_string();
        let receipt = store
            .issue_continuation("org", "account", "install", &run, "run_commit", None)
            .unwrap();
        json!({"schemaVersion":"loomex.follow-session.continuation/v1","runId":run,"source":"generated_markdown","receipt":receipt})
    }

    #[test]
    fn hook_activation_is_exact_idempotent_and_does_not_bind_turn_as_task() {
        let t = tempfile::tempdir().unwrap();
        let store = FollowStore::open(t.path()).unwrap();
        let session = "hook-session";
        let run = Uuid::new_v4();
        let mut start = hook("UserPromptSubmit", session);
        start["continuation"] = runner_issued_continuation(&store, &run);
        assert_eq!(
            store
                .dispatch(
                    "org",
                    "account",
                    "install",
                    "follow.session.lifecycle",
                    &start
                )
                .unwrap()["decision"],
            "continue"
        );
        // Exact duplicate delivery replays its durable receipt; it cannot create
        // a new generation.
        assert_eq!(
            store
                .dispatch(
                    "org",
                    "account",
                    "install",
                    "follow.session.lifecycle",
                    &start
                )
                .unwrap()["decision"],
            "continue"
        );
        let binding = Binding {
            host: "codex".into(),
            host_session: session.into(),
            task: "unverified".into(),
            run: run.to_string(),
        };
        let record = store
            .get(scope(), &json!({"binding":public_binding(&binding)}))
            .unwrap()["session"]
            .clone();
        assert_eq!(record["generation"], 1);
        assert_eq!(record["hostTaskId"], "unverified");
        assert_eq!(
            store
                .dispatch(
                    "org",
                    "account",
                    "install",
                    "follow.session.lifecycle",
                    &hook("SessionStart", session),
                )
                .unwrap()["decision"],
            "continue"
        );
    }

    #[test]
    fn lifecycle_diagnostics_prove_hook_receipt_without_retaining_host_payloads() {
        let t = tempfile::tempdir().unwrap();
        let store = FollowStore::open(t.path()).unwrap();
        let run = Uuid::new_v4();
        let mut start = hook("UserPromptSubmit", "diagnostic-session");
        start["continuation"] = runner_issued_continuation(&store, &run);
        store
            .dispatch(
                "org",
                "account",
                "install",
                "follow.session.lifecycle",
                &start,
            )
            .unwrap();

        let observation = store
            .monitoring_observation("org", "account", "install", &run.to_string())
            .unwrap();
        let diagnostics = &observation["hookDiagnostics"];
        assert_eq!(diagnostics["recordCount"], 1);
        let row = &diagnostics["records"][0];
        assert_eq!(row["event"], "UserPromptSubmit");
        assert_eq!(row["outcome"], "accepted");
        assert_eq!(row["code"], "CONTINUATION_RECEIVED");
        assert!(row.get("sessionId").is_none());
        assert!(row.get("cwd").is_none());
    }

    #[test]
    fn ui_handoff_is_pending_until_an_exact_run_wait_promotes_it() {
        let t = tempfile::tempdir().unwrap();
        let store = FollowStore::open(t.path()).unwrap();
        let run = Uuid::new_v4().to_string();
        let receipt = store
            .issue_continuation("org", "account", "install", &run, "run_commit", None)
            .unwrap();
        store
            .activate_ui_handoff("org", "account", "install", &run, &receipt, None)
            .unwrap();
        // A duplicate UI delivery preserves the pending handoff rather than
        // resetting a follow that a host session may already be starting.
        store
            .activate_ui_handoff("org", "account", "install", &run, &receipt, None)
            .unwrap();
        let binding = json!({"hostId":"codex-ui","hostSessionId":"unbound","hostTaskId":format!("ui-handoff:{}", receipt_key(&receipt)),"runId":run});
        let pending = store.get(scope(), &json!({"binding":binding})).unwrap()["session"].clone();
        assert_eq!(pending["generation"], 1);
        assert_eq!(pending["lifecycle"], "handoff_pending");

        let stop = hook("Stop", "host-session-that-never-saw-ui-message");
        assert!(
            store
                .lifecycle_target("org", "account", "install", &stop)
                .unwrap()
                .is_none()
        );
        // A run detail uses the same exact run association but is a read, not
        // a declaration that this session should be monitored.
        let mut get = hook("PostToolUse", "host-session-that-never-saw-ui-message");
        get["tool"] = json!({"name":"mcp__loomex__loomex_run_get","useId":"get-1","association":{"schemaVersion":"loomex.follow-session.tool-association/v1","runId":run,"request":{"runId":run},"response":{"runId":run}}});
        assert!(
            store
                .lifecycle_target("org", "account", "install", &get)
                .unwrap()
                .is_none()
        );

        let mut wait = hook("PostToolUse", "host-session-that-never-saw-ui-message");
        wait["tool"] = json!({"name":"mcp__loomex__loomex_run_wait","useId":"wait-1","association":{"schemaVersion":"loomex.follow-session.tool-association/v1","runId":run,"request":{"runId":run},"response":{"runId":run}}});
        let target = store
            .lifecycle_target("org", "account", "install", &wait)
            .unwrap()
            .unwrap();
        assert_eq!(target.run_id, run);
        let native = json!({"hostId":"codex","hostSessionId":"host-session-that-never-saw-ui-message","hostTaskId":"unverified","runId":run});
        assert_eq!(
            store.get(scope(), &json!({"binding":native})).unwrap()["session"]["lifecycle"],
            "active"
        );
        assert_eq!(
            store.get(scope(), &json!({"binding":binding})).unwrap()["session"]["lifecycle"],
            "superseded"
        );
    }

    #[test]
    fn pending_ui_handoff_cannot_be_claimed_by_a_second_host_session() {
        let t = tempfile::tempdir().unwrap();
        let store = FollowStore::open(t.path()).unwrap();
        let run = Uuid::new_v4().to_string();
        let receipt = store
            .issue_continuation("org", "account", "install", &run, "run_commit", None)
            .unwrap();
        store
            .activate_ui_handoff("org", "account", "install", &run, &receipt, None)
            .unwrap();
        let mut first_wait = hook("PostToolUse", "first-session");
        first_wait["tool"] = json!({"name":"mcp__loomex__loomex_run_wait","useId":"wait-1","association":{"schemaVersion":"loomex.follow-session.tool-association/v1","runId":run,"request":{"runId":run},"response":{"runId":run}}});
        assert!(
            store
                .lifecycle_target("org", "account", "install", &first_wait)
                .unwrap()
                .is_some()
        );

        let mut second_wait = hook("PostToolUse", "second-session");
        second_wait["tool"] = json!({"name":"mcp__loomex__loomex_run_wait","useId":"wait-2","association":{"schemaVersion":"loomex.follow-session.tool-association/v1","runId":run,"request":{"runId":run},"response":{"runId":run}}});
        assert!(
            store
                .lifecycle_target("org", "account", "install", &second_wait)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn accepted_interaction_reactivates_only_its_exact_native_follow() {
        let t = tempfile::tempdir().unwrap();
        let store = FollowStore::open(t.path()).unwrap();
        let run = Uuid::new_v4().to_string();
        let start_receipt = store
            .issue_continuation("org", "account", "install", &run, "run_commit", None)
            .unwrap();
        store
            .activate_ui_handoff("org", "account", "install", &run, &start_receipt, None)
            .unwrap();
        let mut initial_wait = hook("PostToolUse", "native-session");
        initial_wait["tool"] = json!({"name":"mcp__loomex__loomex_run_wait","useId":"wait-start","association":{"schemaVersion":"loomex.follow-session.tool-association/v1","runId":run,"request":{"runId":run},"response":{"runId":run}}});
        assert!(
            store
                .lifecycle_target("org", "account", "install", &initial_wait)
                .unwrap()
                .is_some()
        );

        let native = json!({"hostId":"codex","hostSessionId":"native-session","hostTaskId":"unverified","runId":run});
        let active = store.get(scope(), &json!({"binding":native})).unwrap()["session"].clone();
        let request = Uuid::new_v4().to_string();
        let input = json!({"kind":"input","requestId":request,"receiptId":Uuid::new_v4()});
        let requested = decide(&store, &native, &active, input.clone(), true, "none");
        let handoff = decide(
            &store,
            &native,
            &requested["session"],
            input,
            true,
            "handoff",
        );
        assert_eq!(handoff["decision"]["decision"], "needs-handoff");
        assert_eq!(
            store.get(scope(), &json!({"binding":native})).unwrap()["session"]["lifecycle"],
            "input_pending"
        );

        let response_receipt = store
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
            .activate_ui_handoff(
                "org",
                "account",
                "install",
                &run,
                &response_receipt,
                Some(&request),
            )
            .unwrap();
        let mut resumed_wait = hook("PostToolUse", "native-session");
        resumed_wait["tool"] = json!({"name":"mcp__loomex__loomex_run_wait","useId":"wait-resume","association":{"schemaVersion":"loomex.follow-session.tool-association/v1","runId":run,"request":{"runId":run},"response":{"runId":run}}});
        assert_eq!(
            store
                .lifecycle_target("org", "account", "install", &resumed_wait)
                .unwrap()
                .unwrap()
                .run_id,
            run
        );
        let resumed = store.get(scope(), &json!({"binding":native})).unwrap()["session"].clone();
        assert_eq!(resumed["lifecycle"], "active");
        assert!(resumed["generation"].as_u64().unwrap() > active["generation"].as_u64().unwrap());
        assert!(resumed["pendingHandoffReceipt"].is_null());
    }

    #[test]
    fn mismatched_accepted_interaction_cannot_reactivate_input_pending_follow() {
        let t = tempfile::tempdir().unwrap();
        let store = FollowStore::open(t.path()).unwrap();
        let run = Uuid::new_v4().to_string();
        let receipt = store
            .issue_continuation("org", "account", "install", &run, "run_commit", None)
            .unwrap();
        store
            .activate_ui_handoff("org", "account", "install", &run, &receipt, None)
            .unwrap();
        let mut wait = hook("PostToolUse", "native-session");
        wait["tool"] = json!({"name":"mcp__loomex__loomex_run_wait","useId":"wait-start","association":{"schemaVersion":"loomex.follow-session.tool-association/v1","runId":run,"request":{"runId":run},"response":{"runId":run}}});
        store
            .lifecycle_target("org", "account", "install", &wait)
            .unwrap();
        let native = json!({"hostId":"codex","hostSessionId":"native-session","hostTaskId":"unverified","runId":run});
        let active = store.get(scope(), &json!({"binding":native})).unwrap()["session"].clone();
        let pending_request = Uuid::new_v4().to_string();
        let input = json!({"kind":"input","requestId":pending_request,"receiptId":Uuid::new_v4()});
        let requested = decide(&store, &native, &active, input.clone(), true, "none");
        decide(
            &store,
            &native,
            &requested["session"],
            input,
            true,
            "handoff",
        );
        let other_request = Uuid::new_v4().to_string();
        let other_receipt = store
            .issue_continuation(
                "org",
                "account",
                "install",
                &run,
                "accepted_interaction",
                Some(&other_request),
            )
            .unwrap();
        store
            .activate_ui_handoff(
                "org",
                "account",
                "install",
                &run,
                &other_receipt,
                Some(&other_request),
            )
            .unwrap();
        let mut resumed_wait = hook("PostToolUse", "native-session");
        resumed_wait["tool"] = json!({"name":"mcp__loomex__loomex_run_wait","useId":"wait-resume","association":{"schemaVersion":"loomex.follow-session.tool-association/v1","runId":run,"request":{"runId":run},"response":{"runId":run}}});
        assert_eq!(
            store
                .lifecycle_target("org", "account", "install", &resumed_wait)
                .unwrap_err()
                .to_string(),
            "FOLLOW_HANDOFF_MISMATCH"
        );
        assert_eq!(
            store.get(scope(), &json!({"binding":native})).unwrap()["session"]["lifecycle"],
            "input_pending"
        );
    }

    #[test]
    fn pending_ui_handoff_never_guesses_between_two_sources_for_the_same_run() {
        let t = tempfile::tempdir().unwrap();
        let store = FollowStore::open(t.path()).unwrap();
        let run = Uuid::new_v4().to_string();
        let first_receipt = store
            .issue_continuation("org", "account", "install", &run, "run_commit", None)
            .unwrap();
        store
            .activate_ui_handoff("org", "account", "install", &run, &first_receipt, None)
            .unwrap();
        let request = Uuid::new_v4().to_string();
        let second_receipt = store
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
            .activate_ui_handoff(
                "org",
                "account",
                "install",
                &run,
                &second_receipt,
                Some(&request),
            )
            .unwrap();
        let mut wait = hook("PostToolUse", "host");
        wait["tool"] = json!({"name":"mcp__loomex__loomex_run_wait","useId":"wait-1","association":{"schemaVersion":"loomex.follow-session.tool-association/v1","runId":run,"request":{"runId":run},"response":{"runId":run}}});
        assert!(
            store
                .lifecycle_target("org", "account", "install", &wait)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn hook_stop_continues_once_then_allows_after_missing_required_action() {
        let t = tempfile::tempdir().unwrap();
        let store = FollowStore::open(t.path()).unwrap();
        let session = "hook-session";
        let mut start = hook("UserPromptSubmit", session);
        let run = Uuid::new_v4();
        start["continuation"] = runner_issued_continuation(&store, &run);
        store
            .dispatch(
                "org",
                "account",
                "install",
                "follow.session.lifecycle",
                &start,
            )
            .unwrap();
        let stop = hook("Stop", session);
        assert_eq!(
            store
                .dispatch_observed(
                    "org",
                    "account",
                    "install",
                    "follow.session.lifecycle",
                    &stop,
                    Some(&snapshot(&run, "running", false))
                )
                .unwrap()["decision"],
            "continue"
        );
        let mut next_stop = stop.clone();
        next_stop["eventId"] = json!(Uuid::new_v4());
        assert_eq!(
            store
                .dispatch_observed(
                    "org",
                    "account",
                    "install",
                    "follow.session.lifecycle",
                    &next_stop,
                    Some(&snapshot(&run, "running", false))
                )
                .unwrap()["decision"],
            "continue"
        );
    }

    #[test]
    fn active_native_follow_blocks_stop_when_observation_is_unavailable() {
        let t = tempfile::tempdir().unwrap();
        let store = FollowStore::open(t.path()).unwrap();
        let session = "hook-session-observation-unavailable";
        let run = Uuid::new_v4();
        let mut start = hook("UserPromptSubmit", session);
        start["continuation"] = runner_issued_continuation(&store, &run);
        store
            .dispatch(
                "org",
                "account",
                "install",
                "follow.session.lifecycle",
                &start,
            )
            .unwrap();

        let stop = hook("Stop", session);
        assert_eq!(
            store
                .dispatch_observed(
                    "org",
                    "account",
                    "install",
                    "follow.session.lifecycle",
                    &stop,
                    None,
                )
                .unwrap()["decision"],
            "continue"
        );
    }

    #[test]
    fn authenticated_snapshot_decision_table_requires_drain_handoff_or_terminal_receipt() {
        let run = Uuid::new_v4();
        let binding = Binding {
            host: "codex".into(),
            host_session: "session".into(),
            task: "unverified".into(),
            run: run.to_string(),
        };
        let event_page = json!({"execution":{"id":run,"status":"running"},"events":[{"sequence":3}],"latestSequence":4,"hasMoreEvents":true,"humanRequest":null});
        assert_eq!(
            signal_from_observation(&event_page, &binding, None).unwrap()["kind"],
            "event_page"
        );
        let request = Uuid::new_v4();
        let input = json!({"execution":{"id":run,"status":"waiting_for_human"},"events":[],"latestSequence":4,"hasMoreEvents":false,"humanRequest":{"id":request,"status":"pending","execution":{"id":run}}});
        assert_eq!(
            signal_from_observation(&input, &binding, None).unwrap()["kind"],
            "input"
        );
        assert_eq!(
            signal_from_observation(&snapshot(&run, "completed", false), &binding, None).unwrap()["kind"],
            "terminal"
        );
        assert_eq!(
            signal_from_observation(&snapshot(&run, "running", false), &binding, None).unwrap()["kind"],
            "active"
        );
    }

    #[test]
    fn late_callback_cannot_select_newest_run_without_exact_digest() {
        let t = tempfile::tempdir().unwrap();
        let store = FollowStore::open(t.path()).unwrap();
        let session = "shared-host-session";
        let first = Uuid::new_v4();
        let second = Uuid::new_v4();
        for run in [first, second] {
            let mut prompt = hook("UserPromptSubmit", session);
            prompt["continuation"] = runner_issued_continuation(&store, &run);
            store
                .dispatch(
                    "org",
                    "account",
                    "install",
                    "follow.session.lifecycle",
                    &prompt,
                )
                .unwrap();
        }
        let generic = hook("Stop", session);
        assert!(
            store
                .lifecycle_target("org", "account", "install", &generic)
                .unwrap()
                .is_none()
        );
        let mut late = hook("PostToolUse", session);
        late["tool"] = json!({"name":"mcp__loomex__loomex_run_wait","useId":"late-a","association":{"schemaVersion":"loomex.follow-session.tool-association/v1","runId":first,"request":{"runId":first},"response":{"runId":first}}});
        assert!(
            store
                .lifecycle_target("org", "account", "install", &late)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn unrelated_tool_interleaving_never_counts_as_follow_progress() {
        let run = Uuid::new_v4();
        let binding = Binding {
            host: "codex".into(),
            host_session: "s".into(),
            task: "unverified".into(),
            run: run.to_string(),
        };
        let unrelated = json!({"name":"mcp__other__read","useId":"u","association":{"schemaVersion":"loomex.follow-session.tool-association/v1","runId":run,"request":{"runId":run},"response":{"runId":run}}});
        assert!(tool_progress(&unrelated, &binding).is_none());

        let wrong_run = Uuid::new_v4();
        let loomex_wrong = json!({"name":"mcp__loomex__loomex_run_wait","useId":"u","association":{"schemaVersion":"loomex.follow-session.tool-association/v1","runId":wrong_run,"request":{"runId":wrong_run},"response":{"runId":wrong_run}}});
        assert!(tool_progress(&loomex_wrong, &binding).is_none());
    }

    #[test]
    fn interaction_association_uses_documented_request_only_shape() {
        let run = Uuid::new_v4();
        let request = Uuid::new_v4();
        let interaction = json!({
            "schemaVersion":"loomex.follow-session.tool-association/v1",
            "runId":run,
            "requestId":request,
            "request":{"requestId":request},
            "response":{"runId":run,"requestId":request}
        });
        assert!(valid_association(
            "mcp__loomex__loomex_interaction_get",
            &interaction
        ));

        let mut extra_request_run = interaction.clone();
        extra_request_run["request"]["runId"] = json!(run);
        assert!(!valid_association(
            "mcp__loomex__loomex_interaction_get",
            &extra_request_run
        ));

        let run_tool = json!({
            "schemaVersion":"loomex.follow-session.tool-association/v1",
            "runId":run,
            "request":{"runId":run},
            "response":{"runId":run}
        });
        assert!(valid_association("mcp__loomex__loomex_run_wait", &run_tool));
        let mut run_without_request_run = run_tool.clone();
        run_without_request_run["request"] = json!({"requestId":request});
        assert!(!valid_association(
            "mcp__loomex__loomex_run_wait",
            &run_without_request_run
        ));
    }

    #[test]
    fn handoff_and_terminal_require_matching_response_receipts() {
        let run = Uuid::new_v4();
        let request = Uuid::new_v4();
        let binding = Binding {
            host: "codex".into(),
            host_session: "s".into(),
            task: "unverified".into(),
            run: run.to_string(),
        };
        let pending = json!({"snapshot":{"execution":{"id":run,"status":"waiting_for_human"},"events":[],"latestSequence":0,"hasMoreEvents":false,"humanRequest":{"id":request,"status":"pending","execution":{"id":run}}}});
        let delivery = Uuid::new_v4().to_string();
        let wrong_request = Uuid::new_v4().to_string();
        let request_text = request.to_string();
        let wrong = signal_from_observation(
            &pending,
            &binding,
            Some(ToolReceipt {
                kind: "handoff",
                receipt: &delivery,
                association_request_id: Some(&wrong_request),
                request_request_id: Some(&wrong_request),
                response_request_id: Some(&wrong_request),
            }),
        );
        assert!(wrong.is_none());
        let delivered = signal_from_observation(
            &pending,
            &binding,
            Some(ToolReceipt {
                kind: "handoff",
                receipt: &delivery,
                association_request_id: Some(&request_text),
                request_request_id: Some(&request_text),
                response_request_id: Some(&request_text),
            }),
        );
        assert!(delivered.is_some());
        let result = json!({"snapshot":snapshot(&run, "completed", false),"terminalResult":{"execution":{"id":run,"status":"completed"}}});
        assert_eq!(
            signal_from_observation(&result, &binding, None).unwrap()["kind"],
            "terminal"
        );
    }

    #[test]
    fn interaction_handoff_requires_same_request_in_association_and_pending_snapshot() {
        let temp = tempfile::tempdir().unwrap();
        let store = FollowStore::open(temp.path()).unwrap();
        let run = Uuid::new_v4();
        let request = Uuid::new_v4();
        let mut start = hook("UserPromptSubmit", "session");
        start["continuation"] = runner_issued_continuation(&store, &run);
        store
            .dispatch(
                "org",
                "account",
                "install",
                "follow.session.lifecycle",
                &start,
            )
            .unwrap();
        let pending = json!({
            "execution":{"id":run,"status":"waiting_for_human"},
            "events":[],"latestSequence":0,"hasMoreEvents":false,
            "humanRequest":{"id":request,"status":"pending","execution":{"id":run}}
        });
        let mismatched = Uuid::new_v4();
        let mut wrong = hook("PostToolUse", "session");
        wrong["tool"] = json!({
            "name":"mcp__loomex__loomex_interaction_get","useId":"wrong",
            "association":{"schemaVersion":"loomex.follow-session.tool-association/v1","runId":run,
                "requestId":mismatched,
                "request":{"requestId":mismatched},
                "response":{"runId":run,"requestId":mismatched}}
        });
        assert_eq!(
            store
                .dispatch_observed(
                    "org",
                    "account",
                    "install",
                    "follow.session.lifecycle",
                    &wrong,
                    Some(&pending)
                )
                .unwrap()["decision"],
            "allow"
        );
        let binding = Binding {
            host: "codex".into(),
            host_session: "session".into(),
            task: "unverified".into(),
            run: run.to_string(),
        };
        assert_eq!(
            store
                .get(scope(), &json!({"binding":public_binding(&binding)}))
                .unwrap()["session"]["lifecycle"],
            "active"
        );

        let mut exact = hook("PostToolUse", "session");
        exact["tool"] = json!({
            "name":"mcp__loomex__loomex_interaction_view","useId":"exact",
            "association":{"schemaVersion":"loomex.follow-session.tool-association/v1","runId":run,
                "requestId":request,
                "request":{"requestId":request},
                "response":{"runId":run,"requestId":request}}
        });
        assert_eq!(
            store
                .dispatch_observed(
                    "org",
                    "account",
                    "install",
                    "follow.session.lifecycle",
                    &exact,
                    Some(&pending)
                )
                .unwrap()["decision"],
            "allow"
        );
        assert_eq!(
            store
                .get(scope(), &json!({"binding":public_binding(&binding)}))
                .unwrap()["session"]["lifecycle"],
            "input_pending"
        );
    }

    #[test]
    fn server_local_tool_names_remain_compatible_with_the_checked_association_contract() {
        assert_eq!(tool_kind("loomex_run_wait"), Some("wait"));
        assert_eq!(tool_kind("loomex_interaction_view"), Some("handoff"));
        assert_eq!(tool_kind("loomex_run_result"), Some("result_read"));
        assert_eq!(tool_kind("unrelated_tool"), None);
    }

    #[test]
    fn generated_continuation_requires_runner_minted_receipt() {
        let temp = tempfile::tempdir().unwrap();
        let store = FollowStore::open(temp.path()).unwrap();
        let run = Uuid::new_v4().to_string();
        let mut legacy = hook("UserPromptSubmit", "legacy-session");
        legacy["continuation"] = json!({"schemaVersion":"loomex.follow-session.continuation/v1","runId":run,"source":"bare_command"});
        assert_eq!(
            store
                .dispatch(
                    "org",
                    "account",
                    "install",
                    "follow.session.lifecycle",
                    &legacy
                )
                .unwrap_err()
                .to_string(),
            "INVALID_REQUEST"
        );
        let receipt = store
            .issue_continuation("org", "account", "install", &run, "run_commit", None)
            .unwrap();
        let mut accepted = hook("UserPromptSubmit", "session");
        accepted["continuation"] = json!({"schemaVersion":"loomex.follow-session.continuation/v1","runId":run,"source":"generated_markdown","receipt":receipt});
        assert_eq!(
            store
                .dispatch(
                    "org",
                    "account",
                    "install",
                    "follow.session.lifecycle",
                    &accepted
                )
                .unwrap()["decision"],
            "continue"
        );
        let mut wrong_run = hook("UserPromptSubmit", "wrong-run-session");
        wrong_run["continuation"] = json!({"schemaVersion":"loomex.follow-session.continuation/v1","runId":Uuid::new_v4(),"source":"generated_markdown","receipt":receipt});
        assert_eq!(
            store
                .dispatch(
                    "org",
                    "account",
                    "install",
                    "follow.session.lifecycle",
                    &wrong_run
                )
                .unwrap_err()
                .to_string(),
            "FOLLOW_RECEIPT_INVALID"
        );
        let mut forged = hook("UserPromptSubmit", "other-session");
        forged["continuation"] = json!({"schemaVersion":"loomex.follow-session.continuation/v1","runId":run,"source":"generated_markdown","receipt":"AAAAAAAAAAAAAAAAAAAAAA"});
        assert_eq!(
            store
                .dispatch(
                    "org",
                    "account",
                    "install",
                    "follow.session.lifecycle",
                    &forged
                )
                .unwrap_err()
                .to_string(),
            "FOLLOW_RECEIPT_INVALID"
        );
    }

    #[test]
    fn issued_continuation_recovers_only_the_exact_scoped_receipt() {
        let temp = tempfile::tempdir().unwrap();
        let store = FollowStore::open(temp.path()).unwrap();
        let run = Uuid::new_v4().to_string();
        let receipt = store
            .issue_continuation("org", "account", "install", &run, "run_commit", None)
            .unwrap();
        assert_eq!(
            store
                .issued_continuation("org", "account", "install", &run, "run_commit", None)
                .unwrap(),
            Some(receipt)
        );
        assert_eq!(
            store
                .issued_continuation("org", "other-account", "install", &run, "run_commit", None)
                .unwrap(),
            None
        );
        assert_eq!(
            store
                .issued_continuation(
                    "org",
                    "account",
                    "install",
                    &run,
                    "accepted_interaction",
                    None
                )
                .unwrap(),
            None
        );
    }
}
