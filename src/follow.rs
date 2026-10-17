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
    path::{Path, PathBuf},
    sync::Mutex,
};
use uuid::Uuid;

/// Follow state is execution evidence.  An active, blocked, suspended, or
/// handoff-pending session never expires automatically; only a terminal
/// session with its required result receipt gets the 30-day retirement window.
const RETENTION_SECONDS: u64 = 30 * 24 * 60 * 60;
const SCHEMA_VERSION: u64 = 2;
const MAX_JSON_BYTES: usize = 128 * 1024;
const MAX_MONITORING_RECORDS: usize = 32;
const MAX_HOOK_DIAGNOSTICS: usize = 8;

pub struct FollowStore {
    connection: Mutex<Connection>,
    directory: PathBuf,
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
          PRAGMA user_version = 2;")?;
        crate::continuation_resolution::initialize(&connection)?;
        connection.execute_batch("CREATE TABLE IF NOT EXISTS follow_lineage (
          organization_id TEXT NOT NULL, account_subject TEXT NOT NULL, installation_id TEXT NOT NULL,
          predecessor_id TEXT NOT NULL, predecessor_generation INTEGER NOT NULL,
          successor_id TEXT NOT NULL, successor_generation INTEGER NOT NULL,
          PRIMARY KEY(organization_id,account_subject,installation_id,predecessor_id,predecessor_generation));
          CREATE TABLE IF NOT EXISTS follow_generation_transitions (
          organization_id TEXT NOT NULL, account_subject TEXT NOT NULL, installation_id TEXT NOT NULL,
          follow_session_id TEXT NOT NULL, from_generation INTEGER NOT NULL,to_generation INTEGER NOT NULL,
          from_json BLOB NOT NULL,to_anchor_json BLOB NOT NULL,
          PRIMARY KEY(organization_id,account_subject,installation_id,follow_session_id,from_generation));
          CREATE TABLE IF NOT EXISTS follow_capability_bindings (follow_session_id TEXT NOT NULL, generation INTEGER NOT NULL, receipt TEXT NOT NULL, PRIMARY KEY(follow_session_id,generation,receipt));
          CREATE TABLE IF NOT EXISTS follow_retired_capabilities (
          organization_id TEXT NOT NULL, account_subject TEXT NOT NULL, installation_id TEXT NOT NULL,
          receipt TEXT NOT NULL, run_id TEXT NOT NULL, trigger TEXT NOT NULL, request_id TEXT,
          PRIMARY KEY(organization_id,account_subject,installation_id,receipt));")?;
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
            directory: dir.to_path_buf(),
        };
        {
            let c = store
                .connection
                .lock()
                .map_err(|_| anyhow::anyhow!("INTERNAL"))?;
            backfill_capability_bindings(&c)?;
        }
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
        {
            let c = self
                .connection
                .lock()
                .map_err(|_| anyhow::anyhow!("INTERNAL"))?;
            let retired: bool=c.query_row("SELECT EXISTS(SELECT 1 FROM follow_retired_capabilities WHERE organization_id=?1 AND account_subject=?2 AND installation_id=?3 AND run_id=?4 AND trigger=?5 AND request_id IS ?6)",params![org,account,installation,run,trigger,request_id],|r|r.get(0))?;
            ensure!(!retired, "CONTINUATION_RESOLVED");
        }
        self.presentation_eligible(org, account, run, trigger, request_id, None)?;
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
        if self
            .presentation_eligible(org, account, run, trigger, request_id, None)
            .is_err()
        {
            return Ok(None);
        }
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
                   AND request_id IS ?6 AND expires_at > ?7 AND NOT EXISTS(SELECT 1 FROM follow_retired_capabilities r WHERE r.receipt=follow_continuations.receipt AND r.organization_id=follow_continuations.organization_id AND r.account_subject=follow_continuations.account_subject AND r.installation_id=follow_continuations.installation_id)
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
        self.verify_continuation(
            Scope {
                organization: org,
                account,
                installation,
            },
            &Continuation {
                run: run.into(),
                receipt: receipt.into(),
            },
        )?;
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
            && existing["session"]["resolution"]["state"] == "unresolved"
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
                "continuationReceipt":receipt,
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
                        "anchor":{"kind":"explicit_follow","receiptId":idempotency_key},"continuationReceipt":continuation.receipt,
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
            if found["found"] == true
                && found["session"]["lifecycle"] == "active"
                && found["session"]["resolution"]["state"] == "unresolved"
                && found["session"]["continuationEligible"] == true
            {
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
        if let Some(existing) = &existing_native {
            crate::continuation_resolution::eligible(
                &tx,
                "follow_session",
                scope.organization,
                scope.account,
                scope.installation,
                existing["followSessionId"]
                    .as_str()
                    .context("INVALID_REQUEST")?,
            )?;
        }
        let mut statement = tx.prepare(
            "SELECT host_task_id FROM follow_sessions
             WHERE organization_id=?1 AND account_subject=?2 AND installation_id=?3
               AND host_id='codex-ui' AND host_session_id='unbound' AND run_id=?4
               AND lifecycle='handoff_pending' AND NOT EXISTS (SELECT 1 FROM continuation_resolutions r WHERE r.kind='follow_session' AND r.organization_id=follow_sessions.organization_id AND r.account_subject=follow_sessions.account_subject AND r.installation_id=follow_sessions.installation_id AND r.record_id=follow_sessions.follow_session_id)",
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
        if !self.session_presentation_eligible(scope, &pending_session)? {
            tx.commit()?;
            return Ok(None);
        }
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
            tx.execute(
                "INSERT INTO follow_generation_transitions VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
                params![
                    scope.organization,
                    scope.account,
                    scope.installation,
                    existing["followSessionId"].as_str(),
                    existing["generation"].as_u64(),
                    generation,
                    serde_json::to_vec(&existing)?,
                    serde_json::to_vec(&pending_session["anchor"])?
                ],
            )?;
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
               AND lifecycle='handoff_pending' AND NOT EXISTS (SELECT 1 FROM continuation_resolutions r WHERE r.kind='follow_session' AND r.organization_id=follow_sessions.organization_id AND r.account_subject=follow_sessions.account_subject AND r.installation_id=follow_sessions.installation_id AND r.record_id=follow_sessions.follow_session_id)",
            params![
                now, scope.organization, scope.account, scope.installation,
                pending.task, pending.run,
            ],
        )?;
        ensure!(changed == 1, "FOLLOW_SESSION_NOT_FOUND");
        let successor = find(&tx, scope, native)?.context("FOLLOW_SESSION_NOT_FOUND")?;
        tx.execute(
            "INSERT INTO follow_lineage VALUES(?1,?2,?3,?4,?5,?6,?7)",
            params![
                scope.organization,
                scope.account,
                scope.installation,
                pending_session["followSessionId"].as_str(),
                pending_session["generation"].as_u64(),
                successor["followSessionId"].as_str(),
                successor["generation"].as_u64()
            ],
        )?;
        tx.execute("INSERT OR IGNORE INTO follow_capability_bindings SELECT ?1,?2,receipt FROM follow_capability_bindings WHERE follow_session_id=?3 AND generation=?4",params![successor["followSessionId"].as_str(),successor["generation"].as_u64(),pending_session["followSessionId"].as_str(),pending_session["generation"].as_u64()])?;
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
            let b = Binding {
                host: "codex".into(),
                host_session: id.clone(),
                task: task.into(),
                run: rows[0].0.clone(),
            };
            let current = find(&connection, scope, &b)?.context("FOLLOW_SESSION_NOT_FOUND")?;
            if current["resolution"]["state"] != "unresolved"
                || !self.session_presentation_eligible(scope, &current)?
            {
                return Ok(None);
            }

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
            Some(mut session) => {
                session["continuationEligible"] = json!(
                    self.session_presentation_eligible(scope, &session)?
                        && session["resolution"]["state"] == "unresolved"
                );
                Ok(json!({"found": true, "session": session}))
            }
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
        if let Some(current) = find(&tx, scope, &binding)? {
            crate::continuation_resolution::eligible(
                &tx,
                "follow_session",
                scope.organization,
                scope.account,
                scope.installation,
                current["followSessionId"]
                    .as_str()
                    .context("INVALID_REQUEST")?,
            )?;
        }
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
        if let Some(receipt) = p["continuationReceipt"].as_str() {
            tx.execute(
                "INSERT OR IGNORE INTO follow_capability_bindings VALUES(?1,?2,?3)",
                params![
                    session["followSessionId"].as_str(),
                    session["generation"].as_u64(),
                    receipt
                ],
            )?;
        }
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
        if let Some(current) = find(&tx, scope, &binding)? {
            crate::continuation_resolution::eligible(
                &tx,
                "follow_session",
                scope.organization,
                scope.account,
                scope.installation,
                current["followSessionId"]
                    .as_str()
                    .context("INVALID_REQUEST")?,
            )?;
        }
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
        resolve_predecessors(&tx, &session)?;
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

    fn presentation_eligible(
        &self,
        org: &str,
        account: &str,
        run: &str,
        trigger: &str,
        request: Option<&str>,
        receipt: Option<&str>,
    ) -> Result<()> {
        let path = self.directory.join("presentation.sqlite3");
        if !path.exists() {
            return Ok(());
        }
        let metadata = fs::symlink_metadata(&path)?;
        ensure!(
            metadata.is_file()
                && !metadata.file_type().is_symlink()
                && metadata.uid() == unsafe { libc::geteuid() }
                && metadata.nlink() == 1
                && metadata.mode() & 0o077 == 0,
            "UNSAFE_STATE"
        );
        let c = Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        let identity = if trigger == "accepted_interaction" {
            format!(
                "follow:{run}:{}",
                request.context("FOLLOW_RECEIPT_INVALID")?
            )
        } else {
            format!("follow:{run}:run_started")
        };
        let exists:bool=c.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='presentation_deliveries')",[],|r|r.get(0))?;
        if !exists {
            return Ok(());
        }
        let row:Option<Vec<u8>>=c.query_row("SELECT continuation_json FROM presentation_deliveries WHERE organization_id=?1 AND account_subject=?2 AND identity=?3",params![org,account,identity],|r|r.get(0)).optional()?;
        if let Some(bytes) = row {
            let continuation: Value = serde_json::from_slice(&bytes)?;
            if receipt.is_none() || continuation["receipt"].as_str() == receipt {
                crate::continuation_resolution::eligible(
                    &c,
                    "presentation_delivery",
                    org,
                    account,
                    "",
                    &identity,
                )?;
            }
        }
        Ok(())
    }

    fn session_presentation_eligible(&self, scope: Scope<'_>, session: &Value) -> Result<bool> {
        let c = Connection::open_with_flags(
            self.directory.join("follow.sqlite3"),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )?;
        let mut stmt=c.prepare("SELECT receipt FROM follow_capability_bindings WHERE follow_session_id=?1 AND generation=?2")?;
        let receipts = stmt
            .query_map(
                params![
                    session["followSessionId"].as_str(),
                    session["generation"].as_u64()
                ],
                |r| r.get::<_, String>(0),
            )?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let path = self.directory.join("presentation.sqlite3");
        if !path.exists() {
            return Ok(true);
        }
        let metadata = fs::symlink_metadata(&path)?;
        ensure!(
            metadata.is_file()
                && !metadata.file_type().is_symlink()
                && metadata.uid() == unsafe { libc::geteuid() }
                && metadata.nlink() == 1
                && metadata.mode() & 0o077 == 0,
            "UNSAFE_STATE"
        );
        let p = Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        let exists:bool=p.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='presentation_deliveries')",[],|r|r.get(0))?;
        if !exists {
            return Ok(true);
        }
        let mut stmt=p.prepare("SELECT identity,continuation_json FROM presentation_deliveries WHERE organization_id=?1 AND account_subject=?2")?;
        let rows = stmt
            .query_map(params![scope.organization, scope.account], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let mut proven_lineage = !receipts.is_empty();
        let mut closed_scoped_run = false;
        for (identity, bytes) in rows {
            let continuation: Value = serde_json::from_slice(&bytes)?;
            let historic_exact = continuation["runId"] == session["runId"]
                && continuation["receipt"].as_str().is_some_and(|receipt| {
                    session["anchor"]["receiptId"] == capability_key(receipt)
                });
            let recorded_exact = receipts.iter().any(|r| continuation["receipt"] == *r);
            proven_lineage |= historic_exact;
            let closed = crate::continuation_resolution::projection(
                &p,
                "presentation_delivery",
                scope.organization,
                scope.account,
                "",
                &identity,
            )?["state"]
                != "unresolved";
            if (recorded_exact || historic_exact) && closed {
                return Ok(false);
            }
            closed_scoped_run |= closed
                && continuation["kind"] == "follow"
                && continuation["runId"] == session["runId"];
        }
        // An old direct native anchor identifies a host event rather than a
        // capability. A closed delivery for this scoped run cannot prove which
        // receipt it used, so preserve that uncertainty by denying automatic
        // continuation. A fresh explicit prompt records its own generation's
        // exact capability binding and can independently establish new intent.
        Ok(proven_lineage || !closed_scoped_run)
    }

    pub fn maintenance_candidates(&self) -> Result<Vec<Value>> {
        let c = self
            .connection
            .lock()
            .map_err(|_| anyhow::anyhow!("INTERNAL"))?;
        maintenance_follow_candidates(&c)
    }
    pub fn maintenance_retire(&self, request: &Value) -> Result<Value> {
        self.maintenance_close(
            request,
            "retired_by_owner",
            json!({"reasonCode":"OWNER_RETIRED_LOCAL_CONTINUATION"}),
        )
    }
    pub fn maintenance_reconcile(&self, request: &Value, observation: &Value) -> Result<Value> {
        let mut c = self
            .connection
            .lock()
            .map_err(|_| anyhow::anyhow!("INTERNAL"))?;
        let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let candidate = maintenance_follow_candidates(&tx)?
            .into_iter()
            .find(|v| {
                v["recordId"] == request["recordId"]
                    && v["organizationId"] == request["organizationId"]
                    && v["accountSubject"] == request["accountSubject"]
                    && v["installationId"] == request["installationId"]
            })
            .context("MANAGED_WORK_CHANGED")?;
        crate::continuation_resolution::matches(&candidate, request)?;
        if let Some(existing) = crate::continuation_resolution::replay(&tx, &candidate, request)? {
            tx.commit()?;
            return Ok(existing);
        }
        let fact = crate::continuation_resolution::observe(&tx, &candidate, observation)?;
        let result = if fact["terminal"] == true {
            let closed = crate::continuation_resolution::close(
                &tx,
                &candidate,
                request,
                "verified_terminal",
                json!({"runId":request["runId"],"observationDigest":fact["observationDigest"]}),
            )?;
            invalidate_capabilities(&tx, &candidate)?;
            closed
        } else {
            fact
        };
        tx.commit()?;
        Ok(result)
    }
    fn maintenance_close(&self, request: &Value, state: &str, evidence: Value) -> Result<Value> {
        let mut c = self
            .connection
            .lock()
            .map_err(|_| anyhow::anyhow!("INTERNAL"))?;
        let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let candidate = maintenance_follow_candidates(&tx)?
            .into_iter()
            .find(|v| {
                v["recordId"] == request["recordId"]
                    && v["organizationId"] == request["organizationId"]
                    && v["accountSubject"] == request["accountSubject"]
                    && v["installationId"] == request["installationId"]
            })
            .context("MANAGED_WORK_CHANGED")?;
        crate::continuation_resolution::matches(&candidate, request)?;
        let observed = crate::continuation_resolution::observation(&tx, &candidate)?;
        ensure!(
            observed["recordDigest"] == candidate["recordDigest"],
            "MANAGED_WORK_RECONCILIATION_REQUIRED"
        );
        let result =
            crate::continuation_resolution::close(&tx, &candidate, request, state, evidence)?;
        invalidate_capabilities(&tx, &candidate)?;
        tx.commit()?;
        Ok(result)
    }

    pub(crate) fn sweep(&self, at: u64) -> Result<()> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| anyhow::anyhow!("INTERNAL"))?;
        connection.execute(
            "DELETE FROM follow_sessions WHERE expires_at IS NOT NULL AND expires_at <= ?1 AND lifecycle='terminal' AND required_action='none' AND terminal_receipt_json IS NOT NULL AND follow_session_id NOT IN (SELECT record_id FROM continuation_resolutions) AND follow_session_id NOT IN (SELECT successor_id FROM follow_lineage)",
            params![at],
        )?;
        connection.execute(
            "DELETE FROM follow_receipts WHERE expires_at <= ?1",
            params![at],
        )?;
        connection.execute(
            "DELETE FROM follow_continuations WHERE expires_at <= ?1 AND NOT EXISTS(SELECT 1 FROM follow_capability_bindings b WHERE b.receipt=follow_continuations.receipt)",
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
            "SELECT 1 FROM follow_continuations WHERE receipt=?1 AND organization_id=?2 AND account_subject=?3 AND installation_id=?4 AND run_id=?5 AND expires_at>?6 AND NOT EXISTS(SELECT 1 FROM follow_retired_capabilities r WHERE r.receipt=follow_continuations.receipt AND r.organization_id=follow_continuations.organization_id AND r.account_subject=follow_continuations.account_subject AND r.installation_id=follow_continuations.installation_id)",
            params![receipt, scope.organization, scope.account, scope.installation, continuation.run, crate::state::now()], |_| Ok(()),
        ).optional()?;
        ensure!(found.is_some(), "FOLLOW_RECEIPT_INVALID");
        let (trigger,request):(String,Option<String>)=connection.query_row("SELECT trigger,request_id FROM follow_continuations WHERE receipt=?1 AND organization_id=?2 AND account_subject=?3 AND installation_id=?4",params![receipt,scope.organization,scope.account,scope.installation],|r|Ok((r.get(0)?,r.get(1)?)))?;
        drop(connection);
        self.presentation_eligible(
            scope.organization,
            scope.account,
            &continuation.run,
            &trigger,
            request.as_deref(),
            Some(receipt),
        )?;
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
    // Infrastructure loss is an actionable observation, not an active provider
    // or permission to replay. Keep existing event/input/terminal precedence.
    if snapshot.get("hasMoreEvents") == Some(&Value::Bool(false)) {
        let queue = &snapshot["queueObservation"];
        let timestamps = ["queuedAt", "observedAt"].map(|key| {
            queue[key].as_str().and_then(|value| {
                time::OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339)
                    .ok()
            })
        });
        if status == "queued"
            && snapshot.get("humanRequest").is_none_or(Value::is_null)
            && snapshot.get("agentRequest").is_none_or(Value::is_null)
            && snapshot.get("requiresAgentResponse") != Some(&Value::Bool(true))
            && snapshot
                .get("waitState")
                .is_none_or(|value| value.is_null() || value == "automated_progress")
            && snapshot
                .pointer("/progress/activeNodes")
                .and_then(Value::as_array)
                .is_none_or(Vec::is_empty)
            && queue["schemaVersion"] == "loomex.workflow-queue-observation/v1"
            && queue["executionId"] == binding.run
            && queue["state"] == "queued"
            && queue["workerState"] == "unavailable"
            && queue["code"] == "WORKFLOW_WORKER_UNAVAILABLE"
            && queue["waitSeconds"]
                .as_u64()
                .is_some_and(|value| value <= 9_007_199_254_740_991)
            && matches!(timestamps, [Some(queued), Some(observed)] if observed >= queued)
        {
            return Some(json!({"kind":"interrupted","code":"WORKFLOW_WORKER_UNAVAILABLE"}));
        }
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
fn capability_key(receipt: &str) -> String {
    let mut bytes: [u8; 16] = Sha256::digest(receipt.as_bytes())[..16].try_into().unwrap();
    bytes[6] = (bytes[6] & 0x0f) | 0x80;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes).to_string()
}
fn backfill_capability_bindings(c: &Connection) -> Result<()> {
    let mut stmt=c.prepare("SELECT s.follow_session_id,s.generation,s.anchor_digest,c.receipt FROM follow_sessions s JOIN follow_continuations c ON c.organization_id=s.organization_id AND c.account_subject=s.account_subject AND c.installation_id=s.installation_id AND c.run_id=s.run_id")?;
    let rows = stmt
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, u64>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    drop(stmt);
    for (id, generation, anchor, receipt) in rows {
        if serde_json::from_str::<Value>(&anchor)
            .ok()
            .is_some_and(|a| a["receiptId"] == capability_key(&receipt))
        {
            c.execute(
                "INSERT OR IGNORE INTO follow_capability_bindings VALUES(?1,?2,?3)",
                params![id, generation, receipt],
            )?;
        }
    }
    Ok(())
}
/// Exact identity metadata remains available after capability expiry, until local work is resolved.
pub fn maintenance_acceptance_capabilities(c: &Connection) -> Result<Vec<Value>> {
    let mut stmt=c.prepare("SELECT organization_id,account_subject,installation_id,run_id,receipt,trigger,request_id FROM follow_continuations")?;
    let rows = stmt
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, String>(5)?,
                r.get::<_, Option<String>>(6)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    rows.into_iter().map(|(org,account,install,run,receipt,trigger,request)|Ok(json!({"organizationId":org,"accountSubject":account,"installationId":install,"runId":run,"receipt":receipt,"trigger":trigger,"requestId":request,"resolved":maintenance_continuation_resolved(c,&org,&account,&install,&run,&receipt)?}))).collect()
}
/// Verify a monotonic, immutable chain of exact accepted-request generation transitions.
pub(crate) fn maintenance_generation_path(
    c: &Connection,
    successor: &Value,
    from: u64,
    to: u64,
) -> Result<bool> {
    if from == 0 {
        return Ok(false);
    }
    if from == to {
        return Ok(true);
    }
    if from > to || to - from > 4096 {
        return Ok(false);
    }
    let exists:bool=c.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='follow_generation_transitions')",[],|r|r.get(0))?;
    if !exists {
        return Ok(false);
    }
    for generation in from..to {
        let row:Option<(u64,Vec<u8>,Vec<u8>)>=c.query_row("SELECT to_generation,from_json,to_anchor_json FROM follow_generation_transitions WHERE organization_id=?1 AND account_subject=?2 AND installation_id=?3 AND follow_session_id=?4 AND from_generation=?5",params![successor["organizationId"].as_str(),successor["accountSubject"].as_str(),successor["installationId"].as_str(),successor["followSessionId"].as_str(),generation],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional()?;
        let Some((next, bytes, anchor)) = row else {
            return Ok(false);
        };
        let old: Value = serde_json::from_slice(&bytes)?;
        let anchor: Value = serde_json::from_slice(&anchor)?;
        if next != generation + 1
            || old["generation"] != generation
            || old["lifecycle"] != "input_pending"
            || old["requiredAction"] != "none"
            || old["pendingHandoffReceipt"]["generation"] != generation
            || old["pendingHandoffReceipt"]["requestId"] != anchor["requestId"]
            || anchor["kind"] != "accepted_interaction"
            || anchor["requestId"]
                .as_str()
                .and_then(|s| Uuid::parse_str(s).ok())
                .is_none()
        {
            return Ok(false);
        }
        let mut sources=c.prepare("SELECT p.anchor_digest FROM follow_lineage l JOIN follow_sessions p ON p.follow_session_id=l.predecessor_id AND p.generation=l.predecessor_generation AND p.organization_id=l.organization_id AND p.account_subject=l.account_subject AND p.installation_id=l.installation_id WHERE l.organization_id=?1 AND l.account_subject=?2 AND l.installation_id=?3 AND l.successor_id=?4 AND l.successor_generation=?5 AND p.run_id=?6")?;
        let anchors = sources
            .query_map(
                params![
                    successor["organizationId"].as_str(),
                    successor["accountSubject"].as_str(),
                    successor["installationId"].as_str(),
                    successor["followSessionId"].as_str(),
                    next,
                    successor["runId"].as_str()
                ],
                |r| r.get::<_, String>(0),
            )?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        if anchors
            .iter()
            .filter(|v| {
                serde_json::from_str::<Value>(v)
                    .ok()
                    .is_some_and(|v| v == anchor)
            })
            .count()
            != 1
        {
            return Ok(false);
        }
        for key in [
            "organizationId",
            "accountSubject",
            "installationId",
            "followSessionId",
            "runId",
        ] {
            if old[key] != successor[key] {
                return Ok(false);
            }
        }
    }
    Ok(true)
}

/// Canonical read-only projection for maintenance and uninstall snapshot assessment.
pub fn maintenance_follow_candidates(c: &Connection) -> Result<Vec<Value>> {
    let mut stmt=c.prepare("SELECT organization_id,account_subject,installation_id,host_id,host_session_id,host_task_id,run_id FROM follow_sessions ORDER BY follow_session_id")?;
    let rows = stmt
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, String>(5)?,
                r.get::<_, String>(6)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    rows.into_iter().map(|(org,account,install,host,host_session,task,run)| {
        let scope=Scope{organization:&org,account:&account,installation:&install};
        let mut full=find(c,scope,&Binding{host,host_session,task,run:run.clone()})?.context("FOLLOW_SESSION_NOT_FOUND")?;
        let resolution=full.as_object_mut().context("INVALID_REQUEST")?.remove("resolution").unwrap_or(json!({"state":"unresolved"}));
        let mut candidate=json!({"kind":"follow_session","organizationId":org,"accountSubject":account,"installationId":install,"recordId":full["followSessionId"],"runId":run,"revision":full["revision"],"generation":full["generation"],"attemptId":null,"lifecycle":full["lifecycle"],"recordDigest":crate::state::json_digest(&full),"resolution":resolution});
        candidate["backendObservation"]=crate::continuation_resolution::observation(c,&candidate)?;
        Ok(candidate)
    }).collect()
}
pub fn maintenance_resolved(c: &Connection, candidate: &Value) -> Result<bool> {
    crate::continuation_resolution::resolved(c, candidate)
}
pub fn maintenance_continuation_resolved(
    c: &Connection,
    org: &str,
    account: &str,
    install: &str,
    run: &str,
    receipt: &str,
) -> Result<bool> {
    let exists:bool=c.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='follow_retired_capabilities')",[],|r|r.get(0))?;
    if !exists {
        return Ok(false);
    }
    let retired:bool=c.query_row("SELECT EXISTS(SELECT 1 FROM follow_retired_capabilities r WHERE r.organization_id=?1 AND r.account_subject=?2 AND r.installation_id=?3 AND r.run_id=?4 AND r.receipt=?5 AND EXISTS(SELECT 1 FROM follow_continuations c WHERE c.organization_id=r.organization_id AND c.account_subject=r.account_subject AND c.installation_id=r.installation_id AND c.run_id=r.run_id AND c.receipt=r.receipt AND c.trigger=r.trigger AND c.request_id IS r.request_id))",params![org,account,install,run,receipt],|r|r.get(0))?;
    if !retired {
        return Ok(false);
    }
    for candidate in maintenance_follow_candidates(c)? {
        if candidate["organizationId"] != org
            || candidate["accountSubject"] != account
            || candidate["installationId"] != install
            || candidate["runId"] != run
            || !maintenance_resolved(c, &candidate)?
        {
            continue;
        }
        let bound:bool=c.query_row("SELECT EXISTS(SELECT 1 FROM follow_capability_bindings WHERE follow_session_id=?1 AND generation=?2 AND receipt=?3)",params![candidate["recordId"].as_str(),candidate["generation"].as_u64(),receipt],|r|r.get(0))?;
        if bound {
            return Ok(true);
        }
        // Only UI receipt-derived anchors carry historical exact capability proof.
        let anchor_text: String = c.query_row(
            "SELECT anchor_digest FROM follow_sessions WHERE follow_session_id=?1",
            params![candidate["recordId"].as_str()],
            |r| r.get(0),
        )?;
        let anchor: Value = serde_json::from_str(&anchor_text)?;
        let mut bytes: [u8; 16] = Sha256::digest(receipt.as_bytes())[..16].try_into().unwrap();
        bytes[6] = (bytes[6] & 0x0f) | 0x80;
        bytes[8] = (bytes[8] & 0x3f) | 0x80;
        if anchor["receiptId"] == Uuid::from_bytes(bytes).to_string() {
            return Ok(true);
        }
    }
    Ok(false)
}

fn invalidate_capabilities(c: &Connection, candidate: &Value) -> Result<()> {
    let org = candidate["organizationId"]
        .as_str()
        .context("INVALID_REQUEST")?;
    let account = candidate["accountSubject"]
        .as_str()
        .context("INVALID_REQUEST")?;
    let install = candidate["installationId"]
        .as_str()
        .context("INVALID_REQUEST")?;
    let anchor_text:String=c.query_row("SELECT anchor_digest FROM follow_sessions WHERE follow_session_id=?1 AND organization_id=?2 AND account_subject=?3 AND installation_id=?4",params![candidate["recordId"].as_str(),org,account,install],|r|r.get(0))?;
    let anchor: Value = serde_json::from_str(&anchor_text)?;
    let mut stmt=c.prepare("SELECT receipt,run_id,trigger,request_id FROM follow_continuations WHERE organization_id=?1 AND account_subject=?2 AND installation_id=?3 AND run_id=?4")?;
    let rows = stmt
        .query_map(
            params![org, account, install, candidate["runId"].as_str()],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, Option<String>>(3)?,
                ))
            },
        )?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    drop(stmt);
    for (receipt, run, trigger, request) in rows {
        let mut bytes: [u8; 16] = Sha256::digest(receipt.as_bytes())[..16].try_into().unwrap();
        bytes[6] = (bytes[6] & 0x0f) | 0x80;
        bytes[8] = (bytes[8] & 0x3f) | 0x80;
        let bound:bool=c.query_row("SELECT EXISTS(SELECT 1 FROM follow_capability_bindings WHERE follow_session_id=?1 AND generation=?2 AND receipt=?3)",params![candidate["recordId"].as_str(),candidate["generation"].as_u64(),receipt],|r|r.get(0))?;
        if bound || anchor["receiptId"] == Uuid::from_bytes(bytes).to_string() {
            c.execute(
                "INSERT OR IGNORE INTO follow_retired_capabilities VALUES(?1,?2,?3,?4,?5,?6,?7)",
                params![org, account, install, receipt, run, trigger, request],
            )?;
        }
    }
    Ok(())
}
fn resolve_predecessors(c: &Connection, successor: &Value) -> Result<()> {
    if successor["lifecycle"] != "terminal"
        || successor["requiredAction"] != "none"
        || successor["terminalReceipt"].is_null()
        || !successor["pendingHandoffReceipt"].is_null()
    {
        return Ok(());
    }
    let mut stmt=c.prepare("SELECT predecessor_id,predecessor_generation,successor_generation FROM follow_lineage WHERE organization_id=?1 AND account_subject=?2 AND installation_id=?3 AND successor_id=?4")?;
    let links = stmt
        .query_map(
            params![
                successor["organizationId"].as_str(),
                successor["accountSubject"].as_str(),
                successor["installationId"].as_str(),
                successor["followSessionId"].as_str()
            ],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, u64>(1)?,
                    r.get::<_, u64>(2)?,
                ))
            },
        )?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    drop(stmt);
    let candidates = maintenance_follow_candidates(c)?;
    for (id, generation, lineage_generation) in links {
        if !maintenance_generation_path(
            c,
            successor,
            lineage_generation,
            successor["generation"]
                .as_u64()
                .context("INVALID_REQUEST")?,
        )? {
            continue;
        }
        if let Some(candidate) = candidates.iter().find(|v| {
            v["recordId"] == id
                && v["generation"] == generation
                && v["lifecycle"] == "superseded"
                && v["resolution"]["state"] == "unresolved"
        }) {
            let mut request = candidate.clone();
            request["idempotencyKey"] = json!(Uuid::new_v4());
            crate::continuation_resolution::close(
                c,
                candidate,
                &request,
                "superseded_by_verified_successor",
                json!({"successorId":successor["followSessionId"],"successorGeneration":successor["generation"],"lineageSuccessorGeneration":lineage_generation,"terminalReceipt":successor["terminalReceipt"]}),
            )?;
            invalidate_capabilities(c, candidate)?;
        }
    }
    Ok(())
}

fn find(connection: &Connection, scope: Scope<'_>, b: &Binding) -> Result<Option<Value>> {
    let mut result: Option<Value> = connection.query_row("SELECT follow_session_id,anchor_digest,schema_version,generation,revision,mode,lifecycle,event_cursor,pending_handoff_json,terminal_receipt_json,recovery_json,cleanup_json,action_progress_json,required_action,missed_action_count,hook_count,last_error,created_at,updated_at,expires_at FROM follow_sessions WHERE organization_id=?1 AND account_subject=?2 AND installation_id=?3 AND host_id=?4 AND host_session_id=?5 AND host_task_id=?6 AND run_id=?7",params![scope.organization,scope.account,scope.installation,b.host,b.host_session,b.task,b.run],|r|{let action:Vec<u8>=r.get(12)?;Ok(json!({"followSessionId":r.get::<_,String>(0)?,"organizationId":scope.organization,"accountSubject":scope.account,"installationId":scope.installation,"hostId":b.host,"hostSessionId":b.host_session,"hostTaskId":b.task,"runId":b.run,"anchor":serde_json::from_str::<Value>(&r.get::<_,String>(1)?).unwrap_or(Value::Null),"schemaVersion":r.get::<_,u64>(2)?,"generation":r.get::<_,u64>(3)?,"revision":r.get::<_,u64>(4)?,"mode":r.get::<_,String>(5)?,"lifecycle":r.get::<_,String>(6)?,"eventCursor":r.get::<_,Option<u64>>(7)?,"pendingHandoffReceipt":opt_json(r.get(8)?)?,"terminalReceipt":opt_json(r.get(9)?)?,"recovery":opt_json(r.get(10)?)?,"cleanup":opt_json(r.get(11)?)?,"actionProgress":decode(&action)?,"requiredAction":r.get::<_,String>(13)?,"missedActionCount":r.get::<_,u64>(14)?,"hookCount":r.get::<_,u64>(15)?,"lastError":r.get::<_,Option<String>>(16)?,"createdAt":r.get::<_,u64>(17)?,"updatedAt":r.get::<_,u64>(18)?,"expiresAt":r.get::<_,Option<u64>>(19)?}))}).optional()?;
    if let Some(v) = result.as_mut() {
        v["resolution"] = crate::continuation_resolution::projection(
            connection,
            "follow_session",
            scope.organization,
            scope.account,
            scope.installation,
            v["followSessionId"].as_str().context("INVALID_REQUEST")?,
        )?;
    }
    Ok(result)
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
    fn maintenance_request(candidate: &Value) -> Value {
        let mut v = candidate.clone();
        v["idempotencyKey"] = json!(Uuid::new_v4());
        v
    }
    fn maintenance_observation(run: &str, status: &str) -> Value {
        json!({"snapshot":{"execution":{"id":run,"status":status},"hasMoreEvents":false},"terminalResult":{"execution":{"id":run,"status":status},"hasMoreEvents":false}})
    }

    #[test]
    fn legacy_direct_native_unknown_lineage_cannot_continue_retired_run_automatically() {
        let t = tempfile::tempdir().unwrap();
        let follow = FollowStore::open(t.path()).unwrap();
        let presentation = crate::presentation::PresentationStore::open(t.path()).unwrap();
        let run = Uuid::new_v4().to_string();
        let receipt = follow
            .issue_continuation("org", "account", "install", &run, "run_commit", None)
            .unwrap();
        let identity = format!("follow:{run}:run_started");
        presentation.register_delivery("org","account",&identity,&json!({"kind":"follow","schemaVersion":"loomex.follow-session.continuation/v1","runId":run,"receipt":receipt,"trigger":"run_commit","requestId":null})).unwrap();
        let mut start = hook("UserPromptSubmit", "legacy-direct");
        start["continuation"] = json!({"schemaVersion":"loomex.follow-session.continuation/v1","runId":run,"source":"generated_markdown","receipt":receipt});
        follow
            .dispatch(
                "org",
                "account",
                "install",
                "follow.session.lifecycle",
                &start,
            )
            .unwrap();
        let other = Uuid::new_v4();
        let mut unrelated = hook("UserPromptSubmit", "unrelated");
        unrelated["continuation"] = runner_issued_continuation(&follow, &other);
        follow
            .dispatch(
                "org",
                "account",
                "install",
                "follow.session.lifecycle",
                &unrelated,
            )
            .unwrap();
        {
            let c = follow.connection.lock().unwrap();
            c.execute("DELETE FROM follow_capability_bindings", [])
                .unwrap();
            c.execute(
                "DELETE FROM follow_continuations WHERE run_id=?1",
                params![run],
            )
            .unwrap();
            c.pragma_update(None, "user_version", 1).unwrap();
        }
        drop(follow);
        let candidate = presentation.maintenance_candidates().unwrap().remove(0);
        let request = maintenance_request(&candidate);
        presentation
            .maintenance_reconcile(&request, &maintenance_observation(&run, "running"))
            .unwrap();
        presentation.maintenance_retire(&request).unwrap();
        let migrated = FollowStore::open(t.path()).unwrap();
        assert!(
            migrated
                .lifecycle_target("org", "account", "install", &hook("Stop", "legacy-direct"))
                .unwrap()
                .is_none()
        );
        assert!(
            migrated
                .lifecycle_target("org", "account", "install", &hook("Stop", "unrelated"))
                .unwrap()
                .is_some()
        );
        let new_request = Uuid::new_v4().to_string();
        let fresh = migrated
            .issue_continuation(
                "org",
                "account",
                "install",
                &run,
                "accepted_interaction",
                Some(&new_request),
            )
            .unwrap();
        let mut explicit = hook("UserPromptSubmit", "legacy-direct");
        explicit["continuation"] = json!({"schemaVersion":"loomex.follow-session.continuation/v1","runId":run,"source":"generated_markdown","receipt":fresh});
        migrated
            .dispatch(
                "org",
                "account",
                "install",
                "follow.session.lifecycle",
                &explicit,
            )
            .unwrap();
        assert!(
            migrated
                .lifecycle_target("org", "account", "install", &hook("Stop", "legacy-direct"))
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn accepted_request_generation_chain_resolves_all_exact_predecessors() {
        let t = tempfile::tempdir().unwrap();
        let store = FollowStore::open(t.path()).unwrap();
        let run = Uuid::new_v4().to_string();
        let receipt = store
            .issue_continuation("org", "account", "install", &run, "run_commit", None)
            .unwrap();
        store
            .activate_ui_handoff("org", "account", "install", &run, &receipt, None)
            .unwrap();
        let native = Binding {
            host: "codex".into(),
            host_session: "native".into(),
            task: "unverified".into(),
            run: run.clone(),
        };
        let binding = public_binding(&native);
        store
            .promote_pending_ui_handoff(scope(), &native)
            .unwrap()
            .unwrap();
        for _ in 0..2 {
            let current =
                store.get(scope(), &json!({"binding":binding})).unwrap()["session"].clone();
            let request = Uuid::new_v4().to_string();
            decide(
                &store,
                &binding,
                &current,
                json!({"kind":"input","requestId":request,"receiptId":Uuid::new_v4()}),
                true,
                "handoff",
            );
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
            store
                .promote_pending_ui_handoff(scope(), &native)
                .unwrap()
                .unwrap();
        }
        let current = store.get(scope(), &json!({"binding":binding})).unwrap()["session"].clone();
        assert_eq!(current["generation"], 3);
        decide(
            &store,
            &binding,
            &current,
            json!({"kind":"terminal","receiptId":Uuid::new_v4()}),
            true,
            "result_read",
        );
        let candidates = store.maintenance_candidates().unwrap();
        let predecessors: Vec<_> = candidates
            .iter()
            .filter(|v| v["lifecycle"] == "superseded")
            .collect();
        assert_eq!(predecessors.len(), 3);
        {
            let c = store.connection.lock().unwrap();
            for candidate in &predecessors {
                assert!(maintenance_resolved(&c, candidate).unwrap());
            }
        }
        assert!(crate::uninstall_state::inventory_resolved_state(t.path()).is_ok());
        let first = predecessors
            .iter()
            .find(|v| v["resolution"]["evidence"]["lineageSuccessorGeneration"] == 1)
            .unwrap();
        let c = store.connection.lock().unwrap();
        let original: Vec<u8> = c
            .query_row(
                "SELECT to_anchor_json FROM follow_generation_transitions WHERE from_generation=1",
                [],
                |r| r.get(0),
            )
            .unwrap();
        let mut wrong: Value = serde_json::from_slice(&original).unwrap();
        wrong["requestId"] = json!(Uuid::new_v4());
        c.execute(
            "UPDATE follow_generation_transitions SET to_anchor_json=?1 WHERE from_generation=1",
            params![serde_json::to_vec(&wrong).unwrap()],
        )
        .unwrap();
        assert!(!maintenance_resolved(&c, first).unwrap());
        c.execute("UPDATE follow_generation_transitions SET to_anchor_json=?1,to_generation=3 WHERE from_generation=1",params![original]).unwrap();
        assert!(!maintenance_resolved(&c, first).unwrap());
        drop(c);
        assert!(crate::uninstall_state::inventory_resolved_state(t.path()).is_err());
    }

    #[test]
    fn legacy_promoted_anchor_denies_retired_presentation_without_binding_rows() {
        let t = tempfile::tempdir().unwrap();
        let follow = FollowStore::open(t.path()).unwrap();
        let presentation = crate::presentation::PresentationStore::open(t.path()).unwrap();
        let run = Uuid::new_v4().to_string();
        let receipt = follow
            .issue_continuation("org", "account", "install", &run, "run_commit", None)
            .unwrap();
        let identity = format!("follow:{run}:run_started");
        presentation.register_delivery("org","account",&identity,&json!({"kind":"follow","schemaVersion":"loomex.follow-session.continuation/v1","runId":run,"receipt":receipt,"trigger":"run_commit","requestId":null})).unwrap();
        follow
            .activate_ui_handoff("org", "account", "install", &run, &receipt, None)
            .unwrap();
        let native = Binding {
            host: "codex".into(),
            host_session: "native".into(),
            task: "unverified".into(),
            run: run.clone(),
        };
        follow
            .promote_pending_ui_handoff(scope(), &native)
            .unwrap()
            .unwrap();
        {
            let c = follow.connection.lock().unwrap();
            c.execute("DELETE FROM follow_capability_bindings", [])
                .unwrap();
            c.execute("DELETE FROM follow_continuations", []).unwrap();
            c.pragma_update(None, "user_version", 1).unwrap();
        }
        drop(follow);
        let candidate = presentation.maintenance_candidates().unwrap().remove(0);
        let request = maintenance_request(&candidate);
        presentation
            .maintenance_reconcile(&request, &maintenance_observation(&run, "running"))
            .unwrap();
        presentation.maintenance_retire(&request).unwrap();
        let migrated = FollowStore::open(t.path()).unwrap();
        assert!(
            migrated
                .lifecycle_target("org", "account", "install", &hook("Stop", "native"))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn expired_capability_identity_survives_sweep_before_retirement_and_fences_reissue() {
        let t = tempfile::tempdir().unwrap();
        let store = FollowStore::open(t.path()).unwrap();
        let run = Uuid::new_v4().to_string();
        let receipt = store
            .issue_continuation("org", "account", "install", &run, "run_commit", None)
            .unwrap();
        store
            .activate_ui_handoff("org", "account", "install", &run, &receipt, None)
            .unwrap();
        store
            .sweep(crate::state::now() + RETENTION_SECONDS + 1)
            .unwrap();
        let candidate = store.maintenance_candidates().unwrap().remove(0);
        let request = maintenance_request(&candidate);
        store
            .maintenance_reconcile(&request, &maintenance_observation(&run, "running"))
            .unwrap();
        store.maintenance_retire(&request).unwrap();
        assert_eq!(
            store
                .issue_continuation("org", "account", "install", &run, "run_commit", None)
                .unwrap_err()
                .to_string(),
            "CONTINUATION_RESOLVED"
        );
    }

    #[test]
    fn terminal_reconciliation_replay_preserves_original_observation_proof() {
        let t = tempfile::tempdir().unwrap();
        let store = FollowStore::open(t.path()).unwrap();
        let run = Uuid::new_v4().to_string();
        let receipt = store
            .issue_continuation("org", "account", "install", &run, "run_commit", None)
            .unwrap();
        store
            .activate_ui_handoff("org", "account", "install", &run, &receipt, None)
            .unwrap();
        let candidate = store.maintenance_candidates().unwrap().remove(0);
        let request = maintenance_request(&candidate);
        let first = maintenance_observation(&run, "completed");
        let closed = store.maintenance_reconcile(&request, &first).unwrap();
        let mut second = first.clone();
        second["snapshot"]["latestSequence"] = json!(123);
        assert_eq!(
            store.maintenance_reconcile(&request, &second).unwrap(),
            closed
        );
        let c = store.connection.lock().unwrap();
        assert!(maintenance_resolved(&c, &candidate).unwrap());
        drop(c);
        assert!(crate::uninstall_state::inventory_resolved_state(t.path()).is_ok());
    }

    #[test]
    fn retirement_of_one_exact_pending_handoff_does_not_guess_or_retire_its_peer() {
        let t = tempfile::tempdir().unwrap();
        let store = FollowStore::open(t.path()).unwrap();
        let run = Uuid::new_v4().to_string();
        let a = store
            .issue_continuation("org", "account", "install", &run, "run_commit", None)
            .unwrap();
        let b = store
            .issue_continuation("org", "account", "install", &run, "run_commit", None)
            .unwrap();
        for receipt in [&a, &b] {
            store
                .activate_ui_handoff("org", "account", "install", &run, receipt, None)
                .unwrap();
        }
        let native = Binding {
            host: "codex".into(),
            host_session: "session".into(),
            task: "unverified".into(),
            run: run.clone(),
        };
        assert!(
            store
                .promote_pending_ui_handoff(scope(), &native)
                .unwrap()
                .is_none()
        );
        let candidate = store
            .maintenance_candidates()
            .unwrap()
            .into_iter()
            .find(|v| {
                let c = store.connection.lock().unwrap();
                let anchor: String = c
                    .query_row(
                        "SELECT anchor_digest FROM follow_sessions WHERE follow_session_id=?1",
                        params![v["recordId"].as_str()],
                        |r| r.get(0),
                    )
                    .unwrap();
                serde_json::from_str::<Value>(&anchor).unwrap()["receiptId"] == receipt_key(&a)
            })
            .unwrap();
        let request = maintenance_request(&candidate);
        store
            .maintenance_reconcile(&request, &maintenance_observation(&run, "running"))
            .unwrap();
        store.maintenance_retire(&request).unwrap();
        assert!(
            store
                .promote_pending_ui_handoff(scope(), &native)
                .unwrap()
                .is_some()
        );
        assert!(
            store
                .verify_continuation(
                    scope(),
                    &Continuation {
                        run: run.clone(),
                        receipt: a
                    }
                )
                .is_err()
        );
        assert!(
            store
                .verify_continuation(scope(), &Continuation { run, receipt: b })
                .is_ok()
        );
    }

    #[test]
    fn presentation_retirement_fences_promoted_hook_even_after_capability_expiry() {
        let t = tempfile::tempdir().unwrap();
        let follow = FollowStore::open(t.path()).unwrap();
        let presentation = crate::presentation::PresentationStore::open(t.path()).unwrap();
        let run = Uuid::new_v4().to_string();
        let receipt = follow
            .issue_continuation("org", "account", "install", &run, "run_commit", None)
            .unwrap();
        let identity = format!("follow:{run}:run_started");
        let continuation = json!({"kind":"follow","schemaVersion":"loomex.follow-session.continuation/v1","runId":run,"receipt":receipt,"trigger":"run_commit","requestId":null});
        presentation
            .register_delivery("org", "account", &identity, &continuation)
            .unwrap();
        follow
            .activate_ui_handoff("org", "account", "install", &run, &receipt, None)
            .unwrap();
        let native = Binding {
            host: "codex".into(),
            host_session: "native".into(),
            task: "unverified".into(),
            run: run.clone(),
        };
        follow
            .promote_pending_ui_handoff(scope(), &native)
            .unwrap()
            .unwrap();
        let candidate = presentation.maintenance_candidates().unwrap().remove(0);
        let request = maintenance_request(&candidate);
        presentation
            .maintenance_reconcile(&request, &maintenance_observation(&run, "running"))
            .unwrap();
        presentation.maintenance_retire(&request).unwrap();
        assert!(
            follow
                .issue_continuation("org", "account", "install", &run, "run_commit", None)
                .is_err()
        );
        assert!(
            follow
                .verify_continuation(
                    scope(),
                    &Continuation {
                        run: run.clone(),
                        receipt: receipt.clone()
                    }
                )
                .is_err()
        );
        follow
            .sweep(crate::state::now() + RETENTION_SECONDS + 1)
            .unwrap();
        let stop = hook("Stop", "native");
        assert!(
            follow
                .lifecycle_target("org", "account", "install", &stop)
                .unwrap()
                .is_none()
        );
        let decision = follow
            .dispatch(
                "org",
                "account",
                "install",
                "follow.session.lifecycle",
                &stop,
            )
            .unwrap();
        assert_eq!(decision["decision"], "allow");
    }

    #[test]
    fn promoted_terminal_successor_resolves_only_proven_predecessor() {
        let t = tempfile::tempdir().unwrap();
        let store = FollowStore::open(t.path()).unwrap();
        let run = Uuid::new_v4().to_string();
        let receipt = store
            .issue_continuation("org", "account", "install", &run, "run_commit", None)
            .unwrap();
        store
            .activate_ui_handoff("org", "account", "install", &run, &receipt, None)
            .unwrap();
        let native = Binding {
            host: "codex".into(),
            host_session: "native".into(),
            task: "unverified".into(),
            run: run.clone(),
        };
        store
            .promote_pending_ui_handoff(scope(), &native)
            .unwrap()
            .unwrap();
        let before = store
            .get(scope(), &json!({"binding":public_binding(&native)}))
            .unwrap();
        let native_binding = public_binding(&native);
        decide(
            &store,
            &native_binding,
            &before["session"],
            json!({"kind":"terminal","receiptId":Uuid::new_v4()}),
            true,
            "result_read",
        );
        let candidates = store.maintenance_candidates().unwrap();
        let predecessor = candidates
            .iter()
            .find(|v| v["lifecycle"] == "superseded")
            .unwrap();
        let c = store.connection.lock().unwrap();
        assert!(maintenance_resolved(&c, predecessor).unwrap());
        assert!(
            maintenance_continuation_resolved(&c, "org", "account", "install", &run, &receipt)
                .unwrap()
        );
        assert_eq!(
            predecessor["resolution"]["state"],
            "superseded_by_verified_successor"
        );
        drop(c);
        assert!(crate::uninstall_state::inventory_resolved_state(t.path()).is_ok());
        let c = store.connection.lock().unwrap();
        c.execute("DELETE FROM follow_lineage", []).unwrap();
        assert!(!maintenance_resolved(&c, predecessor).unwrap());
    }

    #[test]
    fn retirement_is_exact_durable_and_invalidates_hooks_receipts_and_reissue() {
        let t = tempfile::tempdir().unwrap();
        let store = FollowStore::open(t.path()).unwrap();
        let run = Uuid::new_v4().to_string();
        let receipt = store
            .issue_continuation("org", "account", "install", &run, "run_commit", None)
            .unwrap();
        store
            .activate_ui_handoff("org", "account", "install", &run, &receipt, None)
            .unwrap();
        let candidate = store.maintenance_candidates().unwrap().remove(0);
        let request = maintenance_request(&candidate);
        assert_eq!(
            store.maintenance_retire(&request).unwrap_err().to_string(),
            "MANAGED_WORK_RECONCILIATION_REQUIRED"
        );
        store
            .maintenance_reconcile(
                &maintenance_request(&candidate),
                &maintenance_observation(&run, "running"),
            )
            .unwrap();
        let closed = store.maintenance_retire(&request).unwrap();
        assert_eq!(closed, store.maintenance_retire(&request).unwrap());
        assert!(
            store
                .activate_ui_handoff("org", "account", "install", &run, &receipt, None)
                .is_err()
        );
        assert!(
            store
                .issue_continuation("org", "account", "install", &run, "run_commit", None)
                .is_err()
        );
        assert!(
            store
                .issued_continuation("org", "account", "install", &run, "run_commit", None)
                .unwrap()
                .is_none()
        );
        let native = Binding {
            host: "codex".into(),
            host_session: "late".into(),
            task: "unverified".into(),
            run: run.clone(),
        };
        assert!(
            store
                .promote_pending_ui_handoff(scope(), &native)
                .unwrap()
                .is_none()
        );
        store
            .sweep(crate::state::now() + RETENTION_SECONDS + 1)
            .unwrap();
        let c = store.connection.lock().unwrap();
        assert!(maintenance_resolved(&c, &candidate).unwrap());
        drop(c);
        drop(store);
        let store = FollowStore::open(t.path()).unwrap();
        assert_eq!(
            store.maintenance_candidates().unwrap()[0]["lifecycle"],
            "handoff_pending"
        );
        assert!(
            store
                .issue_continuation("org", "account", "install", &run, "run_commit", None)
                .is_err()
        );
    }

    #[test]
    fn historical_unknown_lineage_expiry_and_stale_preview_do_not_resolve() {
        let t = tempfile::tempdir().unwrap();
        let store = FollowStore::open(t.path()).unwrap();
        let b = binding();
        let activated = activate(&store, &b, 0);
        let candidate = store.maintenance_candidates().unwrap().remove(0);
        let request = maintenance_request(&candidate);
        let run = b["runId"].as_str().unwrap();
        store
            .maintenance_reconcile(
                &maintenance_request(&candidate),
                &maintenance_observation(run, "running"),
            )
            .unwrap();
        let c = store.connection.lock().unwrap();
        c.execute(
            "UPDATE follow_sessions SET lifecycle='superseded',revision=revision+1",
            [],
        )
        .unwrap();
        drop(c);
        assert_eq!(
            store.maintenance_retire(&request).unwrap_err().to_string(),
            "MANAGED_WORK_CHANGED"
        );
        store
            .sweep(crate::state::now() + RETENTION_SECONDS * 2)
            .unwrap();
        let now = store.maintenance_candidates().unwrap().remove(0);
        let c = store.connection.lock().unwrap();
        assert!(!maintenance_resolved(&c, &now).unwrap());
        assert_eq!(activated["generation"], 1);
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
        let mut queued = snapshot(&run, "queued", false);
        queued["queueObservation"] = json!({"schemaVersion":"loomex.workflow-queue-observation/v1",
            "executionId":run,"state":"queued","workerState":"unavailable",
            "code":"WORKFLOW_WORKER_UNAVAILABLE","waitSeconds":31,
            "queuedAt":"2026-10-16T12:00:00.123456+00:00","observedAt":"2026-10-16T12:00:31.123456+00:00"});
        let lost = signal_from_observation(&queued, &binding, None).unwrap();
        assert_eq!(lost["kind"], "interrupted");
        assert_eq!(decision_for(&lost, "none")["decision"], "suspend");
        queued["hasMoreEvents"] = json!(true);
        queued["events"] = json!([{"sequence":1}]);
        queued["latestSequence"] = json!(2);
        assert_eq!(
            signal_from_observation(&queued, &binding, None).unwrap()["kind"],
            "event_page"
        );
        queued["hasMoreEvents"] = json!(false);
        queued["queueObservation"]["executionId"] = json!(Uuid::new_v4());
        assert_eq!(
            signal_from_observation(&queued, &binding, None).unwrap()["kind"],
            "active"
        );
        queued["queueObservation"]["executionId"] = json!(run);
        for (field, value) in [
            ("requiresAgentResponse", json!(true)),
            ("agentRequest", json!({"id":Uuid::new_v4()})),
            ("waitState", json!("agent_response_required")),
            ("progress", json!({"activeNodes":[{"id":"running"}]})),
        ] {
            let mut other = queued.clone();
            other[field] = value;
            assert_eq!(
                signal_from_observation(&other, &binding, None).unwrap()["kind"],
                "active"
            );
        }
        queued["queueObservation"]["observedAt"] = json!("2026-10-15T12:00:31.123456+00:00");
        assert_eq!(
            signal_from_observation(&queued, &binding, None).unwrap()["kind"],
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
