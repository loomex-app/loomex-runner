//! Fenced durable workers. Interrupted execution is reported indeterminate, never replayed.
#[cfg(test)]
use crate::control::provider_snapshot;
use crate::{
    control::{Daemon, find_executable},
    executor::{self, ExecutionObserver, ExecutionRequest, ProcessIdentity},
    state,
};
use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::STANDARD};
use reqwest::{Client, Method, redirect::Policy};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    future::Future,
    io::Read,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::time::Instant as TokioInstant;
use url::Url;
use uuid::Uuid;

pub mod supervisor;
use supervisor::Quiescence;
pub use supervisor::run;
use supervisor::{ActiveJob, ExecutionScope};
#[cfg(test)]
use supervisor::{admit, session};
mod journal;
pub(crate) use journal::blocking_io;
use journal::*;
mod authorization;
use authorization::*;
mod provider;
use provider::*;
pub mod persona_memory;
pub mod public_status;
use public_status::*;
mod http;
use http::*;
mod execution;
use execution::*;
mod transfer;
use transfer::*;
mod delivery;
use delivery::*;
mod recovery;
use recovery::*;

fn runner_manifest_with_memory(memory: bool) -> Value {
    json!({"version":env!("CARGO_PKG_VERSION"),"executionPolicies":["host_user/v1"],"jobKinds":["shell.exec","command.run","http.request"],"capabilities":{"shell.exec":true,"command.run":true,"http.request":true,"ai.public-status/v1":LIVE_PROVIDER_QUALIFIED,"ai.persona-memory/v1":memory,"codex.native-projected-json/v3":true,"execution.workspace-set/v1":true},"httpResultContracts":[HTTP_RESULT_SCHEMA],"concurrency":null,"executionSeconds":null,"outputBytes":null,"artifactBytes":null})
}
async fn runner_manifest(daemon: &Daemon) -> Result<Value> {
    Ok(runner_manifest_with_memory(
        persona_memory::provider_supported(daemon, "codex").await?,
    ))
}
async fn apply_cancellations(daemon: &Daemon, response: &Value) {
    if let Some(jobs) = response["cancellations"].as_array() {
        for job in jobs {
            if let Some(id) = job["id"].as_str() {
                daemon.execution.cancel(id).await;
            }
        }
    }
}
fn fence(j: &Journal) -> Value {
    json!({"sessionId":j.session,"leaseVersion":j.job["leaseVersion"]})
}

fn job_authority_unchanged(
    expected: &Journal,
    journal: &Arc<Mutex<Journal>>,
    require_live_lease: bool,
) -> bool {
    let Ok(current) = journal.lock() else {
        return false;
    };
    let lease_until = current.job["leasedUntilEpochMs"].as_u64().unwrap_or(0);
    expected.organization == current.organization
        && expected.session == current.session
        && expected.recovery_session == current.recovery_session
        && expected.phase == current.phase
        && expected.terminal_key == current.terminal_key
        && expected.job["id"] == current.job["id"]
        && expected.job["runnerId"] == current.job["runnerId"]
        && expected.job["connectionGeneration"] == current.job["connectionGeneration"]
        && expected.job["leaseVersion"] == current.job["leaseVersion"]
        && expected.job["payloadDigest"] == current.job["payloadDigest"]
        && lease_until == expected.job["leasedUntilEpochMs"].as_u64().unwrap_or(0)
        && (!require_live_lease || lease_until > now_millis())
}

async fn backend_job(
    daemon: &Daemon,
    journal: &Arc<Mutex<Journal>>,
    expected: &Journal,
    method: &str,
    route: &str,
    body: Option<Value>,
    key: Option<&str>,
) -> Result<Value> {
    let credential = daemon.auth.credential(&expected.organization).await?;
    if expected.job["runnerId"]
        .as_str()
        .is_some_and(|id| id != credential.subject)
    {
        bail!("RUNNER_JOB_RUNNER_MISMATCH");
    }
    Ok(daemon
        .api
        .request_job_with_stale_proof_retry(method, route, body, &credential, key, || {
            job_authority_unchanged(expected, journal, true)
        })
        .await?)
}

async fn initial_finalization(
    daemon: &Daemon,
    path: &Path,
    journal: &Arc<Mutex<Journal>>,
) -> Result<()> {
    let outcome = match drain_events(daemon, path, journal).await {
        Ok(()) => materialize_terminal(daemon, path, journal)
            .await
            .map_err(|error| (DeliveryDiagnosticCategory::ArtifactFinalization, error)),
        Err(error) => Err((DeliveryDiagnosticCategory::OutputDelivery, error)),
    };
    if let Err((category, error)) = outcome {
        let diagnostic = delivery_diagnostic(category, &error);
        update(daemon, path, journal, move |record| {
            if record.first_failure_diagnostic.is_none() {
                record.first_failure_diagnostic = Some(diagnostic);
            }
            Ok(())
        })
        .await?;
        return Err(error);
    }
    Ok(())
}
async fn work(
    daemon: Arc<Daemon>,
    path: PathBuf,
    journal: Journal,
    cancel: Arc<AtomicBool>,
    scope: Arc<ExecutionScope>,
) -> Result<()> {
    let shared = Arc::new(Mutex::new(journal));
    let result = execute_job(daemon.clone(), &path, shared.clone(), cancel, scope.clone()).await;
    scope.stop().await;
    if let Err(error) = result {
        let finalization_category = {
            let j = shared.lock().map_err(|_| anyhow::anyhow!("journal lock"))?;
            if j.phase == JournalPhase::Exited && j.result.is_some() {
                j.first_failure_diagnostic.as_ref().map(|d| d.category)
            } else {
                None
            }
        };
        if let Some(category) = finalization_category {
            // `execute_job` already attempted this exact finalization. Preserve
            // its first error and do not blindly issue the same nonretryable
            // artifact request a second time.
            handle_finalization_error(&daemon, &path, &shared, category, error).await?;
            return deliver(daemon, &path, shared).await;
        }
        let typed_http_failure = error
            .downcast_ref::<HttpFailure>()
            .map(|failure| (failure.code, failure.stage, failure.dispatched));
        update(&daemon, &path, &shared, move |j| {
        if j.error.is_none() && j.result.is_none() {
            j.result = None;
            let code = if error
                .to_string()
                .bytes()
                .all(|b| b.is_ascii_uppercase() || b == b'_')
            {
                error.to_string()
            } else {
                "EXECUTION_INDETERMINATE".into()
            };
            j.error = Some(
                if let Some((code, stage, dispatched)) = typed_http_failure {
                    json!({
                        "code": code,
                        "message": "HTTP request did not reach a confirmed terminal response",
                        "indeterminate": dispatched,
                        "stage": stage,
                        "dispatchState": if dispatched { "indeterminate" } else { "known_not_dispatched" },
                    })
                } else if j.job["kind"] == "http.request" {
                    json!({
                        "code": code,
                        "message": "HTTP request was rejected before dispatch",
                        "indeterminate": false,
                        "stage": "validate",
                        "dispatchState": "known_not_dispatched",
                    })
                } else {
                    json!({"code":code,"message":"Local execution could not be confirmed","indeterminate":j.identity.is_some() || code == "HTTP_REQUEST_INDETERMINATE"})
                },
            );
            j.transition(JournalPhase::TerminalPending)?;
        }
        Ok(())
        }).await?;
    }
    deliver(daemon, &path, shared).await
}
#[cfg(test)]
mod tests;

#[cfg(test)]
mod protocol_tests;

pub async fn purge_deleted_jobs(daemon: &Daemon) -> Result<()> {
    let root = daemon.dir.join("jobs");
    if !root.exists() {
        return Ok(());
    }
    for entry in std::fs::read_dir(root)? {
        let path = entry?.path().join("journal.json");
        if !path.exists() {
            continue;
        };
        let journal: Journal = state::read_json(&path)?;
        if crate::retention::deleted(&daemon.dir, &journal.job) {
            let id = journal.job["id"].as_str().unwrap_or("");
            if !daemon.execution.cancel(id).await {
                crate::retention::purge_job(&path)?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod authorization_tests;
