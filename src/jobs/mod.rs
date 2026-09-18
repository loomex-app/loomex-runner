//! Fenced durable workers. Interrupted execution is reported indeterminate, never replayed.
use crate::{
    control::{Daemon, find_executable, provider_snapshot},
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
use journal::*;
mod authorization;
use authorization::*;
mod provider;
use provider::*;
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

fn runner_manifest() -> Value {
    json!({"version":env!("CARGO_PKG_VERSION"),"executionPolicies":["host_user/v1"],"jobKinds":["shell.exec","command.run","http.request"],"capabilities":{"shell.exec":true,"command.run":true,"http.request":true},"httpResultContracts":[HTTP_RESULT_SCHEMA],"concurrency":null,"executionSeconds":null,"outputBytes":null,"artifactBytes":null})
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
        let typed_http_failure = error
            .downcast_ref::<HttpFailure>()
            .map(|failure| (failure.code, failure.stage, failure.dispatched));
        let mut j = shared.lock().map_err(|_| anyhow::anyhow!("journal lock"))?;
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
            persist(&path, &j)?;
        }
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
