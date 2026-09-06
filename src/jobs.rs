//! Fenced durable workers. Interrupted execution is reported indeterminate, never replayed.
use crate::{
    control::{Daemon, find_executable, provider_snapshot},
    executor::{self, ExecutionObserver, ExecutionRequest, ProcessIdentity},
    state,
};
use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    io::Read,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use uuid::Uuid;

struct ActiveJob(Arc<Daemon>);
impl ActiveJob {
    fn new(daemon: Arc<Daemon>) -> Self {
        daemon.managed.fetch_add(1, Ordering::SeqCst);
        daemon.active.fetch_add(1, Ordering::SeqCst);
        Self(daemon)
    }
}
impl Drop for ActiveJob {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::SeqCst);
        self.0.managed.fetch_sub(1, Ordering::SeqCst);
    }
}

struct Quiescence(Arc<Daemon>);
impl Quiescence {
    fn new(daemon: Arc<Daemon>) -> Self {
        daemon.managed.fetch_add(1, Ordering::SeqCst);
        daemon.quiescence.fetch_add(1, Ordering::SeqCst);
        Self(daemon)
    }
}
impl Drop for Quiescence {
    fn drop(&mut self) {
        self.0.quiescence.fetch_sub(1, Ordering::SeqCst);
        self.0.managed.fetch_sub(1, Ordering::SeqCst);
    }
}
fn admit(daemon: &Arc<Daemon>) -> Result<Option<Quiescence>> {
    let _lock = daemon
        .admission
        .lock()
        .map_err(|_| anyhow::anyhow!("INTERNAL"))?;
    if daemon.draining.load(Ordering::SeqCst) {
        return Ok(None);
    }

    Ok(Some(Quiescence::new(daemon.clone())))
}
#[derive(Default)]
struct ExecutionScope {
    finished: Arc<AtomicBool>,
    tasks: Mutex<Vec<tokio::task::JoinHandle<()>>>,
}
impl ExecutionScope {
    fn register(&self, task: tokio::task::JoinHandle<()>) {
        self.tasks.lock().unwrap().push(task);
    }
    async fn stop(&self) {
        self.finished.store(true, Ordering::SeqCst);
        let tasks = std::mem::take(&mut *self.tasks.lock().unwrap());
        for task in &tasks {
            task.abort();
        }
        for task in tasks {
            let _ = task.await;
        }
    }
}
impl Drop for ExecutionScope {
    fn drop(&mut self) {
        self.finished.store(true, Ordering::SeqCst);
        for task in self.tasks.get_mut().unwrap() {
            task.abort();
        }
    }
}
struct OwnedTask(tokio::task::JoinHandle<()>);
impl Drop for OwnedTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}
struct OwnedWork(tokio::task::JoinHandle<Result<()>>);
impl Drop for OwnedWork {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Journal {
    job: Value,
    organization: String,
    session: String,
    #[serde(default)]
    recovery_session: Option<String>,
    phase: String,
    identity: Option<ProcessIdentity>,
    result: Option<Value>,
    error: Option<Value>,
    terminal_key: String,
    started_at: u64,
    #[serde(default)]
    acknowledged_at: Option<u64>,
    #[serde(skip)]
    event_sender: Arc<tokio::sync::Mutex<()>>,
    #[serde(default)]
    stdout_pending: Option<usize>,
    #[serde(default)]
    stderr_pending: Option<usize>,
    stdout_offset: u64,
    stderr_offset: u64,
}
struct Observer {
    path: PathBuf,
    journal: Arc<Mutex<Journal>>,
}
impl ExecutionObserver for Observer {
    fn before_spawn(&self, _: &ExecutionRequest) -> Result<()> {
        let mut j = self
            .journal
            .lock()
            .map_err(|_| anyhow::anyhow!("journal lock"))?;
        j.phase = "spawn_intent".into();
        state::write_json(&self.path, &*j)
    }
    fn spawned(&self, identity: &ProcessIdentity) -> Result<()> {
        let mut j = self
            .journal
            .lock()
            .map_err(|_| anyhow::anyhow!("journal lock"))?;
        j.identity = Some(identity.clone());
        j.phase = "running".into();
        state::write_json(&self.path, &*j)
    }
}
fn snapshot(j: &Arc<Mutex<Journal>>) -> Result<Journal> {
    Ok(j.lock()
        .map_err(|_| anyhow::anyhow!("journal lock"))?
        .clone())
}
fn save(j: &Arc<Mutex<Journal>>, path: &Path) -> Result<()> {
    let record = j.lock().map_err(|_| anyhow::anyhow!("journal lock"))?;
    state::write_json(path, &*record)
}
pub async fn run(daemon: Arc<Daemon>) {
    let mut last_sweep = 0;
    let mut running = HashSet::new();
    let mut tasks = tokio::task::JoinSet::new();
    let mut task_organizations = HashMap::new();
    loop {
        if state::now().saturating_sub(last_sweep) >= 3600 {
            if let Ok(Some(_admission)) = admit(&daemon) {
                let _ = crate::retention::sweep(&daemon.dir, state::now());
                last_sweep = state::now();
            }
        }
        while let Some(result) = tasks.try_join_next_with_id() {
            match result {
                Ok((id, org)) => {
                    running.remove(&org);
                    task_organizations.remove(&id);
                }
                Err(error) => {
                    if let Some(org) = task_organizations.remove(&error.id()) {
                        running.remove(&org);
                    }
                }
            }
        }
        if !daemon.draining.load(Ordering::SeqCst) {
            if let Ok(orgs) = daemon.auth.enrolled_organizations().await {
                for org in orgs {
                    if running.insert(org.clone()) {
                        let d = daemon.clone();
                        let task_org = org.clone();
                        let handle = tasks.spawn(async move {
                            let _ = session(d, org.clone()).await;
                            org
                        });
                        task_organizations.insert(handle.id(), task_org);
                    }
                }
            }
        }
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }
}
async fn session(daemon: Arc<Daemon>, org: String) -> Result<()> {
    let Some(_session_admission) = admit(&daemon)? else {
        return Ok(());
    };
    let manifest = json!({"version":env!("CARGO_PKG_VERSION"),"executionPolicies":["host_user/v1"],"jobKinds":["shell.exec","command.run"],"capabilities":{"shell.exec":true,"command.run":true},"concurrency":null,"executionSeconds":null,"outputBytes":null,"artifactBytes":null});
    let response = daemon
        .backend(
            &org,
            "POST",
            "v1/sessions/",
            Some(json!({"transport":"long_poll","manifest":manifest})),
            None,
        )
        .await?;
    let sid = response["session"]["id"]
        .as_str()
        .context("BACKEND_PROTOCOL_ERROR")?
        .to_string();
    recover(daemon.clone(), &org, &sid).await?;
    let d = daemon.clone();
    let heartbeat_org = org.clone();
    let heartbeat_sid = sid.clone();
    let stop = Arc::new(AtomicBool::new(false));
    let heartbeat_stop = stop.clone();

    let heartbeat_active = Quiescence::new(daemon.clone());
    let heartbeat = OwnedTask(tokio::spawn(async move {
        let _active = heartbeat_active;
        while !heartbeat_stop.load(Ordering::SeqCst) {
            tokio::time::sleep(std::time::Duration::from_secs(15)).await;
            if let Ok(response) = d
                .backend(
                    &heartbeat_org,
                    "POST",
                    &format!("v1/sessions/{heartbeat_sid}/heartbeat/"),
                    Some(json!({"manifest":manifest})),
                    None,
                )
                .await
            {
                apply_cancellations(&d, &response).await;
            }
        }
    }));
    let mut workers = tokio::task::JoinSet::new();
    let result: Result<()> = async {
        while !daemon.draining.load(Ordering::SeqCst) {
            let Some(_lease_admission)=admit(&daemon)? else{break};
            while workers.try_join_next().is_some() {}
            let response = daemon
                .backend(
                    &org,
                    "POST",
                    "v1/jobs/lease/",
                    Some(json!({"sessionId":sid,"waitSeconds":20})),
                    None,
                )
                .await?;
            if let Some(job) = response.get("job").filter(|v| !v.is_null()) {
                let job = job.clone();
                let id = job["id"]
                    .as_str()
                    .context("BACKEND_PROTOCOL_ERROR")?
                    .to_string();
                Uuid::parse_str(&id)?;
                let path = daemon.dir.join("jobs").join(&id).join("journal.json");
                if path.exists() {
                    // A server retry never authorizes duplicate local spawn.
                    continue;
                }
                let journal = Journal {
                    job,
                    organization: org.clone(),
                    session: sid.clone(),
                    recovery_session: None,
                    phase: "leased".into(),
                    identity: None,
                    result: None,
                    error: None,
                    terminal_key: Uuid::new_v4().to_string(),
                    started_at: state::now(),
                    acknowledged_at: None,
                    event_sender:Default::default(),
                    stdout_pending: None,
                    stderr_pending: None,
                    stdout_offset: 0,
                    stderr_offset: 0,
                };
                state::write_json(&path, &journal)?;
                let cancellation = Arc::new(AtomicBool::new(false));
                daemon
                    .cancellations
                    .lock()
                    .await
                    .insert(id.clone(), cancellation.clone());

                let d = daemon.clone();
                let active = ActiveJob::new(d.clone());
                workers.spawn(async move {
                    let _active = active;
                    let scope = Arc::new(ExecutionScope::default());
                    let worker_scope = scope.clone();
                    let worker_daemon = d.clone();
                    let worker_path = path.clone();

                    let work_active=Quiescence::new(d.clone());
                    let mut worker = OwnedWork(tokio::spawn(async move {
                        let _active=work_active;
                        work(worker_daemon, worker_path, journal, cancellation, worker_scope).await
                    }));
                    let outcome = (&mut worker.0).await;
                    // Even on panic, join every helper before writing a terminal record.
                    scope.stop().await;
                    if outcome.is_err() {
                        if let Ok(mut record) = state::read_json::<Journal>(&path) {
                            record.phase = "terminal_pending".into();
                            record.result = None;
                            record.error = Some(json!({"code":"JOB_TASK_PANICKED","message":"Local task stopped without a confirmed outcome","indeterminate":true}));
                            if state::write_json(&path, &record).is_ok() {
                                let _ = deliver(d.clone(), &path, Arc::new(Mutex::new(record))).await;
                            }
                        }
                    }
                    d.cancellations.lock().await.remove(&id);
                });
            }
        }
        Ok(())
    }
    .await;
    while workers.join_next().await.is_some() {}
    stop.store(true, Ordering::SeqCst);
    heartbeat.0.abort();
    let _ = daemon
        .backend(
            &org,
            "POST",
            &format!("v1/sessions/{sid}/disconnect/"),
            Some(json!({"reason":"daemon drained"})),
            None,
        )
        .await;
    result
}
async fn apply_cancellations(daemon: &Daemon, response: &Value) {
    if let Some(jobs) = response["cancellations"].as_array() {
        let tokens = daemon.cancellations.lock().await;
        for job in jobs {
            if let Some(token) = job["id"].as_str().and_then(|id| tokens.get(id)) {
                token.store(true, Ordering::SeqCst)
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
    let result = execute_job(daemon.clone(), &path, shared.clone(), cancel, scope).await;
    if let Err(error) = result {
        let mut j = shared.lock().map_err(|_| anyhow::anyhow!("journal lock"))?;
        if j.error.is_none()
            && (j.result.is_none() || error.downcast_ref::<crate::api::ApiError>().is_none())
        {
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
                json!({"code":code,"message":"Local execution could not be confirmed","indeterminate":j.identity.is_some()}),
            );
            j.phase = "terminal_pending".into();
            state::write_json(&path, &*j)?;
        }
    }
    deliver(daemon, &path, shared).await
}
async fn require_execution_authorization(daemon: &Daemon, journal: &Journal) -> Result<PathBuf> {
    let payload = &journal.job["payload"];
    let preparation = payload["preparationId"]
        .as_str()
        .context("LOCAL_EXECUTION_AUTHORIZATION_REQUIRED")?;
    Uuid::parse_str(preparation)
        .map_err(|_| anyhow::anyhow!("LOCAL_EXECUTION_AUTHORIZATION_REQUIRED"))?;
    let record: Value = state::read_json(
        &daemon
            .dir
            .join("preparations")
            .join(format!("{preparation}.json")),
    )
    .map_err(|_| anyhow::anyhow!("LOCAL_EXECUTION_AUTHORIZATION_REQUIRED"))?;
    let binding = &record["binding"];
    if record["commitAuthorization"]["preparationId"] != preparation
        || record["commitAuthorization"]["bindingDigest"] != payload["bindingDigest"]
        || record["bindingDigest"] != payload["bindingDigest"]
        || payload["bindingDigest"]
            .as_str()
            .is_none_or(|s| s.is_empty())
        || record["organizationId"] != journal.organization
        || record["installationId"] != daemon.auth.installation_id().await?
        || record["workspacePath"] != payload["workspacePath"]
        || binding["executionPolicy"] != "host_user/v1"
        || payload["executionPolicy"] != "host_user/v1"
        || !payload["providerConfiguration"].is_object()
        || payload["providerConfiguration"] != binding["providerConfiguration"]
    {
        bail!("LOCAL_EXECUTION_AUTHORIZATION_REQUIRED")
    }
    if record["providers"] != provider_snapshot()? {
        bail!("PROVIDER_CONFIGURATION_CHANGED")
    }
    daemon
        .granted(
            Path::new(
                payload["workspacePath"]
                    .as_str()
                    .context("WORKSPACE_DENIED")?,
            ),
            &journal.organization,
        )
        .await
}
fn verify_payload_digest(job: &Value) -> Result<()> {
    let mut stable_payload = job["payload"]
        .as_object()
        .cloned()
        .context("BACKEND_PROTOCOL_ERROR")?;
    // The backend hashes the producer payload before adding this volatile
    // top-level lease metadata. All other fields, including workspace/cwd,
    // remain part of the stable payload digest.
    stable_payload.remove("authorizationEnvelope");
    if state::json_digest(&Value::Object(stable_payload))
        != job["payloadDigest"].as_str().unwrap_or("")
    {
        bail!("PAYLOAD_DIGEST_MISMATCH")
    }
    Ok(())
}

async fn execute_job(
    daemon: Arc<Daemon>,
    path: &Path,
    journal: Arc<Mutex<Journal>>,
    cancel: Arc<AtomicBool>,
    scope: Arc<ExecutionScope>,
) -> Result<()> {
    if daemon.draining.load(Ordering::SeqCst) {
        bail!("DAEMON_DRAINING")
    }
    let current = snapshot(&journal)?;
    let job = &current.job;
    let id = job["id"].as_str().context("BACKEND_PROTOCOL_ERROR")?;
    let payload = &job["payload"];
    if payload["executionPolicy"] != "host_user/v1" {
        bail!("UNSUPPORTED_EXECUTION_POLICY")
    }
    if !["shell.exec", "command.run"].contains(&job["kind"].as_str().unwrap_or("")) {
        bail!("UNSUPPORTED_JOB_KIND")
    }
    verify_payload_digest(job)?;
    let workspace = require_execution_authorization(&daemon, &current).await?;
    let mut argv: Vec<String> = if let Some(items) = payload["command"].as_array() {
        items
            .iter()
            .map(|v| v.as_str().map(String::from).context("INVALID_COMMAND"))
            .collect::<Result<_>>()?
    } else {
        bail!("INVALID_COMMAND")
    };
    if argv.is_empty() {
        bail!("INVALID_COMMAND")
    };
    if let Some(provider) = payload["provider"].as_str() {
        let input = payload["providerInput"]
            .as_str()
            .context("PROVIDER_INPUT_MISSING")?;
        if payload["providerInputDigest"] != state::digest(input.as_bytes()) {
            bail!("PROVIDER_INPUT_DIGEST_MISMATCH")
        }
        let exact = match provider {
            "codex" => argv.last().is_some_and(|arg| arg == input),
            "claude" | "gemini" => argv
                .windows(2)
                .any(|args| args[0] == "-p" && args[1] == input),
            _ => false,
        };
        if !exact {
            bail!("PROVIDER_INPUT_ARGV_MISMATCH")
        }
    }

    argv[0] = find_executable(&argv[0])
        .context("PROVIDER_UNAVAILABLE")?
        .to_string_lossy()
        .into_owned();
    let output_dir = path.parent().context("journal parent")?.to_path_buf();
    if let Some(schema) = payload.get("providerOutputSchema") {
        if !schema.is_object()
            || payload["providerOutputSchemaDigest"] != state::json_digest(schema)
        {
            bail!("PROVIDER_SCHEMA_INVALID")
        }
        let schema_path = output_dir.join("provider-schema.json");
        state::write_json(&schema_path, schema)?;
        let mut replaced = 0;
        for arg in &mut argv {
            if arg == "{loomex:provider-schema}" {
                *arg = schema_path.to_string_lossy().into_owned();
                replaced += 1
            }
        }
        if payload["provider"] == "codex" && replaced != 1 {
            bail!("PROVIDER_SCHEMA_INVALID")
        }
    }
    let requested_env: BTreeMap<String, String> = match payload["env"].as_object() {
        Some(map) => map
            .iter()
            .map(|(k, v)| Ok((k.clone(), v.as_str().context("INVALID_COMMAND_ENV")?.into())))
            .collect::<Result<_>>()?,
        None => BTreeMap::new(),
    };
    let mut env = BTreeMap::new();
    for name in ["HOME", "USER", "LOGNAME", "TMPDIR", "LANG", "LC_ALL"] {
        if let Ok(value) = std::env::var(name) {
            env.insert(name.into(), value);
        }
    }
    let base_path = std::env::var("PATH").unwrap_or_default();
    env.insert(
        "PATH".into(),
        format!("{base_path}:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin"),
    );
    env.extend(requested_env);
    let mut j = snapshot(&journal)?;
    j.phase = "start_pending".into();
    {
        *journal.lock().unwrap() = j.clone();
    }
    save(&journal, path)?;
    let started = daemon
        .backend(
            &j.organization,
            "POST",
            &format!("v1/jobs/{id}/start/"),
            Some(fence(&j)),
            None,
        )
        .await?;
    {
        let mut locked = journal.lock().unwrap();
        locked.job = started["job"].clone();
        locked.phase = "started".into();
    }
    save(&journal, path)?;
    let observer = Arc::new(Observer {
        path: path.to_owned(),
        journal: journal.clone(),
    });
    let request = ExecutionRequest {
        job_id: id.into(),
        workspace,
        cwd: payload["cwd"].as_str().map(PathBuf::from),
        argv,
        env,
        output_dir: output_dir.clone(),
        policy: "host_user/v1".into(),
        observer,
    };
    let finished = scope.finished.clone();
    let tick_finished = finished.clone();
    let d = daemon.clone();
    let jr = journal.clone();
    let jp = path.to_owned();
    let token = cancel.clone();

    let tick_active = Quiescence::new(daemon.clone());
    let tick = tokio::spawn(async move {
        let _active = tick_active;
        while !tick_finished.load(Ordering::SeqCst) {
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            if tick_finished.load(Ordering::SeqCst) {
                break;
            };
            let Ok(j) = snapshot(&jr) else { break };
            let id = j.job["id"].as_str().unwrap_or("");
            match d
                .backend(
                    &j.organization,
                    "POST",
                    &format!("v1/jobs/{id}/renew/"),
                    Some(fence(&j)),
                    None,
                )
                .await
            {
                Ok(response) => {
                    if response["job"]["status"] == "canceling" {
                        token.store(true, Ordering::SeqCst)
                    }
                    if let Ok(mut locked) = jr.lock() {
                        locked.job = response["job"].clone();
                        let _ = state::write_json(&jp, &*locked);
                    }
                }
                Err(_) => {
                    let expires = j.job["leasedUntilEpochMs"].as_u64().unwrap_or(0) / 1000;
                    if state::now() >= expires {
                        token.store(true, Ordering::SeqCst);
                    }
                }
            }
            let _ = stream_events(&d, &jp, &jr).await;
        }
    });
    scope.register(tick);
    let authority_journal = journal.clone();
    let authority_cancel = cancel.clone();
    let authority_finished = finished.clone();

    let authority_active = Quiescence::new(daemon.clone());
    let authority_watch = tokio::spawn(async move {
        let _active = authority_active;
        while !authority_finished.load(Ordering::SeqCst) {
            if let Ok(j) = snapshot(&authority_journal) {
                let expiry = j.job["leasedUntilEpochMs"].as_u64().unwrap_or(0);
                let now_ms = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u64;
                if expiry == 0 || now_ms >= expiry {
                    authority_cancel.store(true, Ordering::SeqCst);
                    break;
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        }
    });
    scope.register(authority_watch);
    let outcome = executor::execute(request, cancel).await;
    let terminal: Result<()> = async {
        let outcome = outcome?;
        if outcome.error.is_some() {
            bail!("EXECUTION_INDETERMINATE");
        }
        {
            let mut record = journal.lock().unwrap();
            record.phase = "exited".into();
            record.result = Some(json!({
                "exitCode": outcome.exit_code,
                "durationSeconds": state::now().saturating_sub(record.started_at),
                "timedOut": false,
                "cancelled": outcome.canceled,
                "truncated": false,
                "indeterminate": outcome.indeterminate,
                "managedGroupStopped": outcome.managed_group_stopped,
                "descendantCleanup": outcome.descendant_cleanup,
                "stdoutPath": outcome.stdout_path,
                "stderrPath": outcome.stderr_path
            }));
            state::write_json(path, &*record)?;
        }
        drain_events(&daemon, path, &journal).await?;
        materialize_terminal(&daemon, path, &journal).await
    }
    .await;
    scope.stop().await;
    terminal
}
async fn stream_events(
    daemon: &Daemon,
    path: &Path,
    journal: &Arc<Mutex<Journal>>,
) -> Result<bool> {
    let sender = snapshot(journal)?.event_sender;
    let _sending = sender.lock().await;
    let mut sent = false;
    for stream in ["stdout", "stderr"] {
        let j = snapshot(journal)?;
        let offset = if stream == "stdout" {
            j.stdout_offset
        } else {
            j.stderr_offset
        };
        let mut file = match tokio::fs::File::open(path.parent().unwrap().join(stream)).await {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        file.seek(std::io::SeekFrom::Start(offset)).await?;
        let pending = if stream == "stdout" {
            j.stdout_pending
        } else {
            j.stderr_pending
        };
        let mut bytes = vec![0; pending.unwrap_or(32768)];
        let size = if let Some(size) = pending {
            file.read_exact(&mut bytes).await?;
            size
        } else {
            file.read(&mut bytes).await?
        };
        if size == 0 {
            continue;
        }
        bytes.truncate(size);
        if pending.is_none() {
            let mut locked = journal.lock().unwrap();
            if stream == "stdout" {
                locked.stdout_pending = Some(size)
            } else {
                locked.stderr_pending = Some(size)
            }
            state::write_json(path, &*locked)?;
        }
        let mut body = fence(&j);
        body["events"] = json!([{"eventType":"output","stream":stream,"message":"","payload":{"encoding":"base64","data":STANDARD.encode(&bytes),"offset":offset,"chunkId":format!("{stream}:{offset}")}}]);
        daemon
            .backend(
                &j.organization,
                "POST",
                &format!("v1/jobs/{}/events/", j.job["id"].as_str().unwrap()),
                Some(body),
                None,
            )
            .await?;
        let mut locked = journal.lock().unwrap();
        if stream == "stdout" {
            locked.stdout_pending = None;
            locked.stdout_offset = offset + size as u64
        } else {
            locked.stderr_pending = None;
            locked.stderr_offset = offset + size as u64
        }
        state::write_json(path, &*locked)?;
        sent = true;
    }
    Ok(sent)
}
async fn drain_events(daemon: &Daemon, path: &Path, journal: &Arc<Mutex<Journal>>) -> Result<()> {
    while stream_events(daemon, path, journal).await? {}
    Ok(())
}
async fn materialize_terminal(
    daemon: &Daemon,
    path: &Path,
    journal: &Arc<Mutex<Journal>>,
) -> Result<()> {
    let j = snapshot(journal)?;
    if crate::retention::deleted(&daemon.dir, &j.job) {
        bail!("RUN_DELETED")
    }
    let Some(mut result) = j.result.clone() else {
        return Ok(());
    };
    if j.phase == "terminal_pending" {
        return Ok(());
    }
    for stream in ["stdout", "stderr"] {
        let local = PathBuf::from(
            result[format!("{stream}Path")]
                .as_str()
                .context("SPOOL_MISSING")?,
        );
        let artifact = upload(
            daemon,
            &j,
            &local,
            &format!("{}-{stream}.log", j.job["id"].as_str().unwrap()),
            "application/octet-stream",
            &format!("stream-{stream}"),
        )
        .await?;
        result[format!("{stream}ArtifactId")] = artifact["artifactId"].clone();
        result
            .as_object_mut()
            .unwrap()
            .remove(&format!("{stream}Path"));
    }
    let expected = j.job["payload"]["expectedExitCodes"]
        .as_array()
        .cloned()
        .unwrap_or_else(|| vec![json!(0)]);
    if expected.contains(&result["exitCode"]) && result["cancelled"] != true {
        let mut artifacts = Vec::new();
        if let Some(declarations) = j.job["payload"]["artifactOutputs"].as_array() {
            let workspace = daemon
                .granted(
                    Path::new(
                        j.job["payload"]["workspacePath"]
                            .as_str()
                            .context("WORKSPACE_DENIED")?,
                    ),
                    &j.organization,
                )
                .await?;
            for (index, item) in declarations.iter().enumerate() {
                let relative = Path::new(
                    item["path"]
                        .as_str()
                        .context("ARTIFACT_DECLARATION_INVALID")?,
                );
                if relative.is_absolute()
                    || relative
                        .components()
                        .any(|c| !matches!(c, std::path::Component::Normal(_)))
                {
                    bail!("ARTIFACT_DECLARATION_INVALID")
                }
                let resolved = std::fs::canonicalize(workspace.join(relative))
                    .map_err(|_| anyhow::anyhow!("DECLARED_ARTIFACT_MISSING"))?;
                if !resolved.starts_with(&workspace) || !std::fs::metadata(&resolved)?.is_file() {
                    bail!("ARTIFACT_PATH_DENIED")
                }
                let name = item["name"]
                    .as_str()
                    .context("ARTIFACT_DECLARATION_INVALID")?;
                let mime = item["contentType"]
                    .as_str()
                    .unwrap_or("application/octet-stream");
                let mut artifact = upload(
                    daemon,
                    &j,
                    &resolved,
                    name,
                    mime,
                    &format!("declared-{index}"),
                )
                .await?;
                artifact["path"] = json!(relative);
                artifacts.push(artifact);
            }
        }
        result["artifacts"] = json!(artifacts);
    }
    let mut locked = journal.lock().unwrap();
    locked.result = Some(result);
    locked.phase = "terminal_pending".into();
    state::write_json(path, &*locked)?;
    Ok(())
}
async fn upload(
    daemon: &Daemon,
    j: &Journal,
    path: &Path,
    name: &str,
    content_type: &str,
    tag: &str,
) -> Result<Value> {
    use sha2::{Digest, Sha256};
    let mut file = std::fs::File::open(path)?;
    let size = file.metadata()?.len();
    let mut hasher = Sha256::new();
    let mut buf = vec![0; 262144];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let hash = hex::encode(hasher.finalize());
    let id = j.job["id"].as_str().context("BACKEND_PROTOCOL_ERROR")?;
    let key = format!("job-{id}-{tag}");
    let body = json!({"executionId":j.job["createdByExecutionId"],"nodeExecutionId":j.job["createdByNodeExecutionId"],"jobId":id,"name":name,"contentType":content_type,"sizeBytes":size,"checksumSha256":hash,"idempotencyKey":key});
    let response = daemon
        .backend(
            &j.organization,
            "POST",
            "v2/artifact-transfers/",
            Some(body),
            Some(&key),
        )
        .await?;
    let transfer = response["transferId"]
        .as_str()
        .context("BACKEND_PROTOCOL_ERROR")?;
    let mut offset = response["offset"]
        .as_u64()
        .context("BACKEND_PROTOCOL_ERROR")?;
    let mut input = tokio::fs::File::open(path).await?;
    input.seek(std::io::SeekFrom::Start(offset)).await?;
    while offset < size {
        if crate::retention::deleted(&daemon.dir, &j.job) {
            bail!("RUN_DELETED")
        }
        let n = input.read(&mut buf).await?;
        if n == 0 {
            bail!("SPOOL_CHANGED")
        };
        let response = daemon
            .backend(
                &j.organization,
                "PUT",
                &format!("v2/artifact-transfers/{transfer}/"),
                Some(json!({"offset":offset,"dataBase64":STANDARD.encode(&buf[..n])})),
                None,
            )
            .await?;
        let next = response["offset"]
            .as_u64()
            .context("BACKEND_PROTOCOL_ERROR")?;
        if next != offset + n as u64 {
            bail!("BACKEND_PROTOCOL_ERROR")
        };
        offset = next;
    }
    let response = daemon
        .backend(
            &j.organization,
            "POST",
            &format!("v2/artifact-transfers/{transfer}/complete/"),
            Some(json!({})),
            None,
        )
        .await?;
    Ok(
        json!({"artifactId":response["artifactId"].as_str().context("BACKEND_PROTOCOL_ERROR")?,"name":name,"contentType":content_type,"sizeBytes":size,"checksumSha256":hash}),
    )
}
fn delivery_blocked(code: &str) -> bool {
    [
        "AUTH_REQUIRED",
        "AUTH_EXPIRED",
        "LOGOUT_PENDING",
        "AUTHORIZATION_FAILED",
    ]
    .contains(&code)
        || code.ends_with("_NOT_FOUND")
        || code.ends_with("_TOKEN_INVALID")
}
fn fence_error(code: &str) -> bool {
    [
        "RUNNER_JOB_NOT_FOUND",
        "RUNNER_SESSION_NOT_FOUND",
        "RUNNER_JOB_LEASE_EXPIRED",
        "RUNNER_JOB_LEASE_CONFLICT",
        "RUNNER_JOB_LEASE_INVALID",
    ]
    .contains(&code)
}
async fn reclaim_terminal(
    daemon: &Daemon,
    path: &Path,
    journal: &Arc<Mutex<Journal>>,
) -> Result<()> {
    let j = snapshot(journal)?;
    let id = j.job["id"].as_str().context("BACKEND_PROTOCOL_ERROR")?;
    let session = j.recovery_session.as_ref().unwrap_or(&j.session);
    let response = daemon.backend(&j.organization, "POST", &format!("v1/jobs/{id}/reclaim/"),
        Some(json!({"sessionId":session,"expectedLeaseVersion":j.job["leaseVersion"],"payloadDigest":j.job["payloadDigest"],"terminalSubmission":true,"idempotencyKey":j.terminal_key})), Some(&j.terminal_key)).await?;
    {
        let mut record = journal.lock().unwrap();
        record.job = response["job"].clone();
        record.session = session.clone();
        record.recovery_session = None;
    }
    save(journal, path)
}
async fn retry_delivery(
    daemon: &Daemon,
    path: &Path,
    journal: &Arc<Mutex<Journal>>,
    error: anyhow::Error,
) -> Result<()> {
    let code = error.to_string();
    if fence_error(&code) {
        if let Err(reclaim_error) = reclaim_terminal(daemon, path, journal).await {
            let reclaim_code = reclaim_error.to_string();
            if delivery_blocked(&reclaim_code)
                || [
                    "RUNNER_JOB_NOT_RECLAIMABLE",
                    "RUNNER_JOB_PAYLOAD_MISMATCH",
                    "RUNNER_JOB_IDEMPOTENCY_MISMATCH",
                ]
                .contains(&reclaim_code.as_str())
            {
                journal.lock().unwrap().phase = "delivery_blocked".into();
                save(journal, path)?;
                return Err(reclaim_error);
            }
        }
    } else if delivery_blocked(&code)
        || !error
            .downcast_ref::<crate::api::ApiError>()
            .is_some_and(|e| e.retryable)
    {
        journal.lock().unwrap().phase = "delivery_blocked".into();
        save(journal, path)?;
        return Err(error);
    }
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    Ok(())
}
async fn deliver(daemon: Arc<Daemon>, path: &Path, journal: Arc<Mutex<Journal>>) -> Result<()> {
    loop {
        let mut j = snapshot(&journal)?;
        if crate::retention::deleted(&daemon.dir, &j.job) {
            crate::retention::purge_job(path)?;
            return Ok(());
        }
        if j.phase == "exited" {
            match async {
                drain_events(&daemon, path, &journal).await?;
                materialize_terminal(&daemon, path, &journal).await
            }
            .await
            {
                Ok(()) => j = snapshot(&journal)?,
                Err(error) => {
                    let code = error.to_string();
                    if fence_error(&code)
                        || delivery_blocked(&code)
                        || error
                            .downcast_ref::<crate::api::ApiError>()
                            .is_some_and(|e| e.retryable)
                    {
                        retry_delivery(&daemon, path, &journal, error).await?;
                        continue;
                    }
                    {
                        let mut record = journal.lock().unwrap();
                        record.phase = "terminal_pending".into();
                        record.result = None;
                        record.error = Some(
                            json!({"code":"ARTIFACT_FINALIZATION_FAILED","message":"Declared output could not be registered"}),
                        );
                    }
                    save(&journal, path)?;
                    j = snapshot(&journal)?;
                }
            }
        }
        let id = j.job["id"].as_str().context("BACKEND_PROTOCOL_ERROR")?;
        let failed = j.error.is_some();
        let mut body = fence(&j);
        body["idempotencyKey"] = json!(j.terminal_key);
        if failed {
            body["error"] = j.error.clone().unwrap()
        } else {
            body["result"] = j.result.clone().context("TERMINAL_MISSING")?
        };
        match daemon
            .backend(
                &j.organization,
                "POST",
                &format!("v1/jobs/{id}/{}/", if failed { "fail" } else { "complete" }),
                Some(body),
                Some(&j.terminal_key),
            )
            .await
        {
            Ok(_) => {
                {
                    let mut locked = journal.lock().unwrap();
                    locked.phase = "acknowledged".into();
                    locked.acknowledged_at = Some(state::now());
                }
                save(&journal, path)?;
                return Ok(());
            }
            Err(error) => {
                // A replacement fence permits terminal delivery and output replay only.
                retry_delivery(&daemon, path, &journal, error).await?;
            }
        }
    }
}
async fn recover(daemon: Arc<Daemon>, org: &str, session: &str) -> Result<()> {
    let root = daemon.dir.join("jobs");
    if !root.exists() {
        return Ok(());
    }
    for entry in std::fs::read_dir(root)? {
        let path = entry?.path().join("journal.json");
        if !path.exists() {
            continue;
        };
        let mut j: Journal = state::read_json(&path)?;
        if j.organization != org || ["acknowledged", "delivery_blocked"].contains(&j.phase.as_str())
        {
            continue;
        };
        j.recovery_session = Some(session.into());
        if !["exited", "terminal_pending"].contains(&j.phase.as_str()) {
            j.error = Some(
                json!({"code":"EXECUTION_INDETERMINATE","message":"Daemon restarted before durable terminal outcome; command was not replayed","indeterminate":true}),
            );
            j.result = None;
            j.phase = "terminal_pending".into();
        }
        state::write_json(&path, &j)?;

        let d = daemon.clone();
        let active = ActiveJob::new(d.clone());
        tokio::spawn(async move {
            let _active = active;
            let _ = deliver(d.clone(), &path, Arc::new(Mutex::new(j))).await;
        });
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    fn leased_payload_fixture() -> Value {
        json!({
            "payloadDigest": "cbab9f708061faba6e1a3bdc5be2cdac766e781a6f8b0e09f86cd512f2983a3b",
            "payload": {
                "command": ["/usr/bin/printf", "%s\\n", "LOOMEX_DIGEST_OK"],
                "cwd": ".", "executionPolicy": "host_user/v1",
                "workspacePath": "/tmp/loomex-workspace",
                "preparationId": "11111111-1111-4111-8111-111111111111",
                "bindingDigest": "bound-inputs", "providerConfiguration": {}, "env": {},
                "nested": {"authorizationEnvelope": "stable producer value"},
                "authorizationEnvelope": {
                    "version": 1, "capability": "shell.exec", "actor": "leased-session",
                    "inputDigest": "sha256:capability-input", "workspace": "/tmp/loomex-workspace",
                    "expiresAtEpochMs": 2000000000000u64, "nonce": "lease-nonce",
                    "approval": {"approved": true, "leaseVersion": 7}
                }
            }
        })
    }

    #[test]
    fn leased_payload_digest_matches_backend_stable_projection() {
        // Digest independently produced by Python json.dumps(sort_keys=True,
        // separators=(',', ':'), ensure_ascii=False) before lease enrichment.
        let mut job = leased_payload_fixture();
        assert_ne!(state::json_digest(&job["payload"]), job["payloadDigest"]);
        verify_payload_digest(&job).unwrap();
        job["payload"]["authorizationEnvelope"]["nonce"] = json!("renewed-lease-nonce");
        verify_payload_digest(&job).unwrap();
        job["payload"]
            .as_object_mut()
            .unwrap()
            .remove("authorizationEnvelope");
        verify_payload_digest(&job).unwrap();
    }

    #[test]
    fn leased_payload_digest_rejects_every_stable_field_tamper() {
        for (pointer, replacement) in [
            ("/payload/command/2", "TAMPERED"),
            ("/payload/workspacePath", "/tmp/other-workspace"),
            ("/payload/cwd", "other-directory"),
            ("/payload/bindingDigest", "different-binding"),
            (
                "/payload/nested/authorizationEnvelope",
                "tampered nested producer value",
            ),
        ] {
            let mut job = leased_payload_fixture();
            *job.pointer_mut(pointer).unwrap() = json!(replacement);
            assert_eq!(
                verify_payload_digest(&job).unwrap_err().to_string(),
                "PAYLOAD_DIGEST_MISMATCH",
                "{pointer}"
            );
        }
    }

    #[test]
    fn fence_preserves_exact_lease() {
        let j = Journal {
            job: json!({"leaseVersion":42}),
            organization: "o".into(),
            session: "s".into(),
            recovery_session: None,
            phase: "running".into(),
            identity: None,
            result: None,
            error: None,
            terminal_key: "t".into(),
            started_at: 0,
            acknowledged_at: None,
            event_sender: Default::default(),
            stdout_pending: None,
            stderr_pending: None,
            stdout_offset: 0,
            stderr_offset: 0,
        };
        assert_eq!(fence(&j), json!({"sessionId":"s","leaseVersion":42}));
    }
}

#[cfg(test)]
mod protocol_tests {
    use super::*;
    use crate::{api::Api, auth::Auth};
    use tokio::io::AsyncWriteExt;
    use tokio::net::{TcpListener, TcpStream};
    async fn receive(listener: &TcpListener) -> (TcpStream, Value) {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut bytes = Vec::new();
        loop {
            let mut buf = [0; 8192];
            let n = stream.read(&mut buf).await.unwrap();
            assert!(n > 0);
            bytes.extend_from_slice(&buf[..n]);
            if let Some(end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                let head = String::from_utf8_lossy(&bytes[..end]);
                let length = head
                    .lines()
                    .find_map(|l| {
                        l.to_ascii_lowercase()
                            .strip_prefix("content-length: ")
                            .map(|s| s.parse::<usize>().unwrap())
                    })
                    .unwrap();
                if bytes.len() >= end + 4 + length {
                    return (stream, serde_json::from_slice(&bytes[end + 4..]).unwrap());
                }
            }
        }
    }
    async fn reply(mut stream: TcpStream, data: Value) {
        let body = json!({"data":data,"meta":{}}).to_string();
        stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{}",body.len(),body).as_bytes()).await.unwrap();
    }
    fn journal() -> Journal {
        Journal {
            job: json!({"id":"11111111-1111-4111-8111-111111111111","leaseVersion":7,"payloadDigest":"digest","createdByExecutionId":"22222222-2222-4222-8222-222222222222","createdByNodeExecutionId":null,"payload":{"command":["/bin/sh","-c","exit 99"]}}),
            organization: "org".into(),
            session: "old-session".into(),
            recovery_session: None,
            phase: "running".into(),
            identity: None,
            result: None,
            error: None,
            terminal_key: "persistent-terminal-key".into(),
            started_at: 0,
            acknowledged_at: None,
            event_sender: Default::default(),
            stdout_pending: None,
            stderr_pending: None,
            stdout_offset: 0,
            stderr_offset: 0,
        }
    }
    fn daemon(path: &Path, origin: String) -> Arc<Daemon> {
        let api = Api::for_test_origin(&origin).unwrap();
        Arc::new(
            Daemon::new(
                path.into(),
                api.clone(),
                Auth::test_enrolled(api, "org", "runner"),
            )
            .unwrap(),
        )
    }
    #[tokio::test]
    async fn concurrent_output_senders_serialize_offsets() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let t = tempfile::tempdir().unwrap();
        let d = daemon(
            &t.path().join("state"),
            format!("http://{}", listener.local_addr().unwrap()),
        );
        let j = Arc::new(Mutex::new(journal()));
        let path = d
            .dir
            .join("jobs")
            .join(journal().job["id"].as_str().unwrap())
            .join("journal.json");
        state::write_json(&path, &snapshot(&j).unwrap()).unwrap();
        let stdout = path.parent().unwrap().join("stdout");
        std::fs::write(&stdout, vec![b'a'; 32768]).unwrap();
        let d1 = d.clone();
        let j1 = j.clone();
        let p1 = path.clone();
        let first = tokio::spawn(async move { stream_events(&d1, &p1, &j1).await.unwrap() });
        let (stream, body) = receive(&listener).await;
        assert_eq!(body["events"][0]["payload"]["offset"], 0);
        let d2 = d.clone();
        let j2 = j.clone();
        let p2 = path.clone();
        let second = tokio::spawn(async move { stream_events(&d2, &p2, &j2).await.unwrap() });
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(30), listener.accept())
                .await
                .is_err()
        );
        std::fs::write(&stdout, vec![b'a'; 65536]).unwrap();
        reply(stream, json!({})).await;
        let (stream, body) = receive(&listener).await;
        assert_eq!(body["events"][0]["payload"]["offset"], 32768);
        assert_eq!(body["events"][0]["payload"]["chunkId"], "stdout:32768");
        reply(stream, json!({})).await;
        assert!(first.await.unwrap() && second.await.unwrap());
        assert_eq!(snapshot(&j).unwrap().stdout_offset, 65536);
        assert!(!stream_events(&d, &path, &j).await.unwrap());
    }
    #[tokio::test]
    async fn lost_output_response_retries_exact_durable_chunk_when_spool_grows() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let t = tempfile::tempdir().unwrap();
        let d = daemon(
            &t.path().join("state"),
            format!("http://{}", listener.local_addr().unwrap()),
        );
        let j = Arc::new(Mutex::new(journal()));
        let path = d
            .dir
            .join("jobs")
            .join(journal().job["id"].as_str().unwrap())
            .join("journal.json");
        state::write_json(&path, &snapshot(&j).unwrap()).unwrap();
        let stdout = path.parent().unwrap().join("stdout");
        std::fs::write(&stdout, b"first chunk").unwrap();
        let d1 = d.clone();
        let j1 = j.clone();
        let p1 = path.clone();
        let first = tokio::spawn(async move { stream_events(&d1, &p1, &j1).await });
        let (stream, original) = receive(&listener).await;
        drop(stream);
        assert!(first.await.unwrap().is_err());
        std::fs::write(&stdout, b"first chunk plus later output").unwrap();
        // Simulate restart: pending length must be in the durable journal.
        let recovered = Arc::new(Mutex::new(state::read_json::<Journal>(&path).unwrap()));
        let d2 = d.clone();
        let p2 = path.clone();
        let j2 = recovered.clone();
        let retry = tokio::spawn(async move { stream_events(&d2, &p2, &j2).await.unwrap() });
        let (stream, retried) = receive(&listener).await;
        assert_eq!(original, retried);
        reply(stream, json!({})).await;
        assert!(retry.await.unwrap());
        assert_eq!(snapshot(&recovered).unwrap().stdout_offset, 11);
    }
    #[tokio::test]
    async fn helper_scope_joins_writers_before_panic_terminal_is_recorded() {
        let t = tempfile::tempdir().unwrap();
        let path = t.path().join("journal.json");
        let scope = Arc::new(ExecutionScope::default());
        let helper_path = path.clone();
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        scope.register(tokio::spawn(async move {
            let _ = ready_tx.send(());
            tokio::time::sleep(std::time::Duration::from_millis(40)).await;
            state::write_json(&helper_path, &json!({"phase":"started"})).unwrap();
        }));
        ready_rx.await.unwrap();
        let worker = tokio::spawn(async { panic!("injected execution task panic") });
        assert!(worker.await.is_err());
        scope.stop().await;
        state::write_json(
            &path,
            &json!({"phase":"acknowledged","error":"JOB_TASK_PANICKED"}),
        )
        .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(60)).await;
        assert_eq!(
            state::read_json::<Value>(&path).unwrap()["phase"],
            "acknowledged"
        );
        assert!(scope.tasks.lock().unwrap().is_empty());
    }
    #[tokio::test]
    async fn drain_counts_held_startup_and_lease_until_session_writers_finish() {
        for hold_startup in [true, false] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let t = tempfile::tempdir().unwrap();
            let d = daemon(
                &t.path().join("state"),
                format!("http://{}", listener.local_addr().unwrap()),
            );
            let worker_daemon = d.clone();
            let task =
                tokio::spawn(async move { session(worker_daemon, "org".into()).await.unwrap() });
            let (stream, _) = receive(&listener).await;
            let held = if hold_startup {
                stream
            } else {
                reply(stream, json!({"session":{"id":"session"}})).await;
                receive(&listener).await.0
            };
            let status = d.dispatch("status.get", json!({})).await.unwrap();
            assert_eq!(status["activeJobs"], 0);
            let drain = d
                .dispatch("daemon.drain", json!({"idempotencyKey":Uuid::new_v4()}))
                .await
                .unwrap();
            assert!(drain["activeJobs"].as_u64().unwrap() > 0);
            assert_eq!(drain["updateDeferred"], true);
            assert!(admit(&d).unwrap().is_none());
            reply(
                held,
                if hold_startup {
                    json!({"session":{"id":"session"}})
                } else {
                    json!({"job":null})
                },
            )
            .await;
            let (stream, body) = receive(&listener).await;
            assert_eq!(body["reason"], "daemon drained");
            reply(stream, json!({})).await;
            task.await.unwrap();
            tokio::task::yield_now().await;
            assert_eq!(d.managed_work(), 0);
        }
    }
    #[tokio::test]
    async fn artifact_upload_resumes_and_preserves_more_than_one_transport_frame() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let t = tempfile::tempdir().unwrap();
        let d = daemon(
            &t.path().join("state"),
            format!("http://{}", listener.local_addr().unwrap()),
        );
        let data: Vec<u8> = (0..1_200_017).map(|i| (i % 251) as u8).collect();
        let expected = data.clone();
        let path = t.path().join("large-output");
        std::fs::write(&path, &data).unwrap();
        let server = tokio::spawn(async move {
            let (stream, start) = receive(&listener).await;
            assert_eq!(start["checksumSha256"], state::digest(&expected));
            assert_eq!(start["jobId"], "11111111-1111-4111-8111-111111111111");
            let mut offset = 262144usize;
            reply(stream, json!({"transferId":"transfer","offset":offset})).await;
            while offset < expected.len() {
                let (stream, chunk) = receive(&listener).await;
                assert_eq!(chunk["offset"].as_u64(), Some(offset as u64));
                let raw = STANDARD
                    .decode(chunk["dataBase64"].as_str().unwrap())
                    .unwrap();
                assert!(raw.len() <= 262144);
                assert_eq!(raw, expected[offset..offset + raw.len()]);
                offset += raw.len();
                reply(stream, json!({"offset":offset})).await;
            }
            let (stream, body) = receive(&listener).await;
            assert_eq!(body, json!({}));
            reply(
                stream,
                json!({"artifactId":"33333333-3333-4333-8333-333333333333"}),
            )
            .await;
        });
        let result = upload(
            &d,
            &journal(),
            &path,
            "output.bin",
            "application/octet-stream",
            "stdout",
        )
        .await
        .unwrap();
        server.await.unwrap();
        assert_eq!(result["sizeBytes"], data.len());
        assert_eq!(result["checksumSha256"], state::digest(&data));
    }
    #[tokio::test]
    async fn restart_reclaims_only_terminal_delivery_after_historical_fence_is_rejected() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let t = tempfile::tempdir().unwrap();
        let d = daemon(
            &t.path().join("state"),
            format!("http://{}", listener.local_addr().unwrap()),
        );
        let j = journal();
        let path = d
            .dir
            .join("jobs")
            .join(j.job["id"].as_str().unwrap())
            .join("journal.json");
        state::write_json(&path, &j).unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, body) = receive(&listener).await;
            assert_eq!(body["sessionId"], "old-session");
            let error = json!({"error":{"code":"RUNNER_JOB_NOT_FOUND"}}).to_string();
            stream.write_all(format!("HTTP/1.1 409 Conflict\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",error.len(),error).as_bytes()).await.unwrap();
            drop(stream);
            let (stream, body) = receive(&listener).await;
            assert_eq!(body["sessionId"], "new-session");
            assert_eq!(body["terminalSubmission"], true);
            assert_eq!(body["expectedLeaseVersion"], 7);
            let mut renewed = journal().job;
            renewed["leaseVersion"] = json!(8);
            reply(stream, json!({"job":renewed})).await;
            let (stream, body) = receive(&listener).await;
            assert_eq!(body["sessionId"], "new-session");
            assert_eq!(body["leaseVersion"], 8);
            assert_eq!(body["error"]["code"], "EXECUTION_INDETERMINATE");
            reply(stream, json!({"job":{"status":"failed"}})).await;
        });
        recover(d.clone(), "org", "new-session").await.unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(8), server)
            .await
            .unwrap()
            .unwrap();
        for _ in 0..100 {
            if d.active.load(Ordering::SeqCst) == 0 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        let record: Journal = state::read_json(&path).unwrap();
        assert_eq!(record.phase, "acknowledged");
        assert_eq!(record.session, "new-session");
        assert!(record.identity.is_none());
    }
    #[tokio::test]
    async fn restart_redelivers_indeterminate_terminal_without_replaying_command() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let t = tempfile::tempdir().unwrap();
        let d = daemon(
            &t.path().join("state"),
            format!("http://{}", listener.local_addr().unwrap()),
        );
        let j = journal();
        let path = d
            .dir
            .join("jobs")
            .join(j.job["id"].as_str().unwrap())
            .join("journal.json");
        state::write_json(&path, &j).unwrap();
        let server = tokio::spawn(async move {
            let (stream, body) = receive(&listener).await;
            assert_eq!(body["sessionId"], "old-session");
            assert_eq!(body["leaseVersion"], 7);
            assert_eq!(body["idempotencyKey"], "persistent-terminal-key");
            assert_eq!(body["error"]["code"], "EXECUTION_INDETERMINATE");
            assert!(body.get("result").is_none());
            reply(stream, json!({"job":{"status":"failed"}})).await;
        });
        recover(d.clone(), "org", "new-session").await.unwrap();
        server.await.unwrap();
        for _ in 0..100 {
            if d.active.load(Ordering::SeqCst) == 0 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        let recovered: Journal = state::read_json(&path).unwrap();
        assert_eq!(recovered.phase, "acknowledged");
        assert!(recovered.identity.is_none());
        assert!(recovered.error.is_some());
        assert!(!path.parent().unwrap().join("stdout").exists());
    }
}

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
            if let Some(cancel) = daemon.cancellations.lock().await.get(id) {
                cancel.store(true, Ordering::SeqCst);
            } else {
                crate::retention::purge_job(&path)?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod authorization_tests {
    use super::*;
    use crate::{api::Api, auth::Auth, state::WorkspaceGrant};
    #[tokio::test]
    async fn workspace_choice_never_substitutes_for_confirmed_preparation() {
        let temp = tempfile::tempdir().unwrap();
        let workspace = temp.path().join("workspace");
        std::fs::create_dir(&workspace).unwrap();
        let workspace = std::fs::canonicalize(workspace).unwrap();
        let api = Api::for_test_origin("http://127.0.0.1:9").unwrap();
        let daemon = Daemon::new(
            temp.path().join("state"),
            api.clone(),
            Auth::test_enrolled(api, "org", "runner"),
        )
        .unwrap();
        let install = daemon.auth.installation_id().await.unwrap();
        daemon
            .public
            .lock()
            .await
            .grants
            .push(WorkspaceGrant::new(&workspace, "org", &install, "key").unwrap());
        let prep = Uuid::new_v4();
        let providers = provider_snapshot().unwrap();
        let config = json!({"requested":{},"installed":providers});
        let mut j = Journal {
            job: json!({"id":Uuid::new_v4(),"kind":"command.run","payload":{"preparationId":prep,"bindingDigest":"exact-binding","executionPolicy":"host_user/v1","workspacePath":workspace,"providerConfiguration":config,"command":["/usr/bin/true"]}}),
            organization: "org".into(),
            session: "session".into(),
            recovery_session: None,
            phase: "leased".into(),
            identity: None,
            result: None,
            error: None,
            terminal_key: "terminal".into(),
            started_at: 0,
            acknowledged_at: None,
            event_sender: Default::default(),
            stdout_pending: None,
            stderr_pending: None,
            stdout_offset: 0,
            stderr_offset: 0,
        };
        assert!(require_execution_authorization(&daemon, &j).await.is_err());
        let path = daemon.dir.join("preparations").join(format!("{prep}.json"));
        let mut record = json!({"organizationId":"org","installationId":install,"workspacePath":workspace,"bindingDigest":"exact-binding","binding":{"executionPolicy":"host_user/v1","providerConfiguration":config},"providers":providers});
        state::write_json(&path, &record).unwrap();
        assert!(require_execution_authorization(&daemon, &j).await.is_err());
        record["commitAuthorization"] = json!({"preparationId":prep,"bindingDigest":"exact-binding","idempotencyKey":Uuid::new_v4(),"authorizedAt":state::now()});
        state::write_json(&path, &record).unwrap();
        assert_eq!(
            require_execution_authorization(&daemon, &j).await.unwrap(),
            workspace
        );
        j.job["payload"]["bindingDigest"] = json!("changed");
        assert!(require_execution_authorization(&daemon, &j).await.is_err());
        j.job["payload"]["bindingDigest"] = json!("exact-binding");
        j.job["payload"]["command"] = json!("touch unauthorized");
        j.job["payload"]["shell"] = json!(true);
        j.job["payloadDigest"] = json!(state::json_digest(&j.job["payload"]));
        let journal_path = daemon
            .dir
            .join("jobs")
            .join(Uuid::new_v4().to_string())
            .join("journal.json");
        let shared = Arc::new(Mutex::new(j));
        let error = execute_job(
            Arc::new(daemon),
            &journal_path,
            shared,
            Arc::new(AtomicBool::new(false)),
            Arc::new(ExecutionScope::default()),
        )
        .await
        .unwrap_err();
        assert_eq!(error.to_string(), "INVALID_COMMAND");
        assert!(!workspace.join("unauthorized").exists());
    }
    #[tokio::test]
    async fn active_accounting_survives_task_panic() {
        let t = tempfile::tempdir().unwrap();
        let api = Api::for_test_origin("http://127.0.0.1:9").unwrap();
        let d =
            Arc::new(Daemon::new(t.path().into(), api.clone(), Auth::test_unauthed(api)).unwrap());

        let copy = d.clone();
        let task = tokio::spawn(async move {
            let _active = ActiveJob::new(copy);
            panic!("synthetic worker failure")
        });
        assert!(task.await.is_err());
        assert_eq!(d.active.load(Ordering::SeqCst), 0);
    }
}
