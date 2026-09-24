//! Credential-free local API. Only explicitly catalogued backend routes are reachable.
use crate::{
    api::{Api, ApiError},
    auth::Auth,
    follow::FollowStore,
    presentation::PresentationStore,
    recovery::RecoveryStore,
    state::{self, PublicState, WorkspaceGrant},
};
use anyhow::{Context, Result, bail, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use fs2::FileExt;
use serde_json::{Value, json};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
#[cfg(test)]
use std::sync::atomic::AtomicUsize;
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{UnixListener, UnixStream},
    sync::Mutex,
};
use uuid::Uuid;

pub const PROTOCOL: &str = "loomex.local-control/v2";
pub const MAX_FRAME: usize = 1_048_576;
pub const VALIDATION_ERRORS_CAPABILITY: &str = "error.validation-issues/v1";
pub const REQUIRED_SEMANTICS: [&str; 5] = [
    "execution.host_user/v1",
    "authorization.prepare-commit/v1",
    "auth:browser-pkce/v1",
    "transfer.chunked/v1",
    VALIDATION_ERRORS_CAPABILITY,
];
#[cfg(test)]
static TEST_START_HANDOFF_FOLLOW_FAILURE: AtomicBool = AtomicBool::new(false);
fn negotiate(params: &Value) -> Result<Value> {
    let catalog: Value = serde_json::from_str(include_str!("../contracts/method-catalog.json"))?;
    let offered = params["supportedProtocols"]
        .as_array()
        .context("INVALID_REQUEST")?;
    let required = params["requiredCapabilities"]
        .as_array()
        .context("INVALID_REQUEST")?;
    let available = catalog["capabilities"].as_array().context("INTERNAL")?;
    if !offered.contains(&json!(PROTOCOL)) || required.iter().any(|cap| !available.contains(cap)) {
        bail!("COMPATIBILITY_ERROR");
    }
    Ok(
        json!({"selectedProtocol":PROTOCOL,"capabilities":available,"maxFrameBytes":MAX_FRAME,"serverVersion":env!("CARGO_PKG_VERSION")}),
    )
}
struct MutationKey {
    digest: String,
    lock: std::sync::Weak<Mutex<()>>,
}
pub struct Daemon {
    pub dir: PathBuf,
    pub api: Api,
    pub auth: Auth,
    pub presentation: PresentationStore,
    pub recovery: RecoveryStore,
    pub follow: FollowStore,
    pub public: Mutex<PublicState>,
    pub execution: Arc<crate::jobs::supervisor::ExecutionSupervisor>,
    mutation_keys: std::sync::Mutex<HashMap<String, MutationKey>>,
    start_handoff_locks: std::sync::Mutex<HashMap<String, std::sync::Weak<Mutex<()>>>>,
    preparation_handoff_locks: std::sync::Mutex<HashMap<String, std::sync::Weak<Mutex<()>>>>,
    lifecycle_draining: AtomicBool,
}
struct ControlWriter<'a>(&'a Daemon);
impl Drop for ControlWriter<'_> {
    fn drop(&mut self) {
        self.0.execution.end_control();
    }
}
struct LogoutAdmission(Arc<crate::jobs::supervisor::ExecutionSupervisor>);
impl Drop for LogoutAdmission {
    fn drop(&mut self) {
        self.0.set_logout_requested(false);
    }
}
impl Daemon {
    pub fn new(dir: PathBuf, api: Api, auth: Auth) -> Result<Self> {
        state::private_dir(&dir)?;
        let public = PublicState::load(&dir)?;
        let presentation = PresentationStore::open(&dir)?;
        let recovery = RecoveryStore::open(&dir)?;
        let follow = FollowStore::open(&dir)?;
        let draining = dir.join("drain.json").exists();
        Ok(Self {
            dir,
            api,
            auth,
            presentation,
            recovery,
            follow,
            public: Mutex::new(public),
            execution: Arc::new(crate::jobs::supervisor::ExecutionSupervisor::new(draining)),
            mutation_keys: std::sync::Mutex::new(HashMap::new()),
            start_handoff_locks: std::sync::Mutex::new(HashMap::new()),
            preparation_handoff_locks: std::sync::Mutex::new(HashMap::new()),
            lifecycle_draining: AtomicBool::new(draining),
        })
    }
    pub fn managed_work(&self) -> usize {
        self.execution.managed_work()
    }
    /// Work that owns or is about to own a provider process. Ordinary control
    /// RPCs are deliberately excluded: they must not make a connected account
    /// appear to have running workflow work or indefinitely block logout.
    pub fn execution_work(&self) -> usize {
        self.execution.execution_work()
    }
    fn reported_work(&self) -> usize {
        if self.execution.is_draining() {
            self.managed_work()
        } else {
            self.execution.active_work()
        }
    }
    pub async fn selected_org(&self) -> Result<String> {
        self.public
            .lock()
            .await
            .active_organization
            .clone()
            .context("ORGANIZATION_REQUIRED")
    }
    pub async fn backend(
        &self,
        org: &str,
        method: &str,
        path: &str,
        body: Option<Value>,
        key: Option<&str>,
    ) -> Result<Value> {
        let credential = self.auth.credential(org).await?;
        Ok(self
            .api
            .request(method, path, body, Some(&credential), key)
            .await?)
    }
    pub async fn granted(&self, path: &Path, org: &str) -> Result<PathBuf> {
        let install = self.auth.installation_id().await?;
        self.public.lock().await.require_grant(path, org, &install)
    }
    fn drain_status(&self) -> Value {
        let work = self.managed_work();
        json!({"draining":true,"activeJobs":work,"updateDeferred":work>0})
    }
    fn control_writer(&self, method: &str, write: bool) -> Result<Option<ControlWriter<'_>>> {
        if ["protocol.negotiate", "status.get", "connection.get"].contains(&method) {
            return Ok(None);
        }
        let _admission = self.execution.admission_lock()?;
        if self.lifecycle_draining.load(Ordering::SeqCst) {
            if method == "daemon.drain" && self.dir.join("drain.json").exists() {
                return Ok(None);
            }
            if method != "daemon.drain" {
                if write && !["runs.cancel", "auth.logout"].contains(&method) {
                    bail!("RUNNER_NOT_READY");
                }
                // A cancellation/read may join an existing drain, but cannot reopen
                // an idle acknowledgement. Incrementing only a nonzero total is atomic.
                self.execution.join_drain()?;
                return Ok(Some(ControlWriter(self)));
            }
        } else if self.execution.is_draining()
            && write
            && ![
                "auth.login",
                "auth.cancel",
                "auth.recover",
                "auth.logout",
                "organizations.select",
                "daemon.drain",
                "runs.cancel",
            ]
            .contains(&method)
        {
            bail!("RUNNER_NOT_READY");
        }
        self.execution.begin_control();
        if method == "daemon.drain" {
            self.lifecycle_draining.store(true, Ordering::SeqCst);
            self.execution.set_draining(true);
        }
        Ok(Some(ControlWriter(self)))
    }
    pub async fn dispatch(&self, method: &str, params: Value) -> Result<Value> {
        let catalog: Value =
            serde_json::from_str(include_str!("../contracts/method-catalog.json"))?;
        let entry = catalog["methods"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["name"] == method)
            .context("METHOD_NOT_FOUND")?;
        validate_params(&params, &entry["inputSchema"])?;
        let write = entry["mutating"] == true;
        // A reviewed-run ticket is a runner-issued, one-use idempotency
        // boundary. Use it as the local singleflight and receipt key because
        // the chat commit surface intentionally accepts no caller-selected
        // idempotency key.
        // Read-only receipt lookups carry the mutation's idempotency key as
        // data. They must not claim the mutation's local journal slot.
        let key = write
            .then(|| {
                params
                    .get("idempotencyKey")
                    .and_then(Value::as_str)
                    .or_else(|| {
                        (method == "runs.start_handoff.commit")
                            .then(|| params.get("handoffRef").and_then(Value::as_str))
                            .flatten()
                    })
            })
            .flatten();
        // Capture organization before waiting for any operation. The handler never
        // substitutes a later active organization into this operation's identity.
        let scope = if method.starts_with("auth.")
            || method.starts_with("connection.")
            || method == "daemon.drain"
        {
            None
        } else {
            params["organizationId"].as_str().map(String::from).or(self
                .public
                .lock()
                .await
                .active_organization
                .clone())
        };
        let scoped_account = if account_scoped_method(method) {
            Some(
                self.auth
                    .credential(scope.as_deref().context("ORGANIZATION_REQUIRED")?)
                    .await?
                    .subject,
            )
        } else {
            None
        };
        let identity = state::json_digest(
            &json!({"method":method,"params":params,"organizationId":scope,"accountSubject":scoped_account}),
        );
        let journal_key = key.map(|key| {
            if account_scoped_method(method) {
                state::json_digest(&json!({"organizationId":scope,"accountSubject":scoped_account,"idempotencyKey":key}))
            } else {
                key.to_owned()
            }
        });
        // Recovery mutations own a stricter, transactional receipt journal in
        // `RecoveryStore`.  Returning this generic operation cache after a
        // lost response would replay the creator's `attemptPermitted: true`
        // result and could authorize a second host scheduling mutation.  Keep
        // the generic cache for other operations, but always route recovery
        // methods through their durable, safe replay projection.
        // Start issue and approval have runner-owned lifecycle records rather
        // than generic operation-cache entries. A lost response must be
        // reconciled against that exact record; it never authorizes a replay.
        let operation = (!method.starts_with("recovery.")
            && !matches!(
                method,
                "runs.start_handoff.issue" | "runs.start_handoff.approve"
            ))
        .then(|| {
            journal_key
                .as_deref()
                .map(|key| self.dir.join("operations").join(format!("{key}.json")))
        })
        .flatten();
        if let Some(path) = operation.as_ref().filter(|path| path.exists()) {
            let record: Value = state::read_json(path)?;
            if record["digest"] != identity {
                bail!("IDEMPOTENCY_CONFLICT");
            }
        }
        let singleflight = if let Some(key) = journal_key.as_deref() {
            let mut keys = self
                .mutation_keys
                .lock()
                .map_err(|_| anyhow::anyhow!("INTERNAL"))?;
            keys.retain(|_, entry| entry.lock.strong_count() > 0);
            let lock = if let Some(existing) = keys.get(key) {
                if existing.digest != identity {
                    bail!("IDEMPOTENCY_CONFLICT");
                }
                existing
                    .lock
                    .upgrade()
                    .unwrap_or_else(|| Arc::new(Mutex::new(())))
            } else {
                Arc::new(Mutex::new(()))
            };
            keys.insert(
                key.to_owned(),
                MutationKey {
                    digest: identity.clone(),
                    lock: Arc::downgrade(&lock),
                },
            );
            Some(lock)
        } else {
            None
        };
        let writer = self.control_writer(method, write)?;
        // A repeated drain after its durable acknowledgement is a read; it must
        // not create another journal writer after an installer observed idle.
        if method == "daemon.drain" && writer.is_none() {
            return Ok(self.drain_status());
        }
        let _singleflight = match singleflight {
            Some(lock) => Some(lock.lock_owned().await),
            None => None,
        };
        let cached = if let Some(path) = &operation {
            if path.exists() {
                let record: Value = state::read_json(path)?;
                if record["digest"] != identity {
                    bail!("IDEMPOTENCY_CONFLICT");
                }
                if record["expired"] == true {
                    bail!("RESULT_EXPIRED");
                }
                record.get("result").cloned()
            } else {
                state::write_json(
                    path,
                    &json!({"digest":identity,"method":method,"status":"pending"}),
                )?;
                None
            }
        } else {
            None
        };
        let result = if let Some(cached) = cached {
            // A process can finish a durable commit while its response is lost
            // or normalized incorrectly by an older daemon. Rehydrate only a
            // receipt that this exact runner identity already issued for this
            // exact mutation; never mint a continuation on cache replay.
            let result = self
                .restore_cached_follow_continuation(scope.as_deref(), method, &params, cached)
                .await?;
            if let Some(path) = operation.as_ref() {
                let execution = params
                    .get("runId")
                    .or_else(|| result.get("executionId"))
                    .or_else(|| result.get("execution").and_then(|value| value.get("id")))
                    .cloned();
                state::write_json(
                    path,
                    &json!({"digest":identity,"method":method,"cachedAt":state::now(),"executionId":execution,"result":result}),
                )?;
            }
            result
        } else {
            let result = normalize_catalog_output(
                self.handle(method, &params, scope.as_deref()).await?,
                &entry["outputSchema"],
            )?;
            let execution = params
                .get("runId")
                .or_else(|| result.get("executionId"))
                .or_else(|| result.get("execution").and_then(|value| value.get("id")))
                .cloned();
            // Spooling remains inside writer coverage; socket delivery below is not
            // counted once no more local files or backend state can be changed.
            let result = self.spool_response(&params, result)?;
            if let Some(path) = operation.as_ref() {
                state::write_json(
                    path,
                    &json!({"digest":identity,"method":method,"cachedAt":state::now(),"executionId":execution,"result":result}),
                )?;
            }
            result
        };
        drop(writer);
        if method == "daemon.drain" {
            Ok(self.drain_status())
        } else {
            Ok(result)
        }
    }
    fn spool_response(&self, params: &Value, result: Value) -> Result<Value> {
        let bytes = serde_json::to_vec(&result)?;
        if bytes.len() <= MAX_FRAME - 1024 {
            return Ok(result);
        }
        let reference = Uuid::new_v4();
        let checksum = state::digest(&bytes);
        state::atomic_write(
            &self.dir.join("responses").join(format!("{reference}.json")),
            &bytes,
        )?;
        state::atomic_write(
            &self
                .dir
                .join("responses")
                .join(format!("{reference}.sha256")),
            checksum.as_bytes(),
        )?;
        state::write_json(
            &self
                .dir
                .join("responses")
                .join(format!("{reference}.meta.json")),
            &json!({"executionId":params["runId"],"lastAccessAt":state::now()}),
        )?;
        Ok(
            json!({"responseRef":reference,"sizeBytes":bytes.len(),"encoding":"json","nextOffset":0,"checksumSha256":checksum}),
        )
    }
    async fn handle(&self, method: &str, p: &Value, scope: Option<&str>) -> Result<Value> {
        let key = p.get("idempotencyKey").and_then(Value::as_str);
        match method {
            "protocol.negotiate" => return negotiate(p),
            "status.get" => {
                return Ok(
                    json!({"version":env!("CARGO_PKG_VERSION"),"protocol":PROTOCOL,"activeJobs":self.reported_work(),"draining":self.execution.is_draining(),"updateDeferred":self.dir.join("pending-update.json").exists(),"details":{"monitoring":{"schemaVersion":"loomex.monitoring-readiness/v1","runObservationAvailable":true,"hostHookDeliveryAuthority":"host_managed","hostRecoveryAuthority":"host_managed","guarantee":"none"}}}),
                );
            }
            "connection.get" => {
                let selected = self.public.lock().await.active_organization.clone();
                let mut projection = self.auth.connection(selected, self.execution_work()).await;
                projection["webAppUrl"] = json!(self.api.web_app_url());
                return Ok(projection);
            }
            "auth.login" => {
                return self
                    .auth
                    .login(
                        p["runnerName"].as_str().unwrap_or("Loomex runner"),
                        key.unwrap(),
                    )
                    .await;
            }
            "auth.cancel" => return self.auth.cancel_login(required(p, "flowId")?).await,
            "auth.recover" => return self.auth.reconcile().await,
            "auth.status" => return self.auth.status().await,
            "auth.logout" => {
                let _logout_admission = {
                    let _admission = self.execution.admission_lock()?;
                    // Existing provider work is never stopped by logout.
                    // Idle lease and heartbeat tasks are instead prevented
                    // from admitting more work, then allowed to exit normally.
                    if self.execution.active_work() > 0 {
                        bail!("ACTIVE_WORK_REQUIRES_DRAIN");
                    }
                    self.execution.set_logout_requested(true);
                    LogoutAdmission(self.execution.clone())
                };
                let deadline = Instant::now() + Duration::from_secs(40);
                while self.execution_work() > 0 {
                    if self.execution.active_work() > 0 || Instant::now() >= deadline {
                        bail!("ACTIVE_WORK_REQUIRES_DRAIN");
                    }
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                let result = self.auth.logout().await?;
                let mut public = self.public.lock().await;
                public.active_organization = None;
                public.save(&self.dir)?;
                return Ok(result);
            }
            "organizations.list" => return self.auth.organizations().await,
            "organizations.select" => {
                let org = required(p, "organizationId")?;
                let result = self.auth.select(org, key.unwrap()).await?;
                let mut public = self.public.lock().await;
                public.active_organization = Some(org.into());
                public.save(&self.dir)?;
                {
                    let _admission = self.execution.admission_lock()?;
                    if !self.lifecycle_draining.load(Ordering::SeqCst) {
                        self.execution.set_draining(false);
                    }
                }
                return Ok(result);
            }
            "daemon.drain" => {
                {
                    let _admission = self.execution.admission_lock()?;
                    self.execution.set_draining(true);
                }
                state::write_json(
                    &self.dir.join("drain.json"),
                    &json!({"requestedAt":state::now(),"idempotencyKey":key}),
                )?;
                return Ok(
                    json!({"draining":true,"activeJobs":self.reported_work(),"updateDeferred":self.managed_work()>0}),
                );
            }
            "workspaces.list" => return Ok(json!({"workspaces":self.public.lock().await.grants})),
            "responses.read" => return read_spool(&self.dir, p).await,
            "responses.delete" => {
                crate::retention::purge_response(&self.dir, required(p, "responseRef")?)?;
                return Ok(json!({"deleted":true}));
            }
            _ => {}
        }
        if let Some(operation) = method.strip_prefix("connection.views.") {
            // Owner-checked socket plus local installation storage. No account
            // authority is needed for disposable connection navigation.
            ensure!(
                ["create", "get", "update"].contains(&operation),
                "METHOD_NOT_FOUND"
            );
            return self.presentation.dispatch(
                "local-connection",
                "host-user",
                &format!("presentation.sessions.{operation}"),
                p,
            );
        }
        let org = scope.context("ORGANIZATION_REQUIRED")?.to_owned();
        if method == "presentation.delivery.get" {
            return self.delivery_get_or_derive(&org, p).await;
        }
        if method.starts_with("presentation.") {
            // The child runner identity is uniquely bound by the backend to one
            // account and organization. Neither scope component is accepted from UI.
            let account = self.auth.credential(&org).await?.subject;
            return self.presentation.dispatch(&org, &account, method, p);
        }
        if method.starts_with("recovery.") {
            let account = self.auth.credential(&org).await?.subject;
            let installation = self.auth.installation_id().await?;
            return self
                .recovery
                .dispatch(&org, &account, &installation, method, p);
        }
        if method.starts_with("follow.session.") {
            let account = self.auth.credential(&org).await?.subject;
            let installation = self.auth.installation_id().await?;
            let observation = if let Some(target) =
                self.follow
                    .lifecycle_target(&org, &account, &installation, p)?
            {
                let mut read = json!({"runId":target.run_id});
                if let Some(cursor) = target.event_cursor {
                    read["afterSequence"] = json!(cursor);
                }
                let (verb, route, body) = backend_route("runs.get", &read)?;
                let snapshot = self.backend(&org, &verb, &route, body, None).await?;
                // A terminal status is only a candidate. Read the terminal
                // result projection after event pages are exhausted before the
                // store records an allow-to-stop receipt.
                if crate::follow::FollowStore::terminal_snapshot(&snapshot) {
                    let (verb, route, body) = backend_route("runs.result", &read)?;
                    let terminal_result = self.backend(&org, &verb, &route, body, None).await?;
                    Some(json!({"snapshot":snapshot,"terminalResult":terminal_result}))
                } else {
                    Some(json!({"snapshot":snapshot}))
                }
            } else {
                None
            };
            return self.follow.dispatch_observed(
                &org,
                &account,
                &installation,
                method,
                p,
                observation.as_ref(),
            );
        }
        if method == "preparations.get" {
            return self.preparation_get(&org, p).await;
        }
        match method {
            "runs.start_handoff.issue" => return self.issue_run_start_handoff(&org, p).await,
            "runs.start_handoff.restore" => return self.restore_run_start_handoff(&org, p).await,
            "runs.start_handoff.approve" => return self.approve_run_start_handoff(&org, p).await,
            "runs.start_handoff.get" => return self.get_run_start_handoff(&org, p).await,
            "runs.start_handoff.commit" => return self.commit_run_start_handoff(&org, p).await,
            "workspaces.grant" => {
                self.auth.credential(&org).await?;
                let install = self.auth.installation_id().await?;
                let grant = WorkspaceGrant::new(
                    Path::new(required(p, "workspacePath")?),
                    &org,
                    &install,
                    key.unwrap(),
                )?;
                let mut public = self.public.lock().await;
                public
                    .grants
                    .retain(|g| !(g.organization_id == org && g.path == grant.path));
                public.grants.push(grant.clone());
                public.save(&self.dir)?;
                return Ok(json!({"workspace":grant,"executionPolicy":"host_user/v1"}));
            }
            "workspaces.revoke" => {
                let path = PathBuf::from(required(p, "workspacePath")?);
                let canonical = std::fs::canonicalize(&path).ok();
                let mut public = self.public.lock().await;
                public.grants.retain(|g| {
                    !(g.organization_id == org
                        && (g.path == path || canonical.as_ref() == Some(&g.path)))
                });
                public.save(&self.dir)?;
                return Ok(json!({"revoked":true}));
            }
            "runs.prepare" | "builder.prepare" | "editor.prepare" => {
                return self.prepare(method, &org, p).await;
            }
            "runs.commit" | "builder.commit" | "editor.commit" => {
                let mut result = self.commit(method, &org, p).await?;
                if method == "runs.commit" {
                    self.attach_follow_continuation(&org, "run_commit", None, &mut result)
                        .await?;
                    self.activate_ui_follow(&org, &result).await?;
                }
                return Ok(result);
            }
            "artifacts.download" => return self.download(&org, p).await,
            "builder.create" | "editor.create" => {
                self.granted(Path::new(required(p, "workspacePath")?), &org)
                    .await?;
            }
            _ => {}
        }
        let projection_account = if method == "runs.delete"
            || matches!(method, "interactions.respond" | "interactions.decide")
        {
            Some(self.auth.credential(&org).await?.subject)
        } else {
            None
        };
        let mut result = if method == "runs.wait" {
            // Provider activity is useful diagnostic information, but it is
            // not a reason to wake the chat model. Coalesce it locally until
            // a user-visible state change, an event page that must be read,
            // or the caller's bounded wait deadline.
            self.wait_for_meaningful_run_update(&org, p).await?
        } else {
            let (verb, route, body) = backend_route(method, p)?;
            self.backend(&org, &verb, &route, body, key).await?
        };
        if matches!(
            method,
            "runs.get" | "runs.wait" | "runs.events" | "runs.result"
        ) {
            self.attach_monitoring_observation(&org, required(p, "runId")?, &mut result)
                .await?;
        }
        if method == "runs.delete" {
            let run = required(p, "runId")?;
            crate::retention::mark_deleted_tree(&self.dir, run, &result)?;
            let deleted = result["deletedExecutionIds"]
                .as_array()
                .context("BACKEND_PROTOCOL_ERROR")?
                .iter()
                .map(|value| value.as_str().context("BACKEND_PROTOCOL_ERROR"))
                .collect::<Result<Vec<_>>>()?;
            self.presentation.delete_entities(
                &org,
                projection_account.as_deref().unwrap(),
                "execution",
                &deleted,
            )?;
            for field in [
                "preparationId",
                "preparationRootExecutionId",
                "deletedExecutionIds",
            ] {
                result
                    .as_object_mut()
                    .context("BACKEND_PROTOCOL_ERROR")?
                    .remove(field);
            }
            crate::jobs::purge_deleted_jobs(self).await?;
        }
        if method == "runs.cancel" {
            if let Some(jobs) = result["jobs"].as_array() {
                for job in jobs {
                    if let Some(id) = job["id"].as_str() {
                        self.execution.cancel(id).await;
                    }
                }
            }
        }
        if matches!(method, "interactions.respond" | "interactions.decide") {
            // Domain acceptance is already durable at the backend. Preserve
            // its exact safe result before any local continuation write so a
            // failed SQLite save can be repaired from this operation record
            // without resolving the human request a second time.
            self.persist_accepted_interaction_result(
                method,
                &org,
                projection_account.as_deref().unwrap(),
                p,
                &result,
            )?;
            // Both branches of an approval are accepted human responses. A
            // rejection commonly leads to revision feedback, so withholding a
            // continuation there strands the same run just as surely as a
            // missing continuation after an ordinary answer.
            self.attach_follow_continuation(
                &org,
                "accepted_interaction",
                Some(required(p, "requestId")?),
                &mut result,
            )
            .await?;
            self.activate_ui_follow(&org, &result).await?;
            self.presentation.delete_entities(
                &org,
                projection_account.as_deref().unwrap(),
                "request",
                &[required(p, "requestId")?],
            )?;
        }
        Ok(result)
    }

    fn persist_accepted_interaction_result(
        &self,
        method: &str,
        org: &str,
        account: &str,
        params: &Value,
        result: &Value,
    ) -> Result<()> {
        if !accepted_interaction_result(result) {
            return Ok(());
        }
        let key = required(params, "idempotencyKey")?;
        let journal_key = state::json_digest(&json!({
            "organizationId":org,
            "accountSubject":account,
            "idempotencyKey":key,
        }));
        let path = self
            .dir
            .join("operations")
            .join(format!("{journal_key}.json"));
        let digest = state::json_digest(&json!({
            "method":method,
            "params":params,
            "organizationId":org,
            "accountSubject":account,
        }));
        if path.exists() {
            let existing: Value = state::read_json(&path)?;
            ensure!(existing["digest"] == digest, "IDEMPOTENCY_CONFLICT");
        }
        state::write_json(
            &path,
            &json!({
                "digest":digest,
                "method":method,
                "cachedAt":state::now(),
                "executionId":result.get("executionId").cloned().or_else(|| result.pointer("/execution/id").cloned()),
                "result":result,
            }),
        )
    }

    async fn attach_monitoring_observation(
        &self,
        org: &str,
        run: &str,
        result: &mut Value,
    ) -> Result<()> {
        let account = self.auth.credential(org).await?.subject;
        let installation = self.auth.installation_id().await?;
        let follow = self
            .follow
            .monitoring_observation(org, &account, &installation, run)?;
        let recovery = self
            .recovery
            .monitoring_observation(org, &account, &installation, run)?;
        let details = result
            .as_object_mut()
            .context("BACKEND_PROTOCOL_ERROR")?
            .entry("details")
            .or_insert_with(|| json!({}))
            .as_object_mut()
            .context("BACKEND_PROTOCOL_ERROR")?;
        ensure!(
            !details.contains_key("monitoring"),
            "BACKEND_PROTOCOL_ERROR"
        );
        details.insert(
            "monitoring".into(),
            json!({
                "schemaVersion":"loomex.monitoring-observation/v1",
                "runId":run,
                "guarantee":"none",
                "follow":follow,
                "recovery":recovery,
                "limitations":[
                    "host_hook_delivery_is_host_managed",
                    "recovery_records_are_prior_runner_journal_evidence",
                    "fresh_host_recovery_verification_is_required"
                ]
            }),
        );
        Ok(())
    }

    /// A `runs.wait` request is a bounded *semantic* wait. The backend wakes
    /// as soon as an event is recorded, including provider activity. Returning
    /// every such event to the model causes a tight tool loop and makes an
    /// active execution look like a natural point to end the chat turn. The
    /// runner owns this coalescing because it is below both MCP and any host
    /// lifecycle integration and therefore behaves the same for every client.
    async fn wait_for_meaningful_run_update(&self, org: &str, params: &Value) -> Result<Value> {
        let requested = params
            .get("timeoutSeconds")
            .and_then(Value::as_u64)
            .unwrap_or(30)
            .clamp(1, 45);
        let deadline = Instant::now() + Duration::from_secs(requested);
        let mut request = params.clone();

        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            // The backend accepts seconds. Never issue a zero-second read as
            // a substitute for a wait while time remains.
            let timeout = remaining.as_secs().clamp(1, 45);
            request["timeoutSeconds"] = json!(timeout);
            let (verb, route, body) = backend_route("runs.wait", &request)?;
            let result = self.backend(org, &verb, &route, body, None).await?;
            if !automated_progress_only(&result) || Instant::now() >= deadline {
                return Ok(result);
            }

            let Some(sequence) = result.get("latestSequence").and_then(Value::as_u64) else {
                // A malformed response is not safe to hide from the caller.
                return Ok(result);
            };
            let current = request
                .get("afterSequence")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            if sequence <= current {
                return Ok(result);
            }
            request["afterSequence"] = json!(sequence);
        }
    }

    async fn attach_follow_continuation(
        &self,
        org: &str,
        trigger: &str,
        request_id: Option<&str>,
        result: &mut Value,
    ) -> Result<()> {
        let run = result
            .pointer("/execution/id")
            .and_then(Value::as_str)
            .or_else(|| result.get("executionId").and_then(Value::as_str))
            .or_else(|| result.get("runId").and_then(Value::as_str))
            .map(str::to_owned);
        let Some(run) = run else { return Ok(()) };
        if trigger == "accepted_interaction" && !accepted_interaction_result(result) {
            return Ok(());
        }
        let account = self.auth.credential(org).await?.subject;
        let installation = self.auth.installation_id().await?;
        let receipt = self.follow.issue_continuation(
            org,
            &account,
            &installation,
            &run,
            trigger,
            request_id,
        )?;
        let details = result
            .as_object_mut()
            .context("BACKEND_PROTOCOL_ERROR")?
            .entry("details")
            .or_insert_with(|| json!({}));
        let details = details.as_object_mut().context("BACKEND_PROTOCOL_ERROR")?;
        details.insert(
            "followContinuation".into(),
            json!({
                "schemaVersion":"loomex.follow-session.continuation/v1",
                "runId":run,
                "source":"generated_markdown",
                "receipt":receipt,
                "trigger":trigger,
                "requestId":request_id,
            }),
        );
        let identity = if trigger == "accepted_interaction" {
            format!(
                "follow:{run}:{}",
                request_id.context("BACKEND_PROTOCOL_ERROR")?
            )
        } else {
            format!("follow:{run}:run_started")
        };
        self.register_result_delivery(org, &identity, result)
            .await?;
        Ok(())
    }

    async fn register_result_delivery(
        &self,
        org: &str,
        identity: &str,
        result: &Value,
    ) -> Result<Value> {
        let issued = result
            .pointer("/details/followContinuation")
            .cloned()
            .context("DELIVERY_NOT_READY")?;
        let continuation = json!({
            "kind":"follow",
            "schemaVersion":issued["schemaVersion"],
            "runId":issued["runId"],
            "receipt":issued["receipt"],
            "trigger":issued["trigger"],
            "requestId":issued.get("requestId").cloned().unwrap_or(Value::Null),
            "requestStatus":result.get("requestStatus").cloned().unwrap_or(Value::Null),
        });
        let account = self.auth.credential(org).await?.subject;
        self.presentation
            .register_delivery(org, &account, identity, &continuation)
    }

    async fn delivery_get_or_derive(&self, org: &str, p: &Value) -> Result<Value> {
        let identity = required(p, "identity")?;
        let account = self.auth.credential(org).await?.subject;
        match self
            .presentation
            .dispatch(org, &account, "presentation.delivery.get", p)
        {
            Ok(_) => {
                self.presentation
                    .import_legacy_delivery(org, &account, identity)?;
                return self
                    .presentation
                    .dispatch(org, &account, "presentation.delivery.get", p);
            }
            Err(error) if error.to_string() == "DELIVERY_NOT_READY" => {}
            Err(error) => return Err(error),
        }
        if let Some(handoff_ref) = identity.strip_prefix("start:") {
            ensure!(Uuid::parse_str(handoff_ref).is_ok(), "INVALID_REQUEST");
            let (_, record) = self.load_start_handoff(org, handoff_ref).await?;
            ensure!(
                matches!(
                    Self::start_handoff_lifecycle(&record),
                    "approved" | "committing" | "committed"
                ),
                "DELIVERY_NOT_READY"
            );
            let continuation = json!({
                "kind":"start",
                "schemaVersion":"loomex.start-continuation/v1",
                "handoffRef":handoff_ref,
            });
            self.presentation
                .register_delivery(org, &account, identity, &continuation)?;
        } else if let Some(request_id) = identity.strip_prefix("question:") {
            ensure!(Uuid::parse_str(request_id).is_ok(), "INVALID_REQUEST");
            let (verb, route, body) =
                backend_route("interactions.get", &json!({"requestId":request_id}))?;
            let result = self.backend(org, &verb, &route, body, None).await?;
            let request = result
                .get("humanRequest")
                .and_then(Value::as_object)
                .context("DELIVERY_NOT_READY")?;
            ensure!(
                request.get("id").and_then(Value::as_str) == Some(request_id)
                    && request.get("status").and_then(Value::as_str) == Some("pending"),
                "DELIVERY_NOT_READY"
            );
            let channel = request
                .get("answerChannel")
                .and_then(Value::as_str)
                .or_else(|| {
                    request
                        .get("inputSpec")
                        .and_then(|value| value.get("answerChannel"))
                        .and_then(Value::as_str)
                });
            ensure!(channel == Some("chat"), "DELIVERY_NOT_READY");
            let schema_digest = request
                .get("schemaDigest")
                .and_then(Value::as_str)
                .context("DELIVERY_NOT_READY")?;
            let continuation = json!({
                "kind":"question",
                "schemaVersion":"loomex.question-continuation/v1",
                "requestId":request_id,
                "schemaDigest":schema_digest,
            });
            self.presentation
                .register_delivery(org, &account, identity, &continuation)?;
        } else if let Some(rest) = identity.strip_prefix("follow:") {
            let (run, trigger) = rest.split_once(':').context("INVALID_REQUEST")?;
            ensure!(Uuid::parse_str(run).is_ok(), "INVALID_REQUEST");
            if ["follow_requested", "run_started"].contains(&trigger) {
                let (verb, route, body) = backend_route("runs.get", &json!({"runId":run}))?;
                let result = self.backend(org, &verb, &route, body, None).await?;
                ensure!(
                    result.pointer("/execution/id").and_then(Value::as_str) == Some(run),
                    "DELIVERY_NOT_READY"
                );
                let installation = self.auth.installation_id().await?;
                let receipt = self
                    .follow
                    .issued_continuation(org, &account, &installation, run, "run_commit", None)?
                    .context("DELIVERY_NOT_READY")?;
                let continuation = json!({
                    "kind":"follow",
                    "schemaVersion":"loomex.follow-session.continuation/v1",
                    "runId":run,
                    "receipt":receipt,
                    "trigger":"run_commit",
                    "requestId":Value::Null,
                    "requestStatus":Value::Null,
                });
                self.presentation
                    .register_delivery(org, &account, identity, &continuation)?;
            } else {
                // Earlier runner versions minted the accepted-interaction
                // receipt but had no independent delivery row. Recover only
                // after an owner-scoped request read confirms this exact
                // resolved request still belongs to the specified run.
                ensure!(Uuid::parse_str(trigger).is_ok(), "INVALID_REQUEST");
                let request_id = trigger;
                let (verb, route, body) =
                    backend_route("interactions.get", &json!({"requestId":request_id}))?;
                let result = self.backend(org, &verb, &route, body, None).await?;
                let request = result
                    .get("humanRequest")
                    .and_then(Value::as_object)
                    .context("DELIVERY_NOT_READY")?;
                let request_status = request
                    .get("status")
                    .and_then(Value::as_str)
                    .context("DELIVERY_NOT_READY")?;
                ensure!(
                    request.get("id").and_then(Value::as_str) == Some(request_id)
                        && matches!(
                            request_status,
                            "resolved"
                                | "completed"
                                | "answered"
                                | "accepted"
                                | "approved"
                                | "rejected"
                        ),
                    "DELIVERY_NOT_READY"
                );
                let run_ids = [
                    request
                        .get("execution")
                        .and_then(|execution| execution.get("id"))
                        .and_then(Value::as_str),
                    result.get("executionId").and_then(Value::as_str),
                    result.pointer("/execution/id").and_then(Value::as_str),
                ];
                ensure!(
                    run_ids.iter().any(Option::is_some)
                        && run_ids
                            .into_iter()
                            .flatten()
                            .all(|candidate| candidate == run),
                    "DELIVERY_NOT_READY"
                );
                let installation = self.auth.installation_id().await?;
                let receipt = self
                    .follow
                    .issued_continuation(
                        org,
                        &account,
                        &installation,
                        run,
                        "accepted_interaction",
                        Some(request_id),
                    )?
                    .context("DELIVERY_NOT_READY")?;
                let continuation = json!({
                    "kind":"follow",
                    "schemaVersion":"loomex.follow-session.continuation/v1",
                    "runId":run,
                    "receipt":receipt,
                    "trigger":"accepted_interaction",
                    "requestId":request_id,
                    "requestStatus":request_status,
                });
                self.presentation
                    .register_delivery(org, &account, identity, &continuation)?;
            }
        } else {
            bail!("INVALID_REQUEST");
        }
        self.presentation
            .import_legacy_delivery(org, &account, identity)?;
        self.presentation
            .dispatch(org, &account, "presentation.delivery.get", p)
    }

    /// Record a runner-issued app handoff before returning it to the UI. The
    /// caller cannot select its workspace or identity: both come from the
    /// sealed run binding created at commit time. The record is pending until
    /// an exact associated run-wait call binds it to a native Codex session;
    /// an app message alone must not make a later unrelated Stop callback
    /// authoritative.
    async fn activate_ui_follow(&self, org: &str, result: &Value) -> Result<()> {
        let run = result
            .pointer("/execution/id")
            .and_then(Value::as_str)
            .or_else(|| result.get("executionId").and_then(Value::as_str))
            .or_else(|| result.get("runId").and_then(Value::as_str))
            .context("BACKEND_PROTOCOL_ERROR")?;
        let receipt = result
            .pointer("/details/followContinuation/receipt")
            .and_then(Value::as_str)
            .context("BACKEND_PROTOCOL_ERROR")?;
        let request_id = result
            .pointer("/details/followContinuation/requestId")
            .and_then(Value::as_str);
        let account = self.auth.credential(org).await?.subject;
        let installation = self.auth.installation_id().await?;
        self.follow
            .activate_ui_handoff(org, &account, &installation, run, receipt, request_id)
    }

    async fn restore_cached_follow_continuation(
        &self,
        org: Option<&str>,
        method: &str,
        params: &Value,
        mut result: Value,
    ) -> Result<Value> {
        let trigger = match method {
            "runs.commit" => "run_commit",
            "interactions.respond" => "accepted_interaction",
            "interactions.decide" => "accepted_interaction",
            _ => return Ok(result),
        };
        let run = result
            .pointer("/execution/id")
            .and_then(Value::as_str)
            .or_else(|| result.get("executionId").and_then(Value::as_str))
            .or_else(|| result.get("runId").and_then(Value::as_str))
            .map(str::to_owned);
        let Some(run) = run else { return Ok(result) };
        let existing = result
            .pointer("/details/followContinuation/receipt")
            .and_then(Value::as_str);
        let org = org.context("ORGANIZATION_REQUIRED")?;
        if existing.is_some() {
            if trigger == "accepted_interaction" {
                let request = params
                    .get("requestId")
                    .and_then(Value::as_str)
                    .context("BACKEND_PROTOCOL_ERROR")?;
                self.register_result_delivery(org, &format!("follow:{run}:{request}"), &result)
                    .await?;
            }
            return Ok(result);
        }
        let account = self.auth.credential(org).await?.subject;
        let installation = self.auth.installation_id().await?;
        let request_id = (trigger == "accepted_interaction")
            .then(|| params.get("requestId").and_then(Value::as_str))
            .flatten();
        if trigger == "accepted_interaction"
            && (!accepted_interaction_result(&result)
                || result.get("requestId").and_then(Value::as_str) != request_id)
        {
            return Ok(result);
        }
        if trigger == "run_commit"
            && (result.get("preparationId").and_then(Value::as_str)
                != params.get("preparationId").and_then(Value::as_str)
                || Uuid::parse_str(&run).is_err())
        {
            return Ok(result);
        }
        let receipt = if let Some(receipt) = self.follow.issued_continuation(
            org,
            &account,
            &installation,
            &run,
            trigger,
            request_id,
        )? {
            receipt
        } else {
            // The durable idempotency record proves this exact mutation was
            // accepted. A previous runner might have lost the response before
            // it wrote the receipt, so repair that one local delivery fact;
            // do not reissue the backend mutation or execute any workflow.
            self.follow.issue_continuation(
                org,
                &account,
                &installation,
                &run,
                trigger,
                request_id,
            )?
        };
        let details = result
            .as_object_mut()
            .context("BACKEND_PROTOCOL_ERROR")?
            .entry("details")
            .or_insert_with(|| json!({}));
        let details = details.as_object_mut().context("BACKEND_PROTOCOL_ERROR")?;
        details.insert(
            "followContinuation".into(),
            json!({
                "schemaVersion":"loomex.follow-session.continuation/v1",
                "runId":run,
                "source":"generated_markdown",
                "receipt":receipt,
                "trigger":trigger,
                "requestId":request_id,
            }),
        );
        if trigger == "accepted_interaction" {
            let request = request_id.context("BACKEND_PROTOCOL_ERROR")?;
            self.register_result_delivery(org, &format!("follow:{run}:{request}"), &result)
                .await?;
        }
        Ok(result)
    }
    async fn prepare(&self, method: &str, org: &str, p: &Value) -> Result<Value> {
        if self.execution.is_draining() {
            bail!("RUNNER_NOT_READY")
        }
        let workspace = self
            .granted(Path::new(required(p, "workspacePath")?), org)
            .await?;
        let install = self.auth.installation_id().await?;
        let account = self.auth.credential(org).await?.subject;
        let providers = provider_snapshot()?;
        let mut body = p.clone();
        let map = body.as_object_mut().unwrap();
        map.remove("idempotencyKey");
        map.insert("workspacePath".into(), json!(workspace));
        map.insert("installationId".into(), json!(install));
        map.insert("executionPolicy".into(), json!("host_user/v1"));
        let user_config = map.remove("providerConfiguration").unwrap_or(json!({}));
        map.insert(
            "providerConfiguration".into(),
            json!({"requested":user_config,"installed":providers}),
        );
        map.entry("inputs").or_insert(json!({}));
        let mut result = self
            .backend(
                org,
                "POST",
                match method {
                    "builder.prepare" => "v2/workflow-builder/prepare/",
                    "editor.prepare" => "v2/workflow-edit/prepare/",
                    _ => "v2/executions/prepare/",
                },
                Some(body),
                p["idempotencyKey"].as_str(),
            )
            .await?;
        let preparation = required(&result, "preparationId")?.to_owned();
        Uuid::parse_str(&preparation)?;
        let record_path = self
            .dir
            .join("preparations")
            .join(format!("{preparation}.json"));
        let confirmation = if record_path.exists() {
            required(&state::read_json::<Value>(&record_path)?, "confirmationKey")?.to_owned()
        } else {
            Uuid::new_v4().to_string()
        };
        result["confirmationKey"] = json!(confirmation);
        let catalog: Value =
            serde_json::from_str(include_str!("../contracts/method-catalog.json"))?;
        let output_schema = &catalog["methods"]
            .as_array()
            .context("INTERNAL")?
            .iter()
            .find(|entry| entry["name"] == method)
            .context("INTERNAL")?["outputSchema"];
        let sealed = normalize_catalog_output(result, output_schema)?;
        state::write_json(
            &record_path,
            &json!({"operation":method,"organizationId":org,"accountSubject":account,"installationId":install,"workspacePath":workspace,"bindingDigest":sealed["bindingDigest"],"binding":sealed["binding"],"confirmationKey":confirmation,"providers":providers,"review":sealed}),
        )?;
        Ok(sealed)
    }
    async fn preparation_get(&self, org: &str, p: &Value) -> Result<Value> {
        let preparation = required(p, "preparationId")?;
        Uuid::parse_str(preparation).map_err(|_| anyhow::anyhow!("INVALID_REQUEST"))?;
        let path = self
            .dir
            .join("preparations")
            .join(format!("{preparation}.json"));
        let record: Value =
            state::read_json(&path).map_err(|_| anyhow::anyhow!("PREPARATION_NOT_FOUND"))?;
        let (account, install) = self.auth.current_child_identity(org).await?;
        if record["organizationId"] != org
            || record["accountSubject"] != account
            || record["installationId"] != install
        {
            bail!("PREPARATION_NOT_FOUND")
        }
        let operation = record["operation"]
            .as_str()
            .filter(|operation| {
                ["runs.prepare", "builder.prepare", "editor.prepare"].contains(operation)
            })
            .context("PREPARATION_INVALID")?;
        let stale = |reason: &str, next_action: &str| json!({"status":"stale","operation":operation,"preparationId":preparation,"reason":reason,"nextAction":next_action});
        if record.get("commitAuthorization").is_some() {
            // A sealed preparation is never usable for another commit.  Once the
            // original commit response is durable, however, its execution is a
            // safe recovery destination for a restored presentation session.
            // Keep this projection deliberately narrow: the execution still has
            // to be read authoritatively by the caller before it is displayed.
            let mut stale = stale("commit_started", "reconcile_operation");
            if let Some(execution_id) = record["commitResult"]["execution"]["id"]
                .as_str()
                .or_else(|| record["commitResult"]["executionId"].as_str())
            {
                if Uuid::parse_str(execution_id).is_ok() {
                    stale["executionId"] = json!(execution_id);
                }
            }
            return Ok(stale);
        }
        let review = record["review"]
            .as_object()
            .map(|_| record["review"].clone())
            .unwrap_or(Value::Null);
        if review.is_null()
            || review["preparationId"] != preparation
            || review["bindingDigest"] != record["bindingDigest"]
            || review["binding"] != record["binding"]
            || review["confirmationKey"] != record["confirmationKey"]
        {
            return Ok(stale("record_invalid", "prepare_again"));
        }
        if review["expiresAt"]
            .as_u64()
            .is_some_and(|expires| expires <= state::now())
            || (!review["expiresAt"].is_null() && review["expiresAt"].as_u64().is_none())
        {
            return Ok(stale("expired", "prepare_again"));
        }
        let catalog: Value =
            serde_json::from_str(include_str!("../contracts/method-catalog.json"))?;
        let schema = &catalog["methods"]
            .as_array()
            .context("INTERNAL")?
            .iter()
            .find(|entry| entry["name"] == operation)
            .context("INTERNAL")?["outputSchema"]["oneOf"][0];
        if validate_params(&review, schema).is_err() {
            return Ok(stale("record_invalid", "prepare_again"));
        }
        let Some(workspace) = record["workspacePath"]
            .as_str()
            .filter(|workspace| !workspace.is_empty())
        else {
            return Ok(stale("record_invalid", "prepare_again"));
        };
        let binding = &review["binding"];
        if binding["organizationId"] != org
            || binding["runnerId"] != account
            || binding["installationId"] != install
            || binding["workspacePath"] != workspace
            || ["workflowId", "versionId"].iter().any(|field| {
                binding[*field]
                    .as_str()
                    .is_none_or(|id| Uuid::parse_str(id).is_err())
            })
        {
            return Ok(stale("record_invalid", "prepare_again"));
        }
        if !record["providers"].is_object() {
            return Ok(stale("record_invalid", "prepare_again"));
        }
        if self
            .public
            .lock()
            .await
            .require_grant(Path::new(workspace), org, &install)
            .is_err()
        {
            return Ok(stale("workspace_changed", "prepare_again"));
        }
        if !provider_snapshot().is_ok_and(|providers| providers == record["providers"]) {
            return Ok(stale("provider_changed", "prepare_again"));
        }
        Ok(json!({"status":"valid","operation":operation,"preparation":review}))
    }

    /// Seal an exact preparation review.  Issuing a handoff deliberately does
    /// not authorize Start: only a subsequent UI approval records that gesture.
    async fn issue_run_start_handoff(&self, org: &str, p: &Value) -> Result<Value> {
        let preparation = required(p, "preparationId")?;
        let account = self.auth.credential(org).await?.subject;
        let installation = self.auth.installation_id().await?;
        let requested_identity = state::json_digest(&json!({
            "organizationId":org,
            "accountSubject":account,
            "installationId":installation,
            "preparationId":p["preparationId"],
            "bindingDigest":p["bindingDigest"],
            "confirmationKey":p["confirmationKey"],
            "idempotencyKey":p["idempotencyKey"],
        }));
        if let Some((_, existing)) = self.find_start_handoff_by_issue_key(
            org,
            &account,
            &installation,
            required(p, "idempotencyKey")?,
        )? && existing["issueIdentity"] != requested_identity
        {
            bail!("IDEMPOTENCY_CONFLICT");
        }
        let status = self
            .preparation_get(org, &json!({"preparationId": preparation}))
            .await?;
        ensure!(status["status"] == "valid", "PRECONDITION_FAILED");
        let review = status["preparation"]
            .as_object()
            .context("PRECONDITION_FAILED")?;
        ensure!(
            review.get("preparationId") == Some(&p["preparationId"])
                && review.get("bindingDigest") == Some(&p["bindingDigest"])
                && review.get("confirmationKey") == Some(&p["confirmationKey"]),
            "PRECONDITION_FAILED"
        );
        let issue_identity = requested_identity;
        let reservation = json!({
            "organizationId":org,
            "accountSubject":account,
            "installationId":installation,
            "preparationId":p["preparationId"],
            "bindingDigest":p["bindingDigest"],
        });
        let reservation_lock = Self::handoff_lock_from(
            &self.preparation_handoff_locks,
            &state::json_digest(&reservation),
        )?;
        let _reservation_guard = reservation_lock.lock().await;
        if let Some((_, existing)) = self.find_start_handoff_by_issue_key(
            org,
            &account,
            &installation,
            required(p, "idempotencyKey")?,
        )? {
            if existing["issueIdentity"] != issue_identity {
                bail!("IDEMPOTENCY_CONFLICT");
            }
            if Self::start_handoff_lifecycle(&existing) != "prepared" {
                bail!("START_HANDOFF_PREPARATION_RESERVED");
            }
            return self.start_handoff_projection(&existing);
        }
        if let Some((_, existing)) = self.find_reserved_start_handoff(&reservation)? {
            if existing["issueIdempotencyKey"] == p["idempotencyKey"]
                && existing["issueIdentity"] != issue_identity
            {
                bail!("IDEMPOTENCY_CONFLICT");
            }
            if Self::start_handoff_lifecycle(&existing) != "prepared" {
                bail!("START_HANDOFF_PREPARATION_RESERVED");
            }
            return self.start_handoff_projection(&existing);
        }
        let handoff_ref = Uuid::new_v4().to_string();
        let record = json!({
            "schemaVersion":"loomex.run-start-handoff/v2",
            "handoffRef":handoff_ref,
            "organizationId":org,
            "accountSubject":account,
            "installationId":installation,
            "preparationId":p["preparationId"],
            "bindingDigest":p["bindingDigest"],
            "binding":review["binding"],
            // This immutable review includes the confirmation key, but it is
            // private runner state and is never projected by `get`.
            "review":review,
            "commit":{
                "preparationId":p["preparationId"],
                "bindingDigest":p["bindingDigest"],
                "confirmationKey":p["confirmationKey"],
                // Keep the caller's original durable idempotency key for the
                // eventual backend commit. Approval never gets to replace it.
                "idempotencyKey":p["idempotencyKey"],
            },
            "lifecycle":"prepared",
            "approvalObserved":false,
            "issueIdempotencyKey":p["idempotencyKey"],
            "issueIdentity":issue_identity,
            "issuedAt":state::now(),
        });
        state::write_json(
            &self
                .dir
                .join("start-handoffs")
                .join(format!("{handoff_ref}.json")),
            &record,
        )?;
        self.start_handoff_projection(&record)
    }

    fn find_reserved_start_handoff(&self, reservation: &Value) -> Result<Option<(PathBuf, Value)>> {
        let directory = self.dir.join("start-handoffs");
        let entries = match std::fs::read_dir(&directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        for entry in entries {
            let path = entry?.path();
            if path.extension().and_then(|value| value.to_str()) != Some("json") {
                continue;
            }
            let record: Value = match state::read_json(&path) {
                Ok(record) => record,
                Err(_) => continue,
            };
            if record["schemaVersion"] == "loomex.run-start-handoff/v2"
                && record["organizationId"] == reservation["organizationId"]
                && record["accountSubject"] == reservation["accountSubject"]
                && record["installationId"] == reservation["installationId"]
                && record["preparationId"] == reservation["preparationId"]
                && record["bindingDigest"] == reservation["bindingDigest"]
                && matches!(
                    Self::start_handoff_lifecycle(&record),
                    "prepared" | "approved" | "committing"
                )
            {
                return Ok(Some((path, record)));
            }
        }
        Ok(None)
    }

    fn find_start_handoff_by_issue_key(
        &self,
        org: &str,
        account: &str,
        installation: &str,
        idempotency_key: &str,
    ) -> Result<Option<(PathBuf, Value)>> {
        let directory = self.dir.join("start-handoffs");
        let entries = match std::fs::read_dir(&directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        for entry in entries {
            let path = entry?.path();
            let record: Value = match state::read_json(&path) {
                Ok(record) => record,
                Err(_) => continue,
            };
            if record["schemaVersion"] == "loomex.run-start-handoff/v2"
                && record["organizationId"] == org
                && record["accountSubject"] == account
                && record["installationId"] == installation
                && record["issueIdempotencyKey"] == idempotency_key
            {
                return Ok(Some((path, record)));
            }
        }
        Ok(None)
    }

    fn start_handoff_lock(&self, handoff_ref: &str) -> Result<Arc<Mutex<()>>> {
        Self::handoff_lock_from(&self.start_handoff_locks, handoff_ref)
    }

    fn preparation_handoff_lock(&self, record: &Value) -> Result<Arc<Mutex<()>>> {
        let key = state::json_digest(&json!({
            "organizationId":record["organizationId"],
            "accountSubject":record["accountSubject"],
            "installationId":record["installationId"],
            "preparationId":record["preparationId"],
            "bindingDigest":record["bindingDigest"],
        }));
        Self::handoff_lock_from(&self.preparation_handoff_locks, &key)
    }

    fn handoff_lock_from(
        source: &std::sync::Mutex<HashMap<String, std::sync::Weak<Mutex<()>>>>,
        key: &str,
    ) -> Result<Arc<Mutex<()>>> {
        let mut locks = source.lock().map_err(|_| anyhow::anyhow!("INTERNAL"))?;
        locks.retain(|_, lock| lock.strong_count() > 0);
        let lock = locks
            .get(key)
            .and_then(std::sync::Weak::upgrade)
            .unwrap_or_else(|| Arc::new(Mutex::new(())));
        locks.insert(key.to_owned(), Arc::downgrade(&lock));
        Ok(lock)
    }

    async fn load_start_handoff(&self, org: &str, handoff_ref: &str) -> Result<(PathBuf, Value)> {
        Uuid::parse_str(handoff_ref).map_err(|_| anyhow::anyhow!("START_HANDOFF_NOT_FOUND"))?;
        let path = self
            .dir
            .join("start-handoffs")
            .join(format!("{handoff_ref}.json"));
        let record: Value =
            state::read_json(&path).map_err(|_| anyhow::anyhow!("START_HANDOFF_NOT_FOUND"))?;
        let account = self.auth.credential(org).await?.subject;
        let installation = self.auth.installation_id().await?;
        let valid_v2 = record["schemaVersion"] == "loomex.run-start-handoff/v2"
            && record["handoffRef"] == handoff_ref;
        let valid_v1 = record["schemaVersion"] == "loomex.run-start-handoff/v1"
            && record["ticket"] == handoff_ref;
        ensure!(
            (valid_v1 || valid_v2)
                && record["organizationId"] == org
                && record["accountSubject"] == account
                && record["installationId"] == installation,
            "START_HANDOFF_NOT_FOUND"
        );
        Ok((path, record))
    }

    fn start_handoff_lifecycle(record: &Value) -> &str {
        if record["schemaVersion"] == "loomex.run-start-handoff/v2" {
            record["lifecycle"].as_str().unwrap_or("ambiguous")
        } else {
            match record["status"].as_str() {
                Some("committed") => "committed",
                Some("commit_started") | Some("commit_ambiguous") => "ambiguous",
                _ => "prepared",
            }
        }
    }

    fn start_handoff_expired(record: &Value) -> bool {
        record["schemaVersion"] == "loomex.run-start-handoff/v2"
            && record["review"]["expiresAt"]
                .as_u64()
                .is_some_and(|expires| expires <= state::now())
    }

    fn redact_handoff_secrets(value: &mut Value) {
        match value {
            Value::Object(object) => {
                object.retain(|key, child| {
                    if Self::forbidden_handoff_projection_key(key) {
                        return false;
                    }
                    Self::redact_handoff_secrets(child);
                    true
                });
            }
            Value::Array(items) => {
                for item in items {
                    Self::redact_handoff_secrets(item);
                }
            }
            _ => {}
        }
    }

    fn forbidden_handoff_projection_key(key: &str) -> bool {
        let normalized = key
            .chars()
            .filter(|character| character.is_ascii_alphanumeric())
            .flat_map(char::to_lowercase)
            .collect::<String>();
        ["confirmation", "idempotencykey", "capabilit"]
            .iter()
            .any(|sensitive| normalized.contains(sensitive))
    }

    /// The public projection is intentionally independent of the private
    /// review/commit envelope, which contains the confirmation key.
    fn start_handoff_projection(&self, record: &Value) -> Result<Value> {
        let mut lifecycle = Self::start_handoff_lifecycle(record);
        if lifecycle == "prepared" && Self::start_handoff_expired(record) {
            lifecycle = "expired";
        }
        let is_v2 = record["schemaVersion"] == "loomex.run-start-handoff/v2";
        let next_action = match lifecycle {
            "prepared" if is_v2 => "approve",
            "approved" => "commit",
            "committing" | "ambiguous" => "reconcile",
            _ => "none",
        };
        let preparation = record["preparationId"]
            .as_str()
            .filter(|value| Uuid::parse_str(value).is_ok())
            .context("START_HANDOFF_STALE")?;
        let handoff_ref = record["handoffRef"]
            .as_str()
            .or_else(|| record["ticket"].as_str())
            .context("START_HANDOFF_STALE")?;
        let mut projection = json!({
            "schemaVersion":"loomex.run-start-handoff/v2",
            "handoffRef":handoff_ref,
            "lifecycle":lifecycle,
            "approvalObserved":is_v2 && record["approvalObserved"] == true,
            "nextAction":next_action,
            "preparationId":preparation,
        });
        if lifecycle == "committed" {
            if let Some(run_id) = record["runId"]
                .as_str()
                .filter(|value| Uuid::parse_str(value).is_ok())
            {
                projection["runId"] = json!(run_id);
            }
            if let Some(mut result) = record.get("result").cloned() {
                Self::redact_handoff_secrets(&mut result);
                projection["result"] = result;
            }
        }
        Ok(projection)
    }

    async fn handoff_review_is_valid(&self, org: &str, record: &Value) -> Result<bool> {
        let review = &record["review"];
        let commit = &record["commit"];
        if !review.is_object()
            || !commit.is_object()
            || review["preparationId"] != record["preparationId"]
            || review["bindingDigest"] != record["bindingDigest"]
            || review["binding"] != record["binding"]
            || commit["preparationId"] != record["preparationId"]
            || commit["bindingDigest"] != record["bindingDigest"]
            || commit["confirmationKey"] != review["confirmationKey"]
            || commit["idempotencyKey"]
                .as_str()
                .is_none_or(|key| Uuid::parse_str(key).is_err())
        {
            return Ok(false);
        }
        let current = self
            .preparation_get(org, &json!({"preparationId":record["preparationId"]}))
            .await?;
        Ok(current["status"] == "valid" && current["preparation"] == *review)
    }

    async fn expire_start_handoff(&self, path: &Path, record: &mut Value) -> Result<()> {
        record["lifecycle"] = json!("expired");
        record["updatedAt"] = json!(state::now());
        state::write_json(path, record)
    }

    /// Record the explicit gesture received through an app-only MCP tool.
    /// The local-control socket verifies the peer UID, the MCP server keeps
    /// this method off the model surface, and the handoff remains bound to the
    /// selected organization and sealed preparation. This avoids depending on
    /// an embedded browser's loopback-network policy for authorization.
    async fn approve_run_start_handoff(&self, org: &str, p: &Value) -> Result<Value> {
        let handoff_ref = required(p, "handoffRef")?;
        let lock = self.start_handoff_lock(handoff_ref)?;
        let _guard = lock.lock().await;
        let (path, mut record) = self.load_start_handoff(org, handoff_ref).await?;
        let preparation_lock = self.preparation_handoff_lock(&record)?;
        let _preparation_guard = preparation_lock.lock().await;
        ensure!(
            record["schemaVersion"] == "loomex.run-start-handoff/v2",
            "START_HANDOFF_APPROVAL_REJECTED"
        );
        match Self::start_handoff_lifecycle(&record) {
            "prepared" => {
                ensure!(
                    !self.other_active_start_handoff(&path, &record)?,
                    "START_HANDOFF_PREPARATION_RESERVED"
                );
                if Self::start_handoff_expired(&record)
                    || !self.handoff_review_is_valid(org, &record).await?
                {
                    self.expire_start_handoff(&path, &mut record).await?;
                    bail!("START_HANDOFF_STALE");
                }
                record["lifecycle"] = json!("approved");
                record["approvalObserved"] = json!(true);
                record["approval"] = json!({"approvedAt":state::now()});
                record
                    .as_object_mut()
                    .context("START_HANDOFF_STALE")?
                    .remove("approvalCapabilityDigest");
                record["updatedAt"] = json!(state::now());
                state::write_json(&path, &record)?;
            }
            "approved" | "committed" => bail!("START_HANDOFF_APPROVAL_REJECTED"),
            "expired" => bail!("START_HANDOFF_STALE"),
            "committing" | "ambiguous" => bail!("START_HANDOFF_AMBIGUOUS"),
            _ => bail!("START_HANDOFF_STALE"),
        }
        let account = self.auth.credential(org).await?.subject;
        self.presentation.register_delivery(org, &account, &format!("start:{handoff_ref}"), &json!({
            "kind":"start", "schemaVersion":"loomex.start-continuation/v1", "handoffRef":handoff_ref
        }))?;
        self.start_handoff_projection(&record)
    }

    fn other_active_start_handoff(&self, current_path: &Path, record: &Value) -> Result<bool> {
        let reservation = json!({
            "organizationId":record["organizationId"],
            "accountSubject":record["accountSubject"],
            "installationId":record["installationId"],
            "preparationId":record["preparationId"],
            "bindingDigest":record["bindingDigest"],
        });
        let directory = self.dir.join("start-handoffs");
        let entries = match std::fs::read_dir(&directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error.into()),
        };
        for entry in entries {
            let path = entry?.path();
            if path == current_path {
                continue;
            }
            let sibling: Value = match state::read_json(&path) {
                Ok(sibling) => sibling,
                Err(_) => continue,
            };
            if sibling["schemaVersion"] == "loomex.run-start-handoff/v2"
                && sibling["organizationId"] == reservation["organizationId"]
                && sibling["accountSubject"] == reservation["accountSubject"]
                && sibling["installationId"] == reservation["installationId"]
                && sibling["preparationId"] == reservation["preparationId"]
                && sibling["bindingDigest"] == reservation["bindingDigest"]
                && matches!(
                    Self::start_handoff_lifecycle(&sibling),
                    "approved" | "committing"
                )
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Read a safe projection. This intentionally does not validate or mutate
    /// a preparation, so callers can inspect a failed or ambiguous lifecycle.
    async fn get_run_start_handoff(&self, org: &str, p: &Value) -> Result<Value> {
        let handoff_ref = required(p, "handoffRef")?;
        let (_, record) = self.load_start_handoff(org, handoff_ref).await?;
        self.start_handoff_projection(&record)
    }

    /// Reconcile an interrupted app-side issue using the original issue key.
    /// The key identifies an existing record owned by this organization,
    /// account, and installation only. It cannot recover the private
    /// review/commit envelope or authorize a run. A remounted app can safely
    /// read the resulting prepared handoff and require a new explicit Start gesture.
    async fn restore_run_start_handoff(&self, org: &str, p: &Value) -> Result<Value> {
        let issue_key = required(p, "idempotencyKey")?;
        let account = self.auth.credential(org).await?.subject;
        let installation = self.auth.installation_id().await?;
        let (_, record) = self
            .find_start_handoff_by_issue_key(org, &account, &installation, issue_key)?
            .context("START_HANDOFF_NOT_FOUND")?;
        self.start_handoff_projection(&record)
    }

    /// Consume an approved UI handoff. A network-ambiguous backend commit is
    /// deliberately left ambiguous rather than replayed automatically.
    async fn commit_run_start_handoff(&self, org: &str, p: &Value) -> Result<Value> {
        let handoff_ref = required(p, "handoffRef")?;
        let lock = self.start_handoff_lock(handoff_ref)?;
        let _guard = lock.lock().await;
        let (path, mut record) = self.load_start_handoff(org, handoff_ref).await?;
        if record["schemaVersion"] == "loomex.run-start-handoff/v1" {
            if record["status"] != "committed" {
                bail!("START_HANDOFF_UNAPPROVED");
            }
            let result = self
                .finish_committed_start_handoff(org, &path, &mut record)
                .await?;
            return self.committed_start_handoff_result(&record, result);
        }
        let preparation_lock = self.preparation_handoff_lock(&record)?;
        let _preparation_guard = preparation_lock.lock().await;
        if self.other_active_start_handoff(&path, &record)? {
            bail!("START_HANDOFF_PREPARATION_RESERVED");
        }
        match Self::start_handoff_lifecycle(&record) {
            "committed" => {
                let result = self
                    .finish_committed_start_handoff(org, &path, &mut record)
                    .await?;
                return self.committed_start_handoff_result(&record, result);
            }
            "prepared" => bail!("START_HANDOFF_UNAPPROVED"),
            "expired" => bail!("START_HANDOFF_STALE"),
            "committing" | "ambiguous" => bail!("START_HANDOFF_AMBIGUOUS"),
            "approved" => {}
            _ => bail!("START_HANDOFF_STALE"),
        }
        if Self::start_handoff_expired(&record)
            || !self.handoff_review_is_valid(org, &record).await?
        {
            self.expire_start_handoff(&path, &mut record).await?;
            bail!("START_HANDOFF_STALE");
        }
        record["lifecycle"] = json!("committing");
        record["commitStartedAt"] = json!(state::now());
        state::write_json(&path, &record)?;
        let commit = record["commit"].clone();
        let result = match self.commit("runs.commit", org, &commit).await {
            Ok(result) => result,
            Err(error) => {
                record["lifecycle"] = json!("ambiguous");
                record["lastError"] = json!(error.to_string());
                record["updatedAt"] = json!(state::now());
                state::write_json(&path, &record)?;
                return Err(error);
            }
        };
        let run = match result
            .pointer("/execution/id")
            .and_then(Value::as_str)
            .or_else(|| result.get("executionId").and_then(Value::as_str))
            .or_else(|| result.get("runId").and_then(Value::as_str))
        {
            Some(run) if Uuid::parse_str(run).is_ok() => run,
            _ => {
                record["lifecycle"] = json!("ambiguous");
                record["lastError"] = json!("BACKEND_PROTOCOL_ERROR");
                record["updatedAt"] = json!(state::now());
                state::write_json(&path, &record)?;
                bail!("BACKEND_PROTOCOL_ERROR");
            }
        };
        // The backend has accepted the commit at this point. Persist that fact
        // before any local follow work so a crash or local-store failure can
        // never turn an execution into an unrecoverable `commit_started` ticket.
        record["lifecycle"] = json!("committed");
        record["result"] = result.clone();
        record["runId"] = json!(run);
        record["followActivationState"] = json!("pending");
        record["updatedAt"] = json!(state::now());
        state::write_json(&path, &record)?;
        let result = self
            .finish_committed_start_handoff(org, &path, &mut record)
            .await?;
        self.committed_start_handoff_result(&record, result)
    }

    /// Convert the runner-owned committed record into the v2 public method
    /// result.  Keep the execution result available as data while ensuring the
    /// tool's declared handoff lifecycle is present for every v2 commit path.
    fn committed_start_handoff_result(&self, record: &Value, result: Value) -> Result<Value> {
        let mut projection = self.start_handoff_projection(record)?;
        let execution = result
            .get("execution")
            .cloned()
            .or_else(|| record.pointer("/result/execution").cloned())
            .filter(Value::is_object)
            .context("BACKEND_PROTOCOL_ERROR")?;
        let execution_policy = result
            .get("executionPolicy")
            .and_then(Value::as_str)
            .or_else(|| {
                record
                    .pointer("/result/executionPolicy")
                    .and_then(Value::as_str)
            })
            .context("BACKEND_PROTOCOL_ERROR")?;
        projection["execution"] = execution;
        projection["executionPolicy"] = json!(execution_policy);
        projection["details"] = result
            .get("details")
            .cloned()
            .filter(Value::is_object)
            .unwrap_or_else(|| json!({}));
        Ok(projection)
    }

    /// Rehydrate the local continuation for a committed Start ticket. This
    /// path is deliberately idempotent: the backend commit has already been
    /// made durable, so retrying it may repair follow evidence but never sends
    /// another execution-commit request.
    async fn finish_committed_start_handoff(
        &self,
        org: &str,
        path: &Path,
        record: &mut Value,
    ) -> Result<Value> {
        let result = record
            .get("result")
            .cloned()
            .context("BACKEND_PROTOCOL_ERROR")?;
        let run = result
            .pointer("/execution/id")
            .and_then(Value::as_str)
            .or_else(|| result.get("executionId").and_then(Value::as_str))
            .or_else(|| result.get("runId").and_then(Value::as_str))
            .context("BACKEND_PROTOCOL_ERROR")?;
        if record["runId"].is_null() {
            // Tickets written by the immediately preceding runner revision
            // did not retain this alias. Recover it from their sealed result
            // without touching the backend.
            record["runId"] = json!(run);
        } else {
            ensure!(record["runId"] == run, "BACKEND_PROTOCOL_ERROR");
        }
        let params = json!({"preparationId":record["preparationId"]});
        let result = self
            .restore_cached_follow_continuation(Some(org), "runs.commit", &params, result)
            .await?;
        #[cfg(test)]
        if TEST_START_HANDOFF_FOLLOW_FAILURE.load(Ordering::SeqCst) {
            bail!("START_HANDOFF_FOLLOW_INJECTED");
        }
        let handoff_ref = record["handoffRef"]
            .as_str()
            .or_else(|| record["ticket"].as_str())
            .context("BACKEND_PROTOCOL_ERROR")?;
        let start_continuation = json!({
            "kind":"start",
            "schemaVersion":"loomex.start-continuation/v1",
            "handoffRef":handoff_ref,
        });
        let account = self.auth.credential(org).await?.subject;
        self.presentation.register_delivery(
            org,
            &account,
            &format!("start:{handoff_ref}"),
            &start_continuation,
        )?;
        self.activate_ui_follow(org, &result).await?;
        record["result"] = result.clone();
        record["followActivationState"] = json!("active");
        record["updatedAt"] = json!(state::now());
        state::write_json(path, record)?;
        Ok(result)
    }

    async fn commit(&self, method: &str, org: &str, p: &Value) -> Result<Value> {
        if self.execution.is_draining() {
            bail!("RUNNER_NOT_READY")
        }
        let preparation = required(p, "preparationId")?;
        let record_path = self
            .dir
            .join("preparations")
            .join(format!("{preparation}.json"));
        let mut record: Value =
            state::read_json(&record_path).map_err(|_| anyhow::anyhow!("PRECONDITION_FAILED"))?;
        if record["operation"] != method.replace(".commit", ".prepare")
            || record["organizationId"] != org
            || record["accountSubject"] != self.auth.credential(org).await?.subject
            || record["bindingDigest"] != p["bindingDigest"]
            || record["confirmationKey"] != p["confirmationKey"]
            || record["installationId"] != self.auth.installation_id().await?
        {
            bail!("PRECONDITION_FAILED")
        }
        self.granted(Path::new(required(&record, "workspacePath")?), org)
            .await?;
        if record["providers"] != provider_snapshot()? {
            bail!("PRECONDITION_FAILED")
        }
        // The separate confirmation authorizes this exact preparation before the
        // backend can enqueue a job. A lost response never removes this grant.
        record["commitAuthorization"] = json!({"preparationId":preparation,"bindingDigest":p["bindingDigest"],"idempotencyKey":p["idempotencyKey"],"authorizedAt":state::now()});
        state::write_json(&record_path, &record)?;
        let result = self
            .backend(
                org,
                "POST",
                match method {
                    "builder.commit" => "v2/workflow-builder/commit/",
                    "editor.commit" => "v2/workflow-edit/commit/",
                    _ => "v2/executions/commit/",
                },
                Some(json!({"preparationId":preparation,"bindingDigest":p["bindingDigest"]})),
                p["idempotencyKey"].as_str(),
            )
            .await?;
        if let Some(run) = result["execution"]["id"]
            .as_str()
            .or_else(|| result["id"].as_str())
            .or_else(|| result["executionId"].as_str())
        {
            Uuid::parse_str(run)?;
            state::write_json(
                &self.dir.join("run-bindings").join(format!("{run}.json")),
                &record,
            )?;
        }
        // This is written before returning the commit result. It lets a closed
        // custom UI recover the one execution created by its already-authorized
        // commit without treating the sealed preparation as reusable.
        record["commitResult"] = result.clone();
        state::write_json(&record_path, &record)?;
        Ok(result)
    }
    async fn download(&self, org: &str, p: &Value) -> Result<Value> {
        let id = required(p, "artifactId")?;
        let requested = PathBuf::from(required(p, "destinationPath")?);
        if !requested.is_absolute() {
            bail!("VALIDATION_FAILED")
        }
        let parent = std::fs::canonicalize(requested.parent().context("VALIDATION_FAILED")?)?;
        let dest = parent.join(requested.file_name().context("VALIDATION_FAILED")?);
        if dest.exists() && p["overwrite"] != true {
            bail!("CONFLICT")
        }
        if std::fs::symlink_metadata(&dest).is_ok_and(|m| m.file_type().is_symlink()) {
            bail!("PRECONDITION_FAILED")
        }
        let temp = parent.join(format!(
            ".loomex-download-{}",
            required(p, "idempotencyKey")?
        ));
        let mut output = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&temp)?;
        use sha2::{Digest, Sha256};
        use std::io::Write;
        let mut hash = Sha256::new();
        let mut offset = 0u64;
        let mut expected_checksum: Option<String> = None;
        loop {
            let page = self
                .backend(
                    org,
                    "GET",
                    &format!("v2/artifacts/{id}/content/?offset={offset}&limit=262144"),
                    None,
                    None,
                )
                .await?;
            let checksum = required(&page, "checksumSha256")?;
            if expected_checksum
                .as_deref()
                .is_some_and(|expected| expected != checksum)
            {
                bail!("BACKEND_PROTOCOL_ERROR")
            };
            expected_checksum = Some(checksum.into());
            let bytes = STANDARD.decode(required(&page, "dataBase64")?)?;
            if page["offset"].as_u64() != Some(offset) {
                bail!("BACKEND_PROTOCOL_ERROR")
            };
            output.write_all(&bytes)?;
            hash.update(&bytes);
            offset += bytes.len() as u64;
            if page["nextOffset"].is_null() {
                if page["sizeBytes"].as_u64() != Some(offset) {
                    bail!("BACKEND_PROTOCOL_ERROR")
                };
                break;
            }
            if page["nextOffset"].as_u64() != Some(offset) || bytes.is_empty() {
                bail!("BACKEND_PROTOCOL_ERROR")
            }
        }
        let checksum = hex::encode(hash.finalize());
        if expected_checksum.as_deref() != Some(&checksum) {
            bail!("ARTIFACT_CHECKSUM_MISMATCH")
        };
        output.sync_all()?;
        if p["overwrite"] == true {
            std::fs::rename(&temp, &dest)?
        } else {
            std::fs::hard_link(&temp, &dest)?;
            std::fs::remove_file(&temp)?
        }
        std::fs::File::open(parent)?.sync_all()?;
        Ok(json!({"artifactId":id,"path":dest,"sizeBytes":offset,"checksumSha256":checksum}))
    }
}
fn normalize_output(mut value: Value, schema: &Value) -> Result<Value> {
    let object = value.as_object_mut().context("BACKEND_PROTOCOL_ERROR")?;
    let keys: Vec<String> = object
        .keys()
        .filter(|key| schema["properties"][*key].is_null())
        .cloned()
        .collect();
    let mut extra = serde_json::Map::new();
    for key in keys {
        extra.insert(key.clone(), object.remove(&key).unwrap());
    }
    if !extra.is_empty() {
        // `details` is the schema-sanctioned envelope for backend fields that
        // have not yet been promoted into the public result shape. Callers may
        // also have attached runner-owned facts before normalization (for
        // example, the receipt that authorizes a chat follow-up). Replacing an
        // existing envelope here silently loses those facts. Merge only when
        // the keys are disjoint: accepting a collision would make one side's
        // meaning depend on ordering and could weaken a protocol boundary.
        match object.get_mut("details") {
            Some(Value::Object(details)) => {
                for (key, field) in extra {
                    if details.contains_key(&key) {
                        bail!("BACKEND_PROTOCOL_ERROR")
                    }
                    details.insert(key, field);
                }
            }
            Some(_) => bail!("BACKEND_PROTOCOL_ERROR"),
            None => {
                object.insert("details".into(), Value::Object(extra));
            }
        }
    }
    for key in schema["required"].as_array().unwrap() {
        if !object.contains_key(key.as_str().unwrap()) {
            bail!("BACKEND_PROTOCOL_ERROR")
        }
    }
    Ok(value)
}

/// The backend represents a successfully stored human response as `resolved`.
/// Provider and compatibility paths can additionally surface the older, more
/// specific labels below. These are response outcomes, not the approval value:
/// a rejected approval is still a successfully accepted response that must let
/// the workflow continue to its revision path.
fn accepted_interaction_result(result: &Value) -> bool {
    matches!(
        result.get("requestStatus").and_then(Value::as_str),
        Some("resolved" | "completed" | "answered" | "accepted" | "approved" | "rejected")
    ) && result.get("error").is_none_or(Value::is_null)
}

/// True only for activity which has no required human or model action. Keep
/// this deliberately narrow: unknown event shapes, paginated events, terminal
/// executions, and any exposed interaction are always returned to the caller.
fn automated_progress_only(result: &Value) -> bool {
    let active = !matches!(
        result.pointer("/execution/status").and_then(Value::as_str),
        Some("completed" | "failed" | "canceled")
    );
    let events = match result.get("events").and_then(Value::as_array) {
        Some(events) if !events.is_empty() => events,
        _ => return false,
    };
    active
        && result.get("waitState").and_then(Value::as_str) == Some("automated_progress")
        && result.get("humanRequest").is_none_or(Value::is_null)
        && result.get("hasMoreEvents").and_then(Value::as_bool) == Some(false)
        && events.iter().all(|event| {
            event
                .get("type")
                .or_else(|| event.get("eventType"))
                .and_then(Value::as_str)
                == Some("ai.progress.v1")
        })
}

#[cfg(test)]
mod monitoring_wait_tests {
    use super::automated_progress_only;
    use serde_json::json;

    #[test]
    fn only_hides_complete_non_actionable_provider_progress() {
        let progress = json!({
            "execution":{"status":"running"}, "waitState":"automated_progress",
            "humanRequest":null, "hasMoreEvents":false,
            "events":[{"type":"ai.progress.v1", "sequence":9}], "latestSequence":9
        });
        assert!(automated_progress_only(&progress));

        for changed in [
            json!({"execution":{"status":"running"}, "waitState":"automated_progress", "humanRequest":null, "hasMoreEvents":false, "events":[{"type":"node.completed", "sequence":9}]}),
            json!({"execution":{"status":"running"}, "waitState":"human_action_required", "humanRequest":{"id":"request"}, "hasMoreEvents":false, "events":[{"type":"ai.progress.v1", "sequence":9}]}),
            json!({"execution":{"status":"completed"}, "waitState":null, "humanRequest":null, "hasMoreEvents":false, "events":[{"type":"ai.progress.v1", "sequence":9}]}),
            json!({"execution":{"status":"running"}, "waitState":"automated_progress", "humanRequest":null, "hasMoreEvents":true, "events":[{"type":"ai.progress.v1", "sequence":9}]}),
        ] {
            assert!(!automated_progress_only(&changed));
        }
    }
}
fn normalize_catalog_output(value: Value, output_schema: &Value) -> Result<Value> {
    let object = value.as_object().context("BACKEND_PROTOCOL_ERROR")?;
    let schemas = if let Some(variants) = output_schema["oneOf"].as_array() {
        variants.as_slice()
    } else if output_schema["type"] == "object" {
        std::slice::from_ref(output_schema)
    } else {
        bail!("BACKEND_PROTOCOL_ERROR")
    };
    let schema = schemas
        .iter()
        .find(|schema| {
            schema["required"].as_array().is_some_and(|required| {
                required
                    .iter()
                    .filter_map(Value::as_str)
                    .all(|key| object.contains_key(key))
            }) && schema["properties"].as_object().is_some_and(|properties| {
                properties.iter().all(|(key, property)| {
                    object.get(key).is_none_or(|field| {
                        property
                            .get("const")
                            .is_none_or(|expected| field == expected)
                            && property["enum"]
                                .as_array()
                                .is_none_or(|options| options.contains(field))
                    })
                })
            })
        })
        .context("BACKEND_PROTOCOL_ERROR")?;
    normalize_output(value, schema)
}
fn required<'a>(p: &'a Value, key: &str) -> Result<&'a str> {
    p[key]
        .as_str()
        .filter(|v| !v.is_empty())
        .context("INVALID_REQUEST")
}
fn account_scoped_method(method: &str) -> bool {
    method.starts_with("presentation.")
        || method.starts_with("recovery.")
        || method.starts_with("follow.session.")
        || method.starts_with("interactions.draft.")
        || matches!(
            method,
            "runs.prepare"
                | "runs.commit"
                | "runs.start_handoff.issue"
                | "runs.start_handoff.restore"
                | "runs.start_handoff.get"
                | "runs.start_handoff.commit"
                | "builder.prepare"
                | "builder.commit"
                | "builder.respond"
                | "builder.finalize"
                | "editor.prepare"
                | "editor.commit"
                | "editor.respond"
                | "editor.finalize"
                | "interactions.respond"
                | "interactions.decide"
        )
}
fn validate_params(p: &Value, schema: &Value) -> Result<()> {
    let map = p.as_object().context("INVALID_REQUEST")?;
    for key in schema["required"].as_array().unwrap() {
        if !map.contains_key(key.as_str().unwrap()) {
            bail!("INVALID_REQUEST")
        }
    }
    for (key, value) in map {
        let s = &schema["properties"][key];
        if s.is_null() {
            bail!("INVALID_REQUEST")
        };
        let type_matches = |kind: &str| match kind {
            "string" => value.is_string(),
            "object" => value.is_object(),
            "integer" => value.as_u64().is_some(),
            "boolean" => value.is_boolean(),
            "null" => value.is_null(),
            "array" => value.as_array().is_some_and(|items| {
                items.len() >= s["minItems"].as_u64().unwrap_or(0) as usize
                    && items.iter().all(|item| {
                        item.as_str()
                            .is_some_and(|text| !text.is_empty() && text.len() <= 160)
                    })
                    && (s["uniqueItems"] != true
                        || items
                            .iter()
                            .enumerate()
                            .all(|(index, item)| !items[..index].contains(item)))
            }),
            _ => false,
        };
        let valid = s["type"]
            .as_str()
            .map(type_matches)
            .or_else(|| {
                s["type"]
                    .as_array()
                    .map(|types| types.iter().filter_map(Value::as_str).any(type_matches))
            })
            .unwrap_or_else(|| s.get("type").is_none());
        if !valid {
            bail!("INVALID_REQUEST")
        };
        if let Some(expected) = s.get("const") {
            if expected != value {
                bail!("INVALID_REQUEST")
            }
        }
        if s["format"] == "uuid" && value.is_string() {
            Uuid::parse_str(value.as_str().unwrap())
                .map_err(|_| anyhow::anyhow!("INVALID_REQUEST"))?;
        }
        if let Some(options) = s["enum"].as_array() {
            if !options.contains(value) {
                bail!("INVALID_REQUEST")
            }
        }
    }
    Ok(())
}
pub fn backend_route(method: &str, p: &Value) -> Result<(String, String, Option<Value>)> {
    let mut body = p.clone();
    for key in [
        "idempotencyKey",
        "workflowId",
        "runId",
        "sessionId",
        "requestId",
        "artifactId",
    ] {
        body.as_object_mut().unwrap().remove(key);
    }
    if method == "runs.list" {
        if let Some(id) = p.get("workflowId") {
            body["workflowId"] = id.clone();
        }
    }
    if method == "workflow.operations.get" {
        body["idempotencyKey"] = p
            .get("idempotencyKey")
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("INVALID_REQUEST"))?;
    }
    let (verb, route) = match method {
        "workflows.list" => ("GET", "v1/workflows/".into()),
        "workflows.get" => (
            "GET",
            format!("v1/workflows/{}/", required(p, "workflowId")?),
        ),
        "workflows.create" if p.get("definition").is_some() => {
            ("POST", "v2/workflow-drafts/".into())
        }
        "workflows.create" => ("POST", "v2/workflows/".into()),
        "workflows.update" => (
            "POST",
            format!("v1/workflows/{}/draft/", required(p, "workflowId")?),
        ),
        "workflow.operations.get" => ("POST", "v2/workflow-operations/get/".into()),
        "workflows.validate" | "builder.validate" => ("POST", "v1/workflows/validate/".into()),
        "workflows.publish" => (
            "POST",
            format!("v1/workflows/{}/publish/", required(p, "workflowId")?),
        ),
        "workflows.activate" => (
            "POST",
            format!(
                "v1/workflow-versions/{}/activate/",
                required(p, "versionId")?
            ),
        ),
        "builder.catalog" => ("GET", "v2/builder/catalog/".into()),
        "builder.create" => ("POST", "v1/workflow-builder/sessions/".into()),
        "builder.get" => (
            "GET",
            format!(
                "v1/workflow-builder/sessions/{}/",
                required(p, "sessionId")?
            ),
        ),
        "builder.respond" => (
            "POST",
            format!(
                "v1/workflow-builder/sessions/{}/responses/",
                required(p, "sessionId")?
            ),
        ),
        "builder.finalize" => (
            "POST",
            format!(
                "v1/workflow-builder/sessions/{}/finalize/",
                required(p, "sessionId")?
            ),
        ),
        "editor.create" => {
            body["workflowId"] = p["workflowId"].clone();
            ("POST", "v1/workflow-edit/sessions/".into())
        }
        "editor.respond" => (
            "POST",
            format!(
                "v1/workflow-edit/sessions/{}/responses/",
                required(p, "sessionId")?
            ),
        ),
        "editor.finalize" => (
            "POST",
            format!(
                "v1/workflow-edit/sessions/{}/finalize/",
                required(p, "sessionId")?
            ),
        ),
        "runs.list" => ("GET", "v2/executions/".into()),
        "runs.get" | "runs.wait" | "runs.events" | "runs.result" => {
            if method == "runs.wait" && !body.as_object().unwrap().contains_key("timeoutSeconds") {
                body["timeoutSeconds"] = json!(45)
            }
            ("GET", format!("v1/executions/{}/", required(p, "runId")?))
        }
        "runs.cancel" => (
            "POST",
            format!("v1/executions/{}/cancel/", required(p, "runId")?),
        ),
        "runs.delete" => (
            "POST",
            format!("v1/executions/{}/delete/", required(p, "runId")?),
        ),
        "interactions.list" => (
            "GET",
            if let Some(run) = p["runId"].as_str() {
                format!("v1/executions/{run}/human-requests/")
            } else {
                "v1/human-requests/".into()
            },
        ),
        "interactions.get" => (
            "GET",
            format!("v1/human-requests/{}/", required(p, "requestId")?),
        ),
        "interactions.draft.get" => (
            "GET",
            format!("v1/human-requests/{}/draft/", required(p, "requestId")?),
        ),
        "interactions.draft.update" => (
            "PUT",
            format!("v1/human-requests/{}/draft/", required(p, "requestId")?),
        ),
        "interactions.draft.delete" => (
            "DELETE",
            format!("v1/human-requests/{}/draft/", required(p, "requestId")?),
        ),
        "interactions.respond" | "interactions.decide" => (
            "POST",
            format!("v1/human-requests/{}/resolve/", required(p, "requestId")?),
        ),
        "artifacts.list" => (
            "GET",
            format!("v2/executions/{}/artifacts/", required(p, "runId")?),
        ),
        "artifacts.read" => (
            "GET",
            format!("v2/artifacts/{}/content/", required(p, "artifactId")?),
        ),
        _ => bail!("METHOD_NOT_FOUND"),
    };
    if verb == "GET" {
        let mut query = url::form_urlencoded::Serializer::new(String::new());
        for (k, v) in body.as_object().unwrap() {
            if !v.is_null() {
                query.append_pair(
                    k,
                    &v.as_str()
                        .map(String::from)
                        .unwrap_or_else(|| v.to_string()),
                );
            }
        }
        let q = query.finish();
        Ok((
            verb.into(),
            format!(
                "{route}{}",
                if q.is_empty() {
                    String::new()
                } else {
                    format!("?{q}")
                }
            ),
            None,
        ))
    } else {
        Ok((verb.into(), route, Some(body)))
    }
}
pub fn provider_snapshot() -> Result<Value> {
    provider_snapshot_with(find_executable_result)
}

/// A credential-free, path-free view for local operator diagnostics.  The
/// preparation binding needs the full provider snapshot (including a stable
/// executable identity), but a CLI diagnostic should only say whether the
/// executable can currently be used and why it cannot.
pub fn provider_diagnostics() -> Value {
    // Exercise the same discovery and validation path that preparation uses.
    // A bad explicit provider binding makes `provider_snapshot` fail closed;
    // resolve each adapter below so the operator can still see the state of
    // the other providers.
    let snapshot = provider_snapshot().ok();
    let mut providers = serde_json::Map::new();
    for (provider, adapter) in [
        ("codex", "codex"),
        ("claude", "claude"),
        ("gemini", "gemini"),
        ("antigravity", "agy"),
    ] {
        let configured = provider_executable_variable(adapter)
            .is_some_and(|variable| std::env::var_os(variable).is_some());
        let (available, reason) = match find_executable_result(adapter) {
            Ok(Some(_))
                if snapshot
                    .as_ref()
                    .is_some_and(|value| value.get(provider).is_some()) =>
            {
                (true, "available")
            }
            Ok(Some(_)) => (true, "available"),
            Ok(None) => (false, "not_found"),
            Err(_) if configured => (false, "configured_path_invalid"),
            Err(_) => (false, "unavailable"),
        };
        providers.insert(
            provider.into(),
            json!({"adapter":adapter,"available":available,"reason":reason,"configured":configured}),
        );
    }
    Value::Object(providers)
}
fn provider_snapshot_with(
    mut resolve: impl FnMut(&str) -> Result<Option<PathBuf>>,
) -> Result<Value> {
    let mut providers = serde_json::Map::new();
    for (name, adapter) in [
        ("codex", "codex"),
        ("claude", "claude"),
        // Keep historic Gemini records bound to the official Gemini CLI.
        ("gemini", "gemini"),
        ("antigravity", "agy"),
    ] {
        if let Some(path) = resolve(adapter)? {
            let m = std::fs::metadata(&path)?;
            use sha2::{Digest, Sha256};
            use std::io::Read;
            let mut input = std::fs::File::open(&path)?;
            let mut hasher = Sha256::new();
            let mut buffer = [0; 65536];
            loop {
                let size = input.read(&mut buffer)?;
                if size == 0 {
                    break;
                }
                hasher.update(&buffer[..size]);
            }
            let checksum = hex::encode(hasher.finalize());
            providers.insert(name.into(),json!({"path":path,"adapter":adapter,"checksumSha256":checksum,"sizeBytes":m.len(),"modifiedNanos":m.modified()?.duration_since(std::time::UNIX_EPOCH)?.as_nanos().to_string(),"executionPolicy":"host_user/v1"}));
        }
    }
    Ok(Value::Object(providers))
}
pub fn find_executable(name: &str) -> Option<PathBuf> {
    find_executable_result(name).ok().flatten()
}
fn provider_executable_variable(name: &str) -> Option<&'static str> {
    match name {
        "codex" => Some("LOOMEX_CODEX_EXECUTABLE"),
        "claude" => Some("LOOMEX_CLAUDE_EXECUTABLE"),
        "gemini" => Some("LOOMEX_GEMINI_EXECUTABLE"),
        "agy" => Some("LOOMEX_ANTIGRAVITY_EXECUTABLE"),
        _ => None,
    }
}
fn executable_path(path: &Path, require_canonical: bool) -> Option<PathBuf> {
    if !path.is_absolute() {
        return None;
    }
    let canonical = std::fs::canonicalize(path).ok()?;
    if require_canonical && canonical != path {
        return None;
    }
    let metadata = std::fs::metadata(&canonical).ok()?;
    (metadata.is_file() && metadata.permissions().mode() & 0o111 != 0).then_some(canonical)
}
fn find_executable_result(name: &str) -> Result<Option<PathBuf>> {
    find_executable_with(
        name,
        |variable| std::env::var_os(variable),
        std::env::var_os("PATH"),
    )
}
fn find_executable_with(
    name: &str,
    configured: impl Fn(&str) -> Option<std::ffi::OsString>,
    search_path: Option<std::ffi::OsString>,
) -> Result<Option<PathBuf>> {
    if let Some(variable) = provider_executable_variable(name)
        && let Some(value) = configured(variable)
    {
        return executable_path(Path::new(&value), true)
            .map(Some)
            .context("PROVIDER_UNAVAILABLE");
    }
    let p = Path::new(name);
    if p.is_absolute() {
        return Ok(executable_path(p, false));
    }
    let path = search_path.unwrap_or_default();
    Ok(std::env::split_paths(&path)
        .chain([
            PathBuf::from("/opt/homebrew/bin"),
            PathBuf::from("/usr/local/bin"),
            PathBuf::from("/usr/bin"),
            PathBuf::from("/bin"),
        ])
        .map(|p| p.join(name))
        .find(|p| {
            std::fs::metadata(p).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        })
        .and_then(|p| std::fs::canonicalize(p).ok()))
}
async fn read_spool(dir: &Path, p: &Value) -> Result<Value> {
    use tokio::io::{AsyncReadExt, AsyncSeekExt};
    let id = required(p, "responseRef")?;
    Uuid::parse_str(id)?;
    let mut file = tokio::fs::File::open(dir.join("responses").join(format!("{id}.json"))).await?;
    let meta_path = dir.join("responses").join(format!("{id}.meta.json"));
    if meta_path.exists() {
        let mut metadata: Value = state::read_json(&meta_path)?;
        metadata["lastAccessAt"] = json!(state::now());
        state::write_json(&meta_path, &metadata)?;
    }
    let size = file.metadata().await?.len();
    let offset = p["offset"].as_u64().unwrap_or(0);
    if offset > size {
        bail!("INVALID_REQUEST")
    };
    let limit = p["limit"].as_u64().unwrap_or(262144).clamp(1, 262144);
    file.seek(std::io::SeekFrom::Start(offset)).await?;
    let mut buf = vec![0; (limit.min(size - offset)) as usize];
    file.read_exact(&mut buf).await?;
    let next = offset + buf.len() as u64;
    Ok(
        json!({"responseRef":id,"checksumSha256":std::fs::read_to_string(dir.join("responses").join(format!("{id}.sha256")))?,"offset":offset,"dataBase64":STANDARD.encode(buf),"nextOffset":if next<size{Some(next)}else{None},"sizeBytes":size}),
    )
}

fn daemon_lock(dir: &Path) -> Result<std::fs::File> {
    state::private_dir(dir)?;
    let lock = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(dir.join("daemon.lock"))?;
    let metadata = lock.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o077 != 0
    {
        bail!("UNSAFE_STATE");
    }
    lock.try_lock_exclusive()
        .map_err(|_| anyhow::anyhow!("DAEMON_ALREADY_RUNNING"))?;
    Ok(lock)
}
pub async fn offline_logout(dir: &Path) -> Result<Value> {
    // Acquire ownership before constructing a native auth operation. No socket or
    // execution service starts in this explicitly selected maintenance command.
    let lock = daemon_lock(dir)?;
    let auth = Auth::new(Api::new()?)?;
    finish_offline_logout(lock, auth).await
}
async fn finish_offline_logout(lock: std::fs::File, auth: Auth) -> Result<Value> {
    // The worker keeps exclusive ownership through native IO even if the caller
    // stops awaiting it. No later daemon may race protected credential cleanup.
    tokio::spawn(async move {
        let _lock = lock;
        auth.offline_logout().await
    })
    .await
    .map_err(|_| anyhow::anyhow!("AUTH_LOGOUT_FAILED"))?
}
pub async fn serve(daemon: Arc<Daemon>) -> Result<()> {
    let lock = daemon_lock(&daemon.dir)?;
    let socket = daemon.dir.join("control.sock");
    if let Ok(metadata) = std::fs::symlink_metadata(&socket) {
        use std::os::unix::fs::FileTypeExt;
        if !metadata.file_type().is_socket() || metadata.uid() != unsafe { libc::geteuid() } {
            bail!("UNSAFE_SOCKET")
        };
        std::fs::remove_file(&socket)?;
    }
    let listener = UnixListener::bind(&socket)?;
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600))?;
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let jobs = daemon.clone();
    let job_task = tokio::spawn(async move {
        crate::jobs::run(jobs).await;
    });
    let serving: Result<()> = async {
        loop {
            tokio::select! {
                result=listener.accept()=>{
                    let(stream,_)=result?;
                    if stream.peer_cred()?.uid()!=unsafe{libc::geteuid()}{continue;}
                    let d=daemon.clone();
                    tokio::spawn(async move{let _=connection(stream,d).await;});
                },
                _=tokio::signal::ctrl_c()=>break,
                _=term.recv()=>break,
            }
        }
        Ok(())
    }
    .await;
    daemon.execution.shutdown();
    let _ = job_task.await;
    while daemon.managed_work() > 0 {
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }
    std::fs::remove_file(socket)?;
    drop(lock);
    serving
}

async fn connection(stream: UnixStream, daemon: Arc<Daemon>) -> Result<()> {
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut negotiated = false;
    let mut validation_errors_negotiated = false;
    let mut recovery_errors_negotiated = false;
    loop {
        let frame = match read_frame(&mut reader).await {
            Ok(Some(frame)) => frame,
            Ok(None) => return Ok(()),
            // A truncated or oversized frame has no trustworthy request ID.
            // Sending an error with a synthetic/empty ID makes it look like a
            // protocol reply even though no client can correlate it. Close the
            // connection so the caller treats the request as indeterminate.
            Err(_) => return Ok(()),
        };
        let parsed = serde_json::from_slice::<Value>(&frame);
        let mut response = match parsed {
            Ok(request) => {
                // Only a request carrying a valid correlation ID may receive a
                // response. JSON parse failures and malformed IDs are
                // uncorrelatable, so they terminate the connection below.
                let Some(id) = request
                    .get("id")
                    .and_then(Value::as_str)
                    .filter(|id| !id.is_empty() && id.len() <= 256)
                else {
                    return Ok(());
                };
                let id = id.to_owned();
                if request["protocol"] != PROTOCOL {
                    json!({"protocol":PROTOCOL,"id":id,"error":state::safe_error("PROTOCOL_MISMATCH",false)})
                } else if request.as_object().is_none_or(|m| m.len() != 4)
                    || !request["id"].is_string()
                {
                    json!({"protocol":PROTOCOL,"id":id,"error":state::safe_error("INVALID_REQUEST",false)})
                } else if !negotiated && request["method"] != "protocol.negotiate" {
                    json!({"protocol":PROTOCOL,"id":id,"error":state::safe_error("COMPATIBILITY_ERROR",false)})
                } else {
                    if request["method"] == "protocol.negotiate" {
                        negotiated = false;
                        validation_errors_negotiated = false;
                        recovery_errors_negotiated = false;
                    }
                    match daemon
                        .dispatch(
                            request["method"].as_str().unwrap_or(""),
                            request["params"].clone(),
                        )
                        .await
                    {
                        Ok(result) => {
                            if request["method"] == "protocol.negotiate" {
                                negotiated = true;
                                recovery_errors_negotiated =
                                    request["params"]["requiredCapabilities"]
                                        .as_array()
                                        .is_some_and(|caps| {
                                            caps.contains(&json!("error.recovery/v1"))
                                        });
                                validation_errors_negotiated =
                                    request["params"]["requiredCapabilities"]
                                        .as_array()
                                        .is_some_and(|capabilities| {
                                            capabilities
                                                .contains(&json!(VALIDATION_ERRORS_CAPABILITY))
                                        });
                            }
                            json!({"protocol":PROTOCOL,"id":id,"result":result})
                        }
                        Err(error) => {
                            let (code, retryable, data) = public_error(&error);
                            let data = if validation_errors_negotiated {
                                data
                            } else {
                                None
                            };
                            json!({"protocol":PROTOCOL,"id":id,"error":state::safe_error_with_data(&code,retryable,data.as_ref())})
                        }
                    }
                }
            }
            // There is no authoritative request ID in malformed JSON, so a
            // reply would violate the correlation contract.
            Err(_) => return Ok(()),
        };
        if !recovery_errors_negotiated {
            if let Some(error) = response.get_mut("error").and_then(Value::as_object_mut) {
                error.remove("recovery");
                error.remove("outcome");
            }
        }
        let mut bytes = serde_json::to_vec(&response)?;
        bytes.push(b'\n');
        writer.write_all(&bytes).await?;
    }
}
pub async fn read_frame<R: tokio::io::AsyncBufRead + Unpin>(
    reader: &mut R,
) -> Result<Option<Vec<u8>>> {
    let mut frame = Vec::new();
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            if frame.is_empty() {
                return Ok(None);
            }
            bail!("INCOMPLETE_FRAME")
        };
        let end = available.iter().position(|b| *b == b'\n');
        let count = end.map(|i| i + 1).unwrap_or(available.len());
        if frame.len() + count > MAX_FRAME {
            bail!("FRAME_TOO_LARGE")
        };
        frame.extend_from_slice(&available[..count]);
        reader.consume(count);
        if end.is_some() {
            frame.pop();
            return Ok(Some(frame));
        }
    }
}
pub fn public_error(error: &anyhow::Error) -> (String, bool, Option<Value>) {
    if let Some(api) = error.downcast_ref::<ApiError>() {
        return (api.code.clone(), api.retryable, api.data.clone());
    }
    let text = error.to_string();
    if text.len() < 100 && text.bytes().all(|b| b.is_ascii_uppercase() || b == b'_') {
        (text, false, None)
    } else if error
        .chain()
        .any(|cause| cause.downcast_ref::<serde_json::Error>().is_some())
        || matches!(
            text.as_str(),
            "method required"
                | "unknown command"
                | "unknown lifecycle command"
                | "lifecycle rollback requires --to VERSION"
                | "invalid lifecycle argument"
                | "state directory must be absolute"
                | "HOME is missing"
        )
        || text.contains(" requires a ")
    {
        ("INVALID_REQUEST".into(), false, None)
    } else if text.contains("lifecycle")
        || text.contains("LaunchAgent")
        || text.contains("candidate health")
        || text.contains("service state")
    {
        // Lifecycle journals deliberately retain the detailed local reason,
        // but the installed CLI is a public, stable surface.  Do not print
        // filesystem paths, launchd output, or an unclassified INTERNAL error.
        ("LIFECYCLE_ERROR".into(), false, None)
    } else {
        ("INTERNAL".into(), false, None)
    }
}
pub async fn client(dir: &Path, method: &str, params: Value) -> Result<Value> {
    client_with_semantics(dir, method, params, &REQUIRED_SEMANTICS).await
}

/// Lifecycle administration must be able to drain the previously installed
/// daemon before activating a candidate with newer product capabilities.
/// Limit this compatibility route to read-only status and the established
/// drain operation; ordinary plugin and CLI calls retain full negotiation.
pub(crate) async fn lifecycle_client(dir: &Path, method: &str, params: Value) -> Result<Value> {
    ensure!(
        matches!(method, "status.get" | "daemon.drain"),
        "INVALID_REQUEST"
    );
    client_with_semantics(dir, method, params, &[]).await
}

async fn client_with_semantics(
    dir: &Path,
    method: &str,
    params: Value,
    semantics: &[&str],
) -> Result<Value> {
    let socket = dir.join("control.sock");
    let metadata =
        std::fs::symlink_metadata(&socket).map_err(|_| anyhow::anyhow!("RUNNER_UNAVAILABLE"))?;
    if metadata.uid() != unsafe { libc::geteuid() } || metadata.permissions().mode() & 0o077 != 0 {
        bail!("RUNNER_UNAVAILABLE")
    }
    // The pathname check and connect are necessarily separate system calls.
    // A daemon shutdown or stale socket can therefore yield ECONNREFUSED after
    // a safe metadata check.  It is a normal unavailable-runner condition,
    // never an opaque INTERNAL error from the installed CLI.
    let stream = UnixStream::connect(socket)
        .await
        .map_err(|_| anyhow::anyhow!("RUNNER_UNAVAILABLE"))?;
    if stream
        .peer_cred()
        .map_err(|_| anyhow::anyhow!("RUNNER_UNAVAILABLE"))?
        .uid()
        != unsafe { libc::geteuid() }
    {
        bail!("RUNNER_UNAVAILABLE")
    };
    let (read, mut write) = stream.into_split();
    let mut read = BufReader::new(read);
    let mut required: Vec<String> = semantics.iter().map(|cap| cap.to_string()).collect();
    if method != "protocol.negotiate" {
        required.push(format!("method:{method}"));
    }
    let agreement = exchange(
        &mut read,
        &mut write,
        "protocol.negotiate",
        json!({"supportedProtocols":[PROTOCOL],"requiredCapabilities":required}),
    )
    .await?;
    let selected = &agreement["result"];
    if agreement.get("error").is_some()
        || selected["selectedProtocol"] != PROTOCOL
        || selected["maxFrameBytes"]
            .as_u64()
            .is_none_or(|size| size < MAX_FRAME as u64)
        || selected["serverVersion"]
            .as_str()
            .is_none_or(|version| version.is_empty())
        || selected["capabilities"]
            .as_array()
            .is_none_or(|caps| required.iter().any(|cap| !caps.contains(&json!(cap))))
    {
        bail!("COMPATIBILITY_ERROR");
    }
    exchange(&mut read, &mut write, method, params).await
}
async fn exchange<R: tokio::io::AsyncBufRead + Unpin, W: tokio::io::AsyncWrite + Unpin>(
    read: &mut R,
    write: &mut W,
    method: &str,
    params: Value,
) -> Result<Value> {
    let id = Uuid::new_v4().to_string();
    let mut bytes =
        serde_json::to_vec(&json!({"protocol":PROTOCOL,"id":id,"method":method,"params":params}))?;
    bytes.push(b'\n');
    if bytes.len() > MAX_FRAME {
        bail!("FRAME_TOO_LARGE");
    }
    write
        .write_all(&bytes)
        .await
        .map_err(|_| anyhow::anyhow!("NETWORK_AMBIGUOUS"))?;
    let frame = read_frame(read)
        .await
        .map_err(|_| anyhow::anyhow!("NETWORK_AMBIGUOUS"))?
        .context("NETWORK_AMBIGUOUS")?;
    let result: Value =
        serde_json::from_slice(&frame).map_err(|_| anyhow::anyhow!("PROTOCOL_MISMATCH"))?;
    if result["id"] != id
        || result["protocol"] != PROTOCOL
        || result.as_object().is_none_or(|object| object.len() != 3)
        || (result.get("result").is_some() == result.get("error").is_some())
    {
        bail!("PROTOCOL_MISMATCH");
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn lifecycle_status_negotiates_across_a_new_auth_capability() {
        let temp = tempfile::tempdir().unwrap();
        let socket = temp.path().join("control.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
        let server = tokio::spawn(async move {
            for _ in 0..2 {
                let (stream, _) = listener.accept().await.unwrap();
                let (read, mut write) = stream.into_split();
                let mut read = BufReader::new(read);
                let negotiation: Value =
                    serde_json::from_slice(&read_frame(&mut read).await.unwrap().unwrap()).unwrap();
                assert_eq!(negotiation["method"], "protocol.negotiate");
                let required = negotiation["params"]["requiredCapabilities"]
                    .as_array()
                    .unwrap();
                let reply = if required.contains(&json!("auth:browser-pkce/v1")) {
                    json!({"protocol":PROTOCOL,"id":negotiation["id"],"error":state::safe_error("COMPATIBILITY_ERROR",false)})
                } else {
                    assert_eq!(required, &vec![json!("method:status.get")]);
                    json!({"protocol":PROTOCOL,"id":negotiation["id"],"result":{
                        "selectedProtocol":PROTOCOL,"serverVersion":"0.3.40","maxFrameBytes":MAX_FRAME,
                        "capabilities":["method:status.get","method:daemon.drain"]}})
                };
                let mut bytes = serde_json::to_vec(&reply).unwrap();
                bytes.push(b'\n');
                write.write_all(&bytes).await.unwrap();
                if reply.get("error").is_some() {
                    continue;
                }
                let request: Value =
                    serde_json::from_slice(&read_frame(&mut read).await.unwrap().unwrap()).unwrap();
                assert_eq!(request["method"], "status.get");
                let mut bytes =
                    serde_json::to_vec(&json!({"protocol":PROTOCOL,"id":request["id"],"result":{
                    "version":"0.3.40","activeJobs":0,"draining":false}}))
                    .unwrap();
                bytes.push(b'\n');
                write.write_all(&bytes).await.unwrap();
            }
        });
        let status = lifecycle_client(temp.path(), "status.get", json!({}))
            .await
            .unwrap();
        assert_eq!(status["result"]["version"], "0.3.40");
        assert_eq!(
            client(temp.path(), "status.get", json!({}))
                .await
                .unwrap_err()
                .to_string(),
            "COMPATIBILITY_ERROR"
        );
        server.await.unwrap();
    }
    #[test]
    fn gemini_discovery_snapshots_gemini_cli_and_never_falls_back_to_agy() {
        let temp = tempfile::tempdir().unwrap();
        for (name, content) in [
            ("gemini", "gemini-cli-fixture"),
            ("agy", "legacy-agy-fixture"),
        ] {
            let path = temp.path().join(name);
            std::fs::write(&path, content).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let resolve = |name: &str| Ok(std::fs::canonicalize(temp.path().join(name)).ok());
        let snapshot = provider_snapshot_with(resolve).unwrap();
        assert_eq!(snapshot["gemini"]["adapter"], "gemini");
        assert_eq!(
            snapshot["gemini"]["path"],
            json!(resolve("gemini").unwrap().unwrap())
        );
        assert_eq!(
            snapshot["gemini"]["checksumSha256"],
            state::digest(b"gemini-cli-fixture")
        );
        std::fs::remove_file(temp.path().join("gemini")).unwrap();
        assert!(resolve("agy").unwrap().is_some());
        assert!(
            provider_snapshot_with(resolve)
                .unwrap()
                .get("gemini")
                .is_none()
        );
        let snapshot = provider_snapshot_with(resolve).unwrap();
        assert_eq!(snapshot["antigravity"]["adapter"], "agy");
        assert_eq!(
            snapshot["antigravity"]["path"],
            json!(resolve("agy").unwrap().unwrap())
        );
    }
    #[test]
    fn configured_provider_path_is_used_without_path_discovery() {
        let temp = tempfile::tempdir().unwrap();
        let configured = temp.path().join("configured-codex");
        let discovered = temp.path().join("codex");
        for path in [&configured, &discovered] {
            std::fs::write(path, "fixture").unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let configured = std::fs::canonicalize(configured).unwrap();
        let resolved = find_executable_with(
            "codex",
            |variable| {
                (variable == "LOOMEX_CODEX_EXECUTABLE").then(|| configured.clone().into_os_string())
            },
            Some(temp.path().as_os_str().to_owned()),
        )
        .unwrap();
        assert_eq!(resolved, Some(configured));
    }
    #[test]
    fn invalid_configured_provider_fails_closed_without_path_fallback() {
        let temp = tempfile::tempdir().unwrap();
        let discovered = temp.path().join("codex");
        std::fs::write(&discovered, "fixture").unwrap();
        std::fs::set_permissions(&discovered, std::fs::Permissions::from_mode(0o755)).unwrap();
        let missing = temp.path().join("configured-codex-missing");
        let error = find_executable_with(
            "codex",
            |_| Some(missing.clone().into_os_string()),
            Some(temp.path().as_os_str().to_owned()),
        )
        .unwrap_err();
        assert_eq!(error.to_string(), "PROVIDER_UNAVAILABLE");
    }
    #[test]
    fn provider_diagnostics_never_exposes_executable_identity_fields() {
        let diagnostics = provider_diagnostics();
        for provider in diagnostics.as_object().unwrap().values() {
            assert!(provider["available"].is_boolean());
            assert!(provider["reason"].is_string());
            assert!(provider.get("path").is_none());
            assert!(provider.get("checksumSha256").is_none());
            assert!(provider.get("sizeBytes").is_none());
        }
    }
    #[test]
    fn public_errors_classify_local_validation_and_lifecycle_failures() {
        for message in [
            "unknown lifecycle command",
            "lifecycle rollback requires --to VERSION",
            "invalid lifecycle argument",
        ] {
            assert_eq!(public_error(&anyhow::anyhow!(message)).0, "INVALID_REQUEST");
        }
        let json_error = serde_json::from_str::<Value>("{").unwrap_err();
        assert_eq!(
            public_error(&anyhow::Error::new(json_error)).0,
            "INVALID_REQUEST"
        );
        assert_eq!(
            public_error(&anyhow::anyhow!("candidate health is unconfirmed")).0,
            "LIFECYCLE_ERROR"
        );
        assert_eq!(
            public_error(&anyhow::anyhow!("state directory must be absolute")).0,
            "INVALID_REQUEST"
        );
    }
    #[test]
    fn configured_provider_must_be_canonical_and_executable() {
        let temp = tempfile::tempdir().unwrap();
        let target = temp.path().join("codex-real");
        let link = temp.path().join("codex-link");
        std::fs::write(&target, "fixture").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o644)).unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();
        for configured in [&target, &link] {
            assert!(
                find_executable_with("codex", |_| Some(configured.as_os_str().to_owned()), None,)
                    .is_err()
            );
        }
    }
    #[test]
    fn route_cannot_forward_arbitrary_url() {
        assert!(backend_route("http.request", &json!({"url":"https://example.org"})).is_err());
    }
    #[test]
    fn strict_schema_rejects_hidden_fields() {
        let schema =
            json!({"required":["runId"],"properties":{"runId":{"type":"string","format":"uuid"}}});
        assert!(validate_params(&json!({"runId":Uuid::new_v4(),"url":"x"}), &schema).is_err());
    }
    #[test]
    fn workflow_create_catalog_accepts_atomic_draft_or_metadata_only_inputs() {
        let catalog: Value =
            serde_json::from_str(include_str!("../contracts/method-catalog.json")).unwrap();
        let schema = &catalog["methods"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["name"] == "workflows.create")
            .unwrap()["inputSchema"];
        let key = Uuid::new_v4();
        let full = json!({
            "name":"Author a release workflow",
            "slug":"release-authoring",
            "definition":{"nodes":[{"id":"draft","kind":"task","config":{"prompt":"preserve this complete payload"}}],"transitions":[]},
            "notes":"initial canonical draft",
            "idempotencyKey":key,
        });
        assert!(validate_params(&full, schema).is_ok());
        assert!(
            validate_params(
                &json!({"name":"Metadata only","idempotencyKey":key}),
                schema
            )
            .is_ok()
        );
        assert!(
            validate_params(
                &json!({"name":"Wrong definition","definition":[],"idempotencyKey":key}),
                schema
            )
            .is_err()
        );
        assert!(
            validate_params(
                &json!({"name":"Wrong notes","notes":{},"idempotencyKey":key}),
                schema
            )
            .is_err()
        );

        let (verb, route, body) = backend_route("workflows.create", &full).unwrap();
        assert_eq!(verb, "POST");
        assert_eq!(route, "v2/workflow-drafts/");
        assert_eq!(
            body,
            Some(json!({
                "name":"Author a release workflow",
                "slug":"release-authoring",
                "definition":{"nodes":[{"id":"draft","kind":"task","config":{"prompt":"preserve this complete payload"}}],"transitions":[]},
                "notes":"initial canonical draft",
            }))
        );
    }
    #[test]
    fn lifecycle_catalog_accepts_const_only_version_and_rejects_substitution() {
        let catalog: Value =
            serde_json::from_str(include_str!("../contracts/method-catalog.json")).unwrap();
        let schema = &catalog["methods"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["name"] == "follow.session.lifecycle")
            .unwrap()["inputSchema"];
        let mut input = json!({"schemaVersion":"loomex.follow-session.lifecycle/v1",
            "event":"SessionStart", "eventId":Uuid::new_v4(),
            "session":{"id":"diagnostic-session","cwd":"/tmp/diagnostic"}});
        assert!(validate_params(&input, schema).is_ok());
        input["schemaVersion"] = json!("wrong/version");
        assert!(validate_params(&input, schema).is_err());
        input["schemaVersion"] = json!(1);
        assert!(validate_params(&input, schema).is_err());
    }

    #[test]
    fn workflow_operation_reconciliation_preserves_exact_identity_in_body() {
        let key = Uuid::new_v4().to_string();
        let input = json!({"operation":"workflows.create","idempotencyKey":key});
        let (verb, route, body) = backend_route("workflow.operations.get", &input).unwrap();
        assert_eq!(verb, "POST");
        assert_eq!(route, "v2/workflow-operations/get/");
        assert_eq!(body, Some(input));
    }

    #[test]
    fn output_normalizer_selects_the_matching_discriminated_variant() {
        let schema = json!({"oneOf":[
            {"properties":{"status":{"const":"valid"},"value":{"type":"object"}},"required":["status","value"]},
            {"properties":{"status":{"const":"stale"},"reason":{"enum":["expired"]}},"required":["status","reason"]}
        ]});
        assert_eq!(
            normalize_catalog_output(json!({"status":"stale","reason":"expired"}), &schema)
                .unwrap(),
            json!({"status":"stale","reason":"expired"})
        );
        assert!(normalize_catalog_output(json!({"status":"unknown"}), &schema).is_err());
    }
    #[test]
    fn output_normalizer_preserves_runner_details_when_lifting_backend_fields() {
        let schema = json!({"oneOf":[{
            "properties":{"execution":{"type":"object"},"details":{"type":"object"}},
            "required":["execution"]
        }]});
        let normalized = normalize_catalog_output(
            json!({
                "execution":{"id":Uuid::new_v4()},
                "executionId":Uuid::new_v4(),
                "details":{"followContinuation":{"receipt":"runner-issued"}}
            }),
            &schema,
        )
        .unwrap();
        assert_eq!(
            normalized["details"]["followContinuation"]["receipt"],
            "runner-issued"
        );
        assert!(normalized["details"]["executionId"].is_string());
    }
    #[test]
    fn output_normalizer_rejects_ambiguous_detail_key_collisions() {
        let schema = json!({"oneOf":[{
            "properties":{"details":{"type":"object"}},
            "required":[]
        }]});
        assert!(
            normalize_catalog_output(
                json!({"details":{"executionId":"runner"},"executionId":"backend"}),
                &schema,
            )
            .is_err()
        );
    }
    #[tokio::test]
    async fn status_reports_monitoring_observability_without_a_delivery_guarantee() {
        let temp = tempfile::tempdir().unwrap();
        let api = Api::for_test_origin("http://127.0.0.1:9").unwrap();
        let organization = "11111111-1111-4111-8111-111111111111";
        let daemon = Daemon::new(
            temp.path().into(),
            api.clone(),
            Auth::test_enrolled(api, organization, "owner"),
        )
        .unwrap();
        let status = daemon.dispatch("status.get", json!({})).await.unwrap();
        assert_eq!(
            status["details"]["monitoring"]["schemaVersion"],
            "loomex.monitoring-readiness/v1"
        );
        assert_eq!(
            status["details"]["monitoring"]["runObservationAvailable"],
            true
        );
        assert_eq!(status["details"]["monitoring"]["guarantee"], "none");
        assert_eq!(
            status["details"]["monitoring"]["hostHookDeliveryAuthority"],
            "host_managed"
        );
    }
    #[test]
    fn resolved_and_rejected_human_responses_authorize_followup() {
        for status in ["resolved", "rejected", "approved", "answered"] {
            assert!(accepted_interaction_result(
                &json!({"requestStatus":status,"error":null})
            ));
        }
        assert!(!accepted_interaction_result(
            &json!({"requestStatus":"pending","error":null})
        ));
        assert!(!accepted_interaction_result(
            &json!({"requestStatus":"resolved","error":{"code":"failed"}})
        ));
    }
    #[test]
    fn ui_replay_mutations_are_account_scoped() {
        for method in [
            "runs.prepare",
            "runs.commit",
            "builder.prepare",
            "builder.commit",
            "builder.respond",
            "builder.finalize",
            "editor.prepare",
            "editor.commit",
            "editor.respond",
            "editor.finalize",
            "interactions.respond",
            "interactions.decide",
        ] {
            assert!(account_scoped_method(method), "{method}");
        }
        assert!(!account_scoped_method("auth.login"));
        assert!(!account_scoped_method("organizations.select"));
    }
    #[test]
    fn route_queries_are_encoded() {
        let (_, path, _) =
            backend_route("workflows.list", &json!({"query":"x&scope=admin"})).unwrap();
        assert_eq!(path, "v1/workflows/?query=x%26scope%3Dadmin");
    }
    #[tokio::test]
    async fn frame_size_is_bounded_without_truncation() {
        let bytes = vec![b'x'; MAX_FRAME + 1];
        assert!(
            read_frame(&mut BufReader::new(bytes.as_slice()))
                .await
                .is_err()
        );
        let mut reader = BufReader::new(b"{\"x\":1}\n".as_slice());
        assert_eq!(
            read_frame(&mut reader).await.unwrap().unwrap(),
            b"{\"x\":1}"
        );
    }
}

#[cfg(test)]
mod conformance {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    fn fixture(dir: &Path, api: Api) -> Daemon {
        Daemon::new(
            dir.into(),
            api.clone(),
            Auth::test_enrolled(
                api,
                "11111111-1111-4111-8111-111111111111",
                "22222222-2222-4222-8222-222222222222",
            ),
        )
        .unwrap()
    }
    #[tokio::test]
    async fn workflow_operation_reconciliation_uses_mutation_key_without_replaying_local_mutation()
    {
        let temp = tempfile::tempdir().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let api =
            Api::for_test_origin(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
        let daemon = fixture(temp.path(), api);
        let org = "11111111-1111-4111-8111-111111111111";
        daemon.public.lock().await.active_organization = Some(org.into());
        let key = Uuid::new_v4().to_string();
        let original = json!({"name":"Draft","idempotencyKey":key});
        let identity = state::json_digest(&json!({
            "method":"workflows.create","params":original,"organizationId":org,"accountSubject":null,
        }));
        let journal = temp.path().join("operations").join(format!("{key}.json"));
        state::write_json(
            &journal,
            &json!({"digest":identity,"method":"workflows.create","status":"pending"}),
        )
        .unwrap();
        let response =
            json!({"operation":"workflows.create","idempotencyKey":key,"status":"not_found"});
        let backend = tokio::spawn(async move {
            let (stream, head) = receive_http(&listener).await;
            assert!(head.starts_with(
                "POST /api/v1/runner-control/runner/v2/workflow-operations/get/ HTTP/1.1"
            ));
            reply_http(stream, 200, response).await;
        });

        let result = daemon
            .dispatch(
                "workflow.operations.get",
                json!({"operation":"workflows.create","idempotencyKey":key}),
            )
            .await
            .unwrap();
        assert_eq!(result["status"], "not_found");
        assert_eq!(
            state::read_json::<Value>(&journal).unwrap()["status"],
            "pending"
        );
        backend.await.unwrap();
        assert_eq!(
            daemon
                .dispatch(
                    "workflows.create",
                    json!({"name":"Changed","idempotencyKey":key})
                )
                .await
                .unwrap_err()
                .to_string(),
            "IDEMPOTENCY_CONFLICT"
        );
    }
    #[tokio::test]
    async fn connection_get_is_advertised_and_reports_local_active_work() {
        let temp = tempfile::tempdir().unwrap();
        let api = Api::for_test_origin("http://127.0.0.1:9").unwrap();
        let daemon = fixture(temp.path(), api);
        assert!(
            negotiate(&json!({
                "supportedProtocols":[PROTOCOL],
                "requiredCapabilities":["method:connection.get", "connection.projection/v2"]
            }))
            .is_ok()
        );
        daemon.public.lock().await.active_organization =
            Some("11111111-1111-4111-8111-111111111111".into());
        for _ in 0..4 {
            daemon.execution.begin_active();
        }
        let result = daemon.dispatch("connection.get", json!({})).await.unwrap();
        assert_eq!(result["state"], "authenticated");
        assert_eq!(result["organization"]["status"], "connected");
        assert_eq!(result["activeWork"], 4);
        assert!(
            result["actions"]
                .as_array()
                .unwrap()
                .contains(&json!("auth.logout"))
        );
    }
    #[tokio::test]
    async fn connection_navigation_is_local_and_revision_checked() {
        let temp = tempfile::tempdir().unwrap();
        let daemon = fixture(
            temp.path(),
            Api::for_test_origin("http://127.0.0.1:9").unwrap(),
        );
        let created = daemon.dispatch("connection.views.create", json!({"kind":"connection","entityType":"catalog","entityId":"00000000-0000-0000-0000-000000000000","state":{},"idempotencyKey":Uuid::new_v4()})).await.unwrap();
        let update = json!({"viewSessionId":created["viewSessionId"],"expectedRevision":created["revision"],"state":{"page":"organizations"},"idempotencyKey":Uuid::new_v4()});
        let saved = daemon
            .dispatch("connection.views.update", update.clone())
            .await
            .unwrap();
        assert_eq!(saved["state"]["page"], "organizations");
        assert_eq!(
            daemon
                .dispatch("connection.views.update", update)
                .await
                .unwrap(),
            saved
        );
        assert_eq!(
            daemon
                .dispatch(
                    "connection.views.get",
                    json!({"viewSessionId":created["viewSessionId"]})
                )
                .await
                .unwrap()["state"]["page"],
            "organizations"
        );
        assert!(daemon.public.lock().await.active_organization.is_none());
    }

    #[tokio::test]
    async fn logout_with_active_work_has_no_drain_or_cancellation_side_effects() {
        let temp = tempfile::tempdir().unwrap();
        let api = Api::for_test_origin("http://127.0.0.1:9").unwrap();
        let daemon = fixture(temp.path(), api);
        let org = "11111111-1111-4111-8111-111111111111";
        daemon.public.lock().await.active_organization = Some(org.into());
        let token = Arc::new(AtomicBool::new(false));
        daemon
            .execution
            .register_cancellation("active-work".into(), token.clone())
            .await
            .unwrap();
        daemon.execution.begin_active();

        assert_eq!(
            daemon
                .dispatch("auth.logout", json!({"idempotencyKey":Uuid::new_v4()}))
                .await
                .unwrap_err()
                .to_string(),
            "ACTIVE_WORK_REQUIRES_DRAIN"
        );
        assert_eq!(
            state::error_recovery("ACTIVE_WORK_REQUIRES_DRAIN"),
            json!({"recovery":"refresh_authority","outcome":"rejected"})
        );
        assert!(!daemon.execution.is_draining());
        assert!(!daemon.execution.logout_requested());
        assert!(!token.load(Ordering::SeqCst));
        assert_eq!(
            daemon.public.lock().await.active_organization.as_deref(),
            Some(org)
        );
        assert_eq!(daemon.auth.status().await.unwrap()["code"], "AUTHENTICATED");
    }
    #[tokio::test]
    async fn idle_logout_clears_the_public_organization_selection() {
        let temp = tempfile::tempdir().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let api =
            Api::for_test_origin(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
        let daemon = fixture(temp.path(), api);
        daemon.public.lock().await.active_organization =
            Some("11111111-1111-4111-8111-111111111111".into());
        let server = tokio::spawn(async move {
            let (stream, head) = receive_http(&listener).await;
            assert!(head.starts_with(
                "POST /api/v1/runner-control/runner/v2/device-authorities/logout/ HTTP/1.1"
            ));
            reply_http(stream, 200, json!({"revoked":true})).await;
        });
        assert_eq!(
            daemon
                .dispatch("auth.logout", json!({"idempotencyKey":Uuid::new_v4()}))
                .await
                .unwrap()["revoked"],
            true
        );
        server.await.unwrap();
        assert!(!daemon.execution.is_draining());
        assert!(daemon.public.lock().await.active_organization.is_none());
        assert!(
            state::read_json::<PublicState>(&temp.path().join("state.json"))
                .unwrap()
                .active_organization
                .is_none()
        );
    }
    #[tokio::test]
    async fn logout_quiesces_idle_session_work_without_persistently_draining() {
        let temp = tempfile::tempdir().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let api =
            Api::for_test_origin(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
        let daemon = fixture(temp.path(), api);
        let server = tokio::spawn(async move {
            let (stream, head) = receive_http(&listener).await;
            assert!(head.starts_with(
                "POST /api/v1/runner-control/runner/v2/device-authorities/logout/ HTTP/1.1"
            ));
            reply_http(stream, 200, json!({"revoked":true})).await;
        });
        daemon.execution.begin_quiescence();
        let release_idle_session = async {
            tokio::time::sleep(Duration::from_millis(50)).await;
            assert!(daemon.execution.logout_requested());
            daemon.execution.end_quiescence();
        };
        let (result, ()) = tokio::join!(
            daemon.dispatch("auth.logout", json!({"idempotencyKey":Uuid::new_v4()})),
            release_idle_session,
        );
        assert_eq!(result.unwrap()["revoked"], true);
        server.await.unwrap();
        assert!(!daemon.execution.logout_requested());
        assert!(!daemon.execution.is_draining());
    }
    #[tokio::test]
    async fn accepted_human_responses_always_receive_a_follow_continuation() {
        let temp = tempfile::tempdir().unwrap();
        let api = Api::for_test_origin("http://127.0.0.1:9").unwrap();
        let daemon = fixture(temp.path(), api);
        let org = "11111111-1111-4111-8111-111111111111";
        for status in ["resolved", "rejected"] {
            let run = Uuid::new_v4().to_string();
            let request = Uuid::new_v4().to_string();
            let mut result = json!({
                "requestId":request,
                "requestStatus":status,
                "executionId":run,
                "executionStatus":"running",
                "error":null,
            });
            daemon
                .attach_follow_continuation(
                    org,
                    "accepted_interaction",
                    Some(&request),
                    &mut result,
                )
                .await
                .unwrap();
            assert_eq!(result["details"]["followContinuation"]["runId"], run);
            assert!(
                result["details"]["followContinuation"]["receipt"]
                    .as_str()
                    .is_some_and(|receipt| !receipt.is_empty())
            );
        }
    }
    #[tokio::test]
    async fn historical_accepted_interaction_delivery_recovers_only_existing_receipt() {
        let org = "11111111-1111-4111-8111-111111111111";
        let account = "22222222-2222-4222-8222-222222222222";
        for (legacy_status, expected_status) in
            [("acknowledged", "acknowledged"), ("sending", "unknown")]
        {
            let temp = tempfile::tempdir().unwrap();
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let api = Api::for_test_origin(&format!("http://{}", listener.local_addr().unwrap()))
                .unwrap();
            let daemon = fixture(temp.path(), api);
            daemon.public.lock().await.active_organization = Some(org.into());
            let run = Uuid::new_v4().to_string();
            let request = Uuid::new_v4().to_string();
            let identity = format!("follow:{run}:{request}");
            let installation = daemon.auth.installation_id().await.unwrap();
            let receipt = daemon
                .follow
                .issue_continuation(
                    org,
                    account,
                    &installation,
                    &run,
                    "accepted_interaction",
                    Some(&request),
                )
                .unwrap();
            daemon
                .presentation
                .dispatch(
                    org,
                    account,
                    "presentation.sessions.create",
                    &json!({
                        "kind":"interaction",
                        "entityType":"request",
                        "entityId":request,
                        "state":{"continuationDelivery":{
                            "schemaVersion":1,
                            "identity":identity,
                            "purpose":"accepted_interaction",
                            "text":"private answer must not enter the delivery row",
                            "status":legacy_status,
                            "attemptId":Uuid::new_v4(),
                        }},
                        "idempotencyKey":Uuid::new_v4(),
                    }),
                )
                .unwrap();
            let run_for_server = run.clone();
            let request_for_server = request.clone();
            let flat_execution_id = legacy_status == "sending";
            let server = tokio::spawn(async move {
                let (stream, head) = receive_http(&listener).await;
                assert!(head.starts_with(&format!(
                    "GET /api/v1/runner-control/runner/v1/human-requests/{request_for_server}/ HTTP/1.1"
                )));
                let mut response = json!({"humanRequest":{
                        "id":request_for_server,
                        "status":"resolved",
                }});
                if flat_execution_id {
                    response["executionId"] = json!(run_for_server);
                } else {
                    response["humanRequest"]["execution"] = json!({"id":run_for_server});
                }
                reply_http(stream, 200, response).await;
            });
            let recovered = daemon
                .dispatch("presentation.delivery.get", json!({"identity":identity}))
                .await
                .unwrap();
            server.await.unwrap();
            assert_eq!(recovered["status"], expected_status);
            assert_eq!(recovered["continuation"]["receipt"], receipt);
            assert_eq!(recovered["continuation"]["requestId"], request);
            assert_eq!(recovered["continuation"]["requestStatus"], "resolved");
            assert!(!recovered.to_string().contains("private answer"));
            assert_eq!(
                daemon
                    .dispatch("presentation.delivery.get", json!({"identity":identity}))
                    .await
                    .unwrap(),
                recovered
            );
        }
    }

    #[tokio::test]
    async fn historical_accepted_interaction_delivery_rejects_wrong_run_or_missing_receipt() {
        let org = "11111111-1111-4111-8111-111111111111";
        for mismatch in [true, false] {
            let temp = tempfile::tempdir().unwrap();
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let api = Api::for_test_origin(&format!("http://{}", listener.local_addr().unwrap()))
                .unwrap();
            let daemon = fixture(temp.path(), api);
            daemon.public.lock().await.active_organization = Some(org.into());
            let run = Uuid::new_v4().to_string();
            let request = Uuid::new_v4().to_string();
            let identity = format!("follow:{run}:{request}");
            if mismatch {
                let installation = daemon.auth.installation_id().await.unwrap();
                daemon
                    .follow
                    .issue_continuation(
                        org,
                        "22222222-2222-4222-8222-222222222222",
                        &installation,
                        &run,
                        "accepted_interaction",
                        Some(&request),
                    )
                    .unwrap();
            }
            let request_for_server = request.clone();
            let execution = if mismatch {
                Uuid::new_v4().to_string()
            } else {
                run.clone()
            };
            let server = tokio::spawn(async move {
                let (stream, head) = receive_http(&listener).await;
                assert!(head.starts_with(&format!(
                    "GET /api/v1/runner-control/runner/v1/human-requests/{request_for_server}/ HTTP/1.1"
                )));
                reply_http(
                    stream,
                    200,
                    json!({"humanRequest":{
                        "id":request_for_server,
                        "status":"resolved",
                        "execution":{"id":execution},
                    }}),
                )
                .await;
            });
            assert_eq!(
                daemon
                    .dispatch("presentation.delivery.get", json!({"identity":identity}))
                    .await
                    .unwrap_err()
                    .to_string(),
                "DELIVERY_NOT_READY"
            );
            server.await.unwrap();
            assert_eq!(
                daemon
                    .presentation
                    .dispatch(
                        org,
                        "22222222-2222-4222-8222-222222222222",
                        "presentation.delivery.get",
                        &json!({"identity":identity}),
                    )
                    .unwrap_err()
                    .to_string(),
                "DELIVERY_NOT_READY"
            );
        }
    }
    #[tokio::test]
    async fn committed_start_handoff_replays_local_follow_repair_without_a_second_backend_commit() {
        let temp = tempfile::tempdir().unwrap();
        let daemon = fixture(
            temp.path(),
            Api::for_test_origin("http://127.0.0.1:9").unwrap(),
        );
        let org = "11111111-1111-4111-8111-111111111111";
        let ticket = Uuid::new_v4().to_string();
        let preparation = Uuid::new_v4().to_string();
        let run = Uuid::new_v4().to_string();
        let backend_result = json!({
            "execution":{"id":run},
            "preparationId":preparation,
            "executionPolicy":"host_user/v1",
        });
        let record = json!({
            "schemaVersion":"loomex.run-start-handoff/v1",
            "ticket":ticket,
            "organizationId":org,
            "accountSubject":"22222222-2222-4222-8222-222222222222",
            "installationId":"00000000-0000-4000-8000-000000000001",
            "preparationId":preparation,
            "bindingDigest":"digest",
            "confirmationKey":Uuid::new_v4(),
            "idempotencyKey":Uuid::new_v4(),
            "status":"committed",
            "runId":run,
            "result":backend_result,
        });
        let path = temp
            .path()
            .join("start-handoffs")
            .join(format!("{ticket}.json"));
        state::write_json(&path, &record).unwrap();
        let legacy_projection = daemon
            .get_run_start_handoff(org, &json!({"handoffRef":ticket}))
            .await
            .unwrap();
        assert_eq!(legacy_projection["lifecycle"], "committed");
        assert_eq!(legacy_projection["runId"], run);
        assert_eq!(legacy_projection["result"], backend_result);

        TEST_START_HANDOFF_FOLLOW_FAILURE.store(true, Ordering::SeqCst);
        let error = daemon
            .commit_run_start_handoff(org, &json!({"handoffRef":ticket}))
            .await
            .unwrap_err();
        TEST_START_HANDOFF_FOLLOW_FAILURE.store(false, Ordering::SeqCst);
        assert_eq!(error.to_string(), "START_HANDOFF_FOLLOW_INJECTED");
        let durable: Value = state::read_json(&path).unwrap();
        assert_eq!(durable["status"], "committed");
        assert_eq!(durable["runId"], run);
        assert_eq!(durable["result"], backend_result);

        // The replay only restores local continuation/activation evidence. A
        // request to the unreachable fixture origin would fail, proving this
        // path never issues a second backend execution commit.
        let replay = daemon
            .commit_run_start_handoff(org, &json!({"handoffRef":ticket}))
            .await
            .unwrap();
        assert_eq!(replay["execution"]["id"], run);
        assert!(
            replay["details"]["followContinuation"]["receipt"]
                .as_str()
                .is_some_and(|receipt| !receipt.is_empty())
        );
        let durable: Value = state::read_json(&path).unwrap();
        assert_eq!(durable["followActivationState"], "active");
    }
    #[tokio::test]
    async fn run_start_handoff_requires_app_only_approval_and_keeps_the_review_immutable() {
        let temp = tempfile::tempdir().unwrap();
        let daemon = fixture(
            temp.path(),
            Api::for_test_origin("http://127.0.0.1:9").unwrap(),
        );
        let org = "11111111-1111-4111-8111-111111111111";
        daemon.public.lock().await.active_organization = Some(org.into());
        let workspace = temp.path().join("workspace");
        std::fs::create_dir(&workspace).unwrap();
        daemon
            .dispatch(
                "workspaces.grant",
                json!({"workspacePath":workspace,"idempotencyKey":Uuid::new_v4()}),
            )
            .await
            .unwrap();
        let preparation = Uuid::new_v4().to_string();
        let confirmation = Uuid::new_v4().to_string();
        let review = json!({
            "preparationId":preparation, "bindingDigest":"digest",
            "binding":{"organizationId":org,"runnerId":"22222222-2222-4222-8222-222222222222","installationId":"00000000-0000-4000-8000-000000000001","workspacePath":workspace,"workflowId":Uuid::new_v4(),"versionId":Uuid::new_v4()},
            "limits":{}, "expiresAt":null, "confirmationKey":confirmation,
        });
        state::write_json(&temp.path().join("preparations").join(format!("{preparation}.json")), &json!({
            "operation":"runs.prepare", "organizationId":org,
            "accountSubject":"22222222-2222-4222-8222-222222222222", "installationId":"00000000-0000-4000-8000-000000000001",
            "workspacePath":workspace, "bindingDigest":"digest", "binding":review["binding"], "confirmationKey":confirmation,
            "providers":provider_snapshot().unwrap(), "review":review,
        })).unwrap();
        let issue_params = json!({"preparationId":preparation,"bindingDigest":"digest","confirmationKey":confirmation,"idempotencyKey":Uuid::new_v4()});
        let issued = daemon
            .dispatch("runs.start_handoff.issue", issue_params.clone())
            .await
            .unwrap();
        let handoff_ref = issued["handoffRef"].as_str().unwrap();
        assert_eq!(issued["lifecycle"], "prepared");
        assert!(issued.pointer("/browserApproval").is_none());
        assert_eq!(
            daemon
                .dispatch("runs.start_handoff.issue", issue_params.clone())
                .await
                .unwrap()["handoffRef"],
            handoff_ref
        );
        assert_eq!(
            daemon
                .dispatch(
                    "runs.start_handoff.commit",
                    json!({"handoffRef":handoff_ref})
                )
                .await
                .unwrap_err()
                .to_string(),
            "START_HANDOFF_UNAPPROVED"
        );
        let approved = daemon
            .dispatch(
                "runs.start_handoff.approve",
                json!({"handoffRef":handoff_ref,"idempotencyKey":Uuid::new_v4()}),
            )
            .await
            .unwrap();
        assert_eq!(approved["lifecycle"], "approved");
        assert_eq!(approved["nextAction"], "commit");
        let delivery = daemon
            .dispatch(
                "presentation.delivery.get",
                json!({"identity":format!("start:{handoff_ref}")}),
            )
            .await
            .unwrap();
        assert_eq!(delivery["status"], "ready");
        assert_eq!(delivery["continuation"]["handoffRef"], handoff_ref);
        assert!(delivery["continuation"].get("runId").is_none());
        let durable: Value = state::read_json(
            &temp
                .path()
                .join("start-handoffs")
                .join(format!("{handoff_ref}.json")),
        )
        .unwrap();
        assert_eq!(durable["commit"]["confirmationKey"], confirmation);
        assert!(durable.get("approvalCapabilityDigest").is_none());
        let projection = daemon
            .dispatch("runs.start_handoff.get", json!({"handoffRef":handoff_ref}))
            .await
            .unwrap();
        assert!(projection.pointer("/review").is_none());
        assert!(!projection.to_string().contains(&confirmation));
    }

    #[tokio::test]
    async fn start_handoff_restore_is_owner_scoped_safe_and_explicit_after_restart() {
        let temp = tempfile::tempdir().unwrap();
        let org = "11111111-1111-4111-8111-111111111111";
        let issue_key = Uuid::new_v4().to_string();
        let handoff_ref = Uuid::new_v4().to_string();
        let preparation = Uuid::new_v4().to_string();
        let confirmation = Uuid::new_v4().to_string();
        let daemon = fixture(
            temp.path(),
            Api::for_test_origin("http://127.0.0.1:9").unwrap(),
        );
        daemon.public.lock().await.active_organization = Some(org.into());
        state::write_json(
            &temp
                .path()
                .join("start-handoffs")
                .join(format!("{handoff_ref}.json")),
            &json!({
                "schemaVersion":"loomex.run-start-handoff/v2",
                "handoffRef":handoff_ref,
                "organizationId":org,
                "accountSubject":"22222222-2222-4222-8222-222222222222",
                "installationId":"00000000-0000-4000-8000-000000000001",
                "preparationId":preparation,
                "lifecycle":"prepared",
                "approvalObserved":false,
                "issueIdempotencyKey":issue_key,
                "review":{"confirmationKey":confirmation,"expiresAt":null},
                "commit":{"confirmationKey":confirmation,"idempotencyKey":issue_key},
                "approvalCapabilityDigest":"durable-digest-only"
            }),
        )
        .unwrap();
        let restore = json!({"idempotencyKey":issue_key});
        let first = daemon
            .dispatch("runs.start_handoff.restore", restore.clone())
            .await
            .unwrap();
        assert_eq!(first["handoffRef"], handoff_ref);
        assert_eq!(first["lifecycle"], "prepared");
        assert!(first.pointer("/browserApproval").is_none());
        assert!(!first.to_string().contains(&confirmation));
        assert!(!first.to_string().contains("durable-digest-only"));
        drop(daemon);

        let other_owner = Daemon::new(
            temp.path().into(),
            Api::for_test_origin("http://127.0.0.1:9").unwrap(),
            Auth::test_enrolled(
                Api::for_test_origin("http://127.0.0.1:9").unwrap(),
                org,
                "33333333-3333-4333-8333-333333333333",
            ),
        )
        .unwrap();
        other_owner.public.lock().await.active_organization = Some(org.into());
        assert_eq!(
            other_owner
                .dispatch("runs.start_handoff.restore", restore.clone())
                .await
                .unwrap_err()
                .to_string(),
            "START_HANDOFF_NOT_FOUND"
        );
        drop(other_owner);

        // Restarting does not resume the handoff. The caller must explicitly
        // restore with the same key, which is a safe idempotent read.
        let reopened = fixture(
            temp.path(),
            Api::for_test_origin("http://127.0.0.1:9").unwrap(),
        );
        reopened.public.lock().await.active_organization = Some(org.into());
        assert_eq!(
            reopened
                .dispatch("runs.start_handoff.restore", restore)
                .await
                .unwrap(),
            first
        );
        assert_eq!(
            reopened
                .dispatch(
                    "runs.start_handoff.commit",
                    json!({"handoffRef":handoff_ref}),
                )
                .await
                .unwrap_err()
                .to_string(),
            "START_HANDOFF_UNAPPROVED"
        );
    }

    #[test]
    fn committed_v2_handoff_matches_its_published_output_contract() {
        let temp = tempfile::tempdir().unwrap();
        let daemon = fixture(
            temp.path(),
            Api::for_test_origin("http://127.0.0.1:9").unwrap(),
        );
        let handoff_ref = Uuid::new_v4().to_string();
        let preparation = Uuid::new_v4().to_string();
        let run = Uuid::new_v4().to_string();
        let result = json!({
            "execution":{"id":run},
            "preparationId":preparation,
            "executionPolicy":"host_user/v1",
            "confirmationKey":"must-not-project",
            "idempotencyKey":"must-not-project",
            "browserApproval":{"capability":"must-not-project"},
            "details":{},
        });
        let record = json!({
            "schemaVersion":"loomex.run-start-handoff/v2",
            "handoffRef":handoff_ref,
            "preparationId":preparation,
            "lifecycle":"committed",
            "approvalObserved":true,
            "runId":run,
            "result":result,
        });
        let projection = daemon
            .committed_start_handoff_result(&record, result)
            .unwrap();
        let catalog: Value =
            serde_json::from_str(include_str!("../contracts/method-catalog.json")).unwrap();
        let schema = &catalog["methods"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["name"] == "runs.start_handoff.commit")
            .unwrap()["outputSchema"]["oneOf"][0];
        assert!(normalize_output(projection.clone(), schema).is_ok());
        assert_eq!(projection["lifecycle"], "committed");
        assert!(!projection.to_string().contains("must-not-project"));
        assert_eq!(projection["execution"]["id"], run);
    }
    #[tokio::test]
    async fn legacy_uncommitted_start_handoff_cannot_be_promoted_or_committed() {
        let temp = tempfile::tempdir().unwrap();
        let daemon = fixture(
            temp.path(),
            Api::for_test_origin("http://127.0.0.1:9").unwrap(),
        );
        let org = "11111111-1111-4111-8111-111111111111";
        daemon.public.lock().await.active_organization = Some(org.into());
        let ticket = Uuid::new_v4().to_string();
        let preparation = Uuid::new_v4().to_string();
        state::write_json(
            &temp
                .path()
                .join("start-handoffs")
                .join(format!("{ticket}.json")),
            &json!({
                "schemaVersion":"loomex.run-start-handoff/v1",
                "ticket":ticket,
                "organizationId":org,
                "accountSubject":"22222222-2222-4222-8222-222222222222",
                "installationId":"00000000-0000-4000-8000-000000000001",
                "preparationId":preparation,
                "status":"ready",
            }),
        )
        .unwrap();
        assert_eq!(
            daemon
                .dispatch(
                    "runs.start_handoff.approve",
                    json!({"handoffRef":ticket,"idempotencyKey":Uuid::new_v4()})
                )
                .await
                .unwrap_err()
                .to_string(),
            "START_HANDOFF_APPROVAL_REJECTED"
        );
        assert_eq!(
            daemon
                .commit_run_start_handoff(org, &json!({"handoffRef":ticket}))
                .await
                .unwrap_err()
                .to_string(),
            "START_HANDOFF_UNAPPROVED"
        );
    }
    #[tokio::test]
    async fn presentation_dispatch_reloads_and_scopes_idempotency_to_account() {
        let temp = tempfile::tempdir().unwrap();
        let api = Api::for_test_origin("http://127.0.0.1:9").unwrap();
        let org = "11111111-1111-4111-8111-111111111111";
        let key = Uuid::new_v4();
        let params = json!({"kind":"browser","entityType":"catalog","entityId":"00000000-0000-0000-0000-000000000000","state":{"query":"active"},"idempotencyKey":key});
        let first = fixture(temp.path(), api.clone());
        first.public.lock().await.active_organization = Some(org.into());
        let first_result = first
            .dispatch("presentation.sessions.create", params.clone())
            .await
            .unwrap();
        drop(first);

        let other = Daemon::new(
            temp.path().into(),
            api.clone(),
            Auth::test_enrolled(api.clone(), org, "33333333-3333-4333-8333-333333333333"),
        )
        .unwrap();
        other.public.lock().await.active_organization = Some(org.into());
        let other_result = other
            .dispatch("presentation.sessions.create", params.clone())
            .await
            .unwrap();
        assert_ne!(first_result["viewSessionId"], other_result["viewSessionId"]);
        drop(other);

        let reopened = fixture(temp.path(), api);
        reopened.public.lock().await.active_organization = Some(org.into());
        assert_eq!(
            reopened
                .dispatch("presentation.sessions.create", params)
                .await
                .unwrap(),
            first_result
        );
    }
    #[tokio::test]
    async fn presentation_restore_dispatch_is_owner_scoped_and_read_only() {
        let temp = tempfile::tempdir().unwrap();
        let api = Api::for_test_origin("http://127.0.0.1:9").unwrap();
        let org = "11111111-1111-4111-8111-111111111111";
        let first = fixture(temp.path(), api.clone());
        first.public.lock().await.active_organization = Some(org.into());
        let created = first
            .dispatch(
                "presentation.sessions.create",
                json!({
                    "kind":"monitor",
                    "entityType":"execution",
                    "entityId":Uuid::new_v4(),
                    "state":{
                        "screen":"monitor",
                        "display":{"screen":"monitor","stageLabel":"Build"}
                    },
                    "idempotencyKey":Uuid::new_v4()
                }),
            )
            .await
            .unwrap();
        let id = created["viewSessionId"].as_str().unwrap();
        let restored = first
            .dispatch("presentation.sessions.restore", json!({"viewSessionId":id}))
            .await
            .unwrap();
        assert_eq!(
            restored["restoreVersion"],
            "presentation.sessions.restore/v1"
        );
        assert_eq!(restored["viewSessionId"], id);
        assert_eq!(
            restored["state"],
            json!({
                "screen":"monitor",
                "display":{"screen":"monitor","stageLabel":"Build"}
            })
        );
        assert_eq!(restored["details"], json!({}));
        assert!(restored.get("createdAt").is_none());
        assert!(restored.get("operation").is_none());

        let other = Daemon::new(
            temp.path().into(),
            api.clone(),
            Auth::test_enrolled(api, org, "33333333-3333-4333-8333-333333333333"),
        )
        .unwrap();
        other.public.lock().await.active_organization = Some(org.into());
        assert_eq!(
            other
                .dispatch("presentation.sessions.restore", json!({"viewSessionId":id}))
                .await
                .unwrap_err()
                .to_string(),
            "VIEW_SESSION_NOT_FOUND"
        );
    }
    #[tokio::test]
    async fn lifecycle_hook_passes_public_dispatch_without_a_follow_session() {
        let temp = tempfile::tempdir().unwrap();
        let api = Api::for_test_origin("http://127.0.0.1:9").unwrap();
        let daemon = fixture(temp.path(), api);
        daemon.public.lock().await.active_organization =
            Some("11111111-1111-4111-8111-111111111111".into());
        for event in ["SessionStart", "Stop", "Interrupt"] {
            let result = daemon.dispatch("follow.session.lifecycle", json!({
                "schemaVersion":"loomex.follow-session.lifecycle/v1", "event":event,
                "eventId":Uuid::new_v4(), "session":{"id":"unbound-test-session","cwd":"/tmp/unbound-test"}
            })).await.unwrap();
            assert_eq!(result["decision"], "allow");
        }
    }

    #[tokio::test]
    async fn recovery_dispatch_is_account_scoped_and_advertised() {
        let temp = tempfile::tempdir().unwrap();
        let api = Api::for_test_origin("http://127.0.0.1:9").unwrap();
        let org = "11111111-1111-4111-8111-111111111111";
        let daemon = fixture(temp.path(), api);
        daemon.public.lock().await.active_organization = Some(org.into());
        let binding = json!({"hostId":"local","hostTaskId":"task-1","runId":Uuid::new_v4()});
        let created = daemon
            .dispatch(
                "recovery.update",
                json!({"binding":binding,"expectedRevision":0,"initialization":"run_started","idempotencyKey":Uuid::new_v4()}),
            )
            .await
            .unwrap();
        assert_eq!(created["recovery"]["registrationState"], "not_attempted");
        let current = daemon
            .dispatch("recovery.get", json!({"binding":binding}))
            .await
            .unwrap();
        assert!(current["found"].as_bool().unwrap());
        assert!(negotiate(&json!({"supportedProtocols":[PROTOCOL],"requiredCapabilities":["recovery.coordination/v1","method:recovery.operations.begin"]})).is_ok());

        // The generic daemon idempotency cache must not replay the one-time
        // scheduling permit after a client loses the first response.
        let begin = json!({
            "binding": binding,
            "expectedRevision": 1,
            "operation": {
                "kind": "create",
                "arguments": {"marker": "loomex-follow-recovery:task-1"},
                "idempotencyKey": Uuid::new_v4(),
            },
            "idempotencyKey": Uuid::new_v4(),
        });
        let first = daemon
            .dispatch("recovery.operations.begin", begin.clone())
            .await
            .unwrap();
        assert_eq!(first["attemptPermitted"], true);
        let replay = daemon
            .dispatch("recovery.operations.begin", begin)
            .await
            .unwrap();
        assert_eq!(replay["attemptPermitted"], false);
        assert_eq!(replay["reconciliationRequired"], true);
    }
    #[tokio::test]
    async fn draft_mutation_cache_is_scoped_to_authenticated_account() {
        let temp = tempfile::tempdir().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let api =
            Api::for_test_origin(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
        let request = Uuid::new_v4();
        let request_for_server = request;
        let backend = tokio::spawn(async move {
            for revision in [1, 2] {
                let (stream, head) = receive_http(&listener).await;
                assert!(head.starts_with(&format!(
                    "PUT /api/v1/runner-control/runner/v1/human-requests/{request_for_server}/draft/ HTTP/1.1"
                )));
                reply_http(
                    stream,
                    200,
                    json!({"draft":{"requestId":request_for_server,"schemaDigest":"a".repeat(64),"answers":{"q":"answer"},"currentQuestionId":null,"phase":"review","revision":revision,"createdAt":1,"updatedAt":revision}}),
                )
                .await;
            }
        });
        let org = "11111111-1111-4111-8111-111111111111";
        let params = json!({"requestId":request,"expectedRevision":0,"answers":{"q":"answer"},"currentQuestionId":null,"phase":"review","expectedSchemaDigest":"a".repeat(64),"idempotencyKey":Uuid::new_v4()});
        for (runner, revision) in [
            ("22222222-2222-4222-8222-222222222222", 1),
            ("33333333-3333-4333-8333-333333333333", 2),
        ] {
            let daemon = Daemon::new(
                temp.path().into(),
                api.clone(),
                Auth::test_enrolled(api.clone(), org, runner),
            )
            .unwrap();
            daemon.public.lock().await.active_organization = Some(org.into());
            assert_eq!(
                daemon
                    .dispatch("interactions.draft.update", params.clone())
                    .await
                    .unwrap()["draft"]["revision"],
                revision
            );
        }
        backend.await.unwrap();
    }
    async fn receive_http(listener: &TcpListener) -> (tokio::net::TcpStream, String) {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut bytes = Vec::new();
        loop {
            let mut buffer = [0; 8192];
            let size = stream.read(&mut buffer).await.unwrap();
            assert!(size > 0);
            bytes.extend_from_slice(&buffer[..size]);
            if let Some(end) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
                let head = String::from_utf8_lossy(&bytes[..end]).into_owned();
                let length = head
                    .lines()
                    .find_map(|line| {
                        line.to_ascii_lowercase()
                            .strip_prefix("content-length: ")
                            .map(|value| value.parse::<usize>().unwrap())
                    })
                    .unwrap_or(0);
                if bytes.len() >= end + 4 + length {
                    return (stream, head);
                }
            }
        }
    }
    async fn reply_http(mut stream: tokio::net::TcpStream, status: u16, value: Value) {
        let body = if status == 200 {
            json!({"data":value,"meta":{}})
        } else {
            value
        }
        .to_string();
        stream.write_all(format!("HTTP/1.1 {status} Reply\r\nContent-Length: {}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{}",body.len(),body).as_bytes()).await.unwrap();
    }
    async fn local_call_with_capabilities(
        daemon: Arc<Daemon>,
        required_capabilities: Vec<&str>,
        method: &str,
        params: Value,
    ) -> Value {
        let (client, server) = UnixStream::pair().unwrap();
        let task = tokio::spawn(connection(server, daemon));
        let (read, mut write) = client.into_split();
        let mut read = BufReader::new(read);
        let negotiation = exchange(
            &mut read,
            &mut write,
            "protocol.negotiate",
            json!({
                "supportedProtocols": [PROTOCOL],
                "requiredCapabilities": required_capabilities
            }),
        )
        .await
        .unwrap();
        assert_eq!(negotiation["result"]["selectedProtocol"], PROTOCOL);
        let result = exchange(&mut read, &mut write, method, params)
            .await
            .unwrap();
        drop(write);
        task.abort();
        result
    }
    async fn download_fixture() -> (tempfile::TempDir, Arc<Daemon>, TcpListener, Value) {
        let temp = tempfile::tempdir().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let api =
            Api::for_test_origin(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
        let daemon = Arc::new(fixture(temp.path(), api));
        daemon.public.lock().await.active_organization =
            Some("11111111-1111-4111-8111-111111111111".into());
        let params = json!({"artifactId":Uuid::new_v4(),"idempotencyKey":Uuid::new_v4(),"destinationPath":temp.path().join("download")});
        (temp, daemon, listener, params)
    }
    fn download_page() -> Value {
        json!({"offset":0,"dataBase64":STANDARD.encode(b"abc"),"nextOffset":null,"sizeBytes":3,"checksumSha256":state::digest(b"abc")})
    }
    #[tokio::test]
    async fn offline_logout_requires_exclusive_daemon_ownership_and_retries_without_service() {
        let (temp, d, listener, _) = download_fixture().await;
        let first_lock = daemon_lock(temp.path()).unwrap();
        assert_eq!(
            daemon_lock(temp.path()).unwrap_err().to_string(),
            "DAEMON_ALREADY_RUNNING"
        );
        let auth = d.auth.clone();
        let check_auth = auth.clone();
        let task = tokio::spawn(finish_offline_logout(first_lock, auth));
        let (held, head) = receive_http(&listener).await;
        assert!(head.contains("/v2/device-authorities/logout/"));
        assert_eq!(
            daemon_lock(temp.path()).unwrap_err().to_string(),
            "DAEMON_ALREADY_RUNNING"
        );
        // Cancellation of the awaiting caller must not release ownership while
        // the authorized native-auth worker still has pending durable writes.
        task.abort();
        let _ = task.await;
        assert_eq!(
            daemon_lock(temp.path()).unwrap_err().to_string(),
            "DAEMON_ALREADY_RUNNING"
        );
        reply_http(held, 200, json!({"revoked":true})).await;
        for _ in 0..100 {
            if !check_auth.status().await.unwrap()["authenticated"]
                .as_bool()
                .unwrap()
            {
                break;
            }
            tokio::task::yield_now().await;
        }
        let retry_lock = daemon_lock(temp.path()).unwrap();
        let result = finish_offline_logout(retry_lock, check_auth).await.unwrap();
        assert_eq!(result["revoked"], true);
        assert_eq!(result["alreadyLoggedOut"], true);
        assert!(!temp.path().join("control.sock").exists());
        assert!(!temp.path().join("jobs").exists());
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(30), listener.accept())
                .await
                .is_err()
        );
    }
    #[tokio::test]
    async fn held_download_allows_drain_and_cancel_and_preserves_singleflight() {
        let (temp, d, listener, params) = download_fixture().await;
        let d1 = d.clone();
        let p1 = params.clone();
        let first = tokio::spawn(async move { d1.dispatch("artifacts.download", p1).await });
        let (held, _) = receive_http(&listener).await;
        let d2 = d.clone();
        let p2 = params.clone();
        let duplicate = tokio::spawn(async move { d2.dispatch("artifacts.download", p2).await });
        for _ in 0..100 {
            if d.managed_work() == 2 {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(d.managed_work(), 2);
        let drain = tokio::time::timeout(
            std::time::Duration::from_millis(200),
            d.dispatch("daemon.drain", json!({"idempotencyKey":Uuid::new_v4()})),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(drain["activeJobs"], 2);
        assert_eq!(drain["updateDeferred"], true);
        assert!(temp.path().join("drain.json").exists());
        let cancel_params = json!({"runId":Uuid::new_v4(),"reason":"user requested","idempotencyKey":Uuid::new_v4()});
        let dc = d.clone();
        let pc = cancel_params.clone();
        let cancel = tokio::spawn(async move { dc.dispatch("runs.cancel", pc).await });
        let (stream, head) = tokio::time::timeout(
            std::time::Duration::from_millis(200),
            receive_http(&listener),
        )
        .await
        .unwrap();
        assert!(head.contains("/cancel/"));
        reply_http(
            stream,
            200,
            json!({"execution":{"id":cancel_params["runId"]},"jobs":[]}),
        )
        .await;
        cancel.await.unwrap().unwrap();
        assert_eq!(d.managed_work(), 2);
        reply_http(held, 200, download_page()).await;
        let first = first.await.unwrap().unwrap();
        let duplicate = duplicate.await.unwrap().unwrap();
        assert_eq!(first, duplicate);
        assert_eq!(std::fs::read(temp.path().join("download")).unwrap(), b"abc");
        assert_eq!(d.managed_work(), 0);
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(30), listener.accept())
                .await
                .is_err()
        );
        let new_key = Uuid::new_v4();
        let repeat = d
            .dispatch("daemon.drain", json!({"idempotencyKey":new_key}))
            .await
            .unwrap();
        assert_eq!(repeat["activeJobs"], 0);
        assert!(
            !temp
                .path()
                .join("operations")
                .join(format!("{new_key}.json"))
                .exists()
        );
        let fresh_cancel =
            json!({"idempotencyKey":Uuid::new_v4(),"runId":Uuid::new_v4(),"reason":"too late"});
        assert_eq!(
            d.dispatch("runs.cancel", fresh_cancel)
                .await
                .unwrap_err()
                .to_string(),
            "RUNNER_NOT_READY"
        );
        assert_eq!(d.managed_work(), 0);
    }
    #[tokio::test]
    async fn queued_retry_keeps_organization_captured_before_selection_changes() {
        let (_temp, d, listener, params) = download_fixture().await;
        let d1 = d.clone();
        let p1 = params.clone();
        let first = tokio::spawn(async move { d1.dispatch("artifacts.download", p1).await });
        let (held, _) = receive_http(&listener).await;
        let d2 = d.clone();
        let p2 = params.clone();
        let retry = tokio::spawn(async move { d2.dispatch("artifacts.download", p2).await });
        for _ in 0..100 {
            if d.managed_work() == 2 {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(d.managed_work(), 2);
        // The replacement selection has no credential. A substituted organization
        // would fail locally, whereas the queued request must retain the original.
        d.public.lock().await.active_organization = Some(Uuid::new_v4().to_string());
        reply_http(held, 503, json!({"error":{"code":"BACKEND_UNAVAILABLE"}})).await;
        assert!(first.await.unwrap().is_err());
        let (stream, _) =
            tokio::time::timeout(std::time::Duration::from_secs(1), receive_http(&listener))
                .await
                .unwrap();
        reply_http(stream, 200, download_page()).await;
        assert_eq!(retry.await.unwrap().unwrap()["sizeBytes"], 3);
        assert_eq!(d.managed_work(), 0);
        assert_eq!(
            d.dispatch("artifacts.download", params)
                .await
                .unwrap_err()
                .to_string(),
            "IDEMPOTENCY_CONFLICT"
        );
    }
    #[tokio::test]
    async fn large_backend_read_keeps_coverage_until_response_spool_is_durable() {
        let (temp, d, listener, _) = download_fixture().await;
        let run = Uuid::new_v4();
        let worker = d.clone();
        let read =
            tokio::spawn(async move { worker.dispatch("runs.get", json!({"runId":run})).await });
        let (held, _) = receive_http(&listener).await;
        let drain = d
            .dispatch("daemon.drain", json!({"idempotencyKey":Uuid::new_v4()}))
            .await
            .unwrap();
        assert_eq!(drain["activeJobs"], 1);
        reply_http(held,200,json!({"execution":{"id":run,"data":"x".repeat(MAX_FRAME+100)},"events":[],"latestSequence":0,"hasMoreEvents":false,"timedOut":false})).await;
        let reference = read.await.unwrap().unwrap();
        let id = reference["responseRef"].as_str().unwrap();
        assert_eq!(d.managed_work(), 0);
        let bytes =
            std::fs::read(temp.path().join("responses").join(format!("{id}.json"))).unwrap();
        assert_eq!(
            state::digest(&bytes),
            reference["checksumSha256"].as_str().unwrap()
        );
        let projected: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            projected["details"]["monitoring"]["schemaVersion"],
            "loomex.monitoring-observation/v1"
        );
        assert_eq!(projected["details"]["monitoring"]["runId"], json!(run));
        assert_eq!(projected["details"]["monitoring"]["guarantee"], "none");
        assert_eq!(
            projected["details"]["monitoring"]["follow"]["recordCount"],
            0
        );
        assert_eq!(
            projected["details"]["monitoring"]["recovery"]["recordCount"],
            0
        );
        assert!(
            temp.path()
                .join("responses")
                .join(format!("{id}.meta.json"))
                .exists()
        );
        assert!(
            temp.path()
                .join("responses")
                .join(format!("{id}.sha256"))
                .exists()
        );
        assert_eq!(
            d.dispatch("runs.get", json!({"runId":run}))
                .await
                .unwrap_err()
                .to_string(),
            "RUNNER_NOT_READY"
        );
    }
    #[tokio::test]
    async fn socket_negotiation_rejects_incompatible_mutations_without_effects() {
        let temp = tempfile::tempdir().unwrap();
        let api = Api::for_test_origin("http://127.0.0.1:9").unwrap();
        let d = Arc::new(fixture(temp.path(), api));
        let listener = UnixListener::bind(temp.path().join("test.sock")).unwrap();
        let client = UnixStream::connect(temp.path().join("test.sock"))
            .await
            .unwrap();
        let (server, _) = listener.accept().await.unwrap();
        let task = tokio::spawn(connection(server, d.clone()));
        let (r, mut w) = client.into_split();
        let mut r = BufReader::new(r);
        let mutation = json!({"idempotencyKey":Uuid::new_v4()});
        let reply = exchange(&mut r, &mut w, "daemon.drain", mutation.clone())
            .await
            .unwrap();
        assert_eq!(reply["error"]["code"], "COMPATIBILITY_ERROR");
        for offer in [
            json!({"supportedProtocols":[PROTOCOL],"requiredCapabilities":["unknown.required/v1"]}),
            json!({"supportedProtocols":["unknown.protocol/v1"],"requiredCapabilities":[]}),
        ] {
            let reply = exchange(&mut r, &mut w, "protocol.negotiate", offer)
                .await
                .unwrap();
            assert_eq!(reply["error"]["code"], "COMPATIBILITY_ERROR");
            let reply = exchange(&mut r, &mut w, "daemon.drain", mutation.clone())
                .await
                .unwrap();
            assert_eq!(reply["error"]["code"], "COMPATIBILITY_ERROR");
            assert!(!d.execution.is_draining());
            assert!(!temp.path().join("drain.json").exists());
            assert!(!temp.path().join("operations").exists());
        }
        let reply=exchange(&mut r,&mut w,"protocol.negotiate",json!({"supportedProtocols":["future.protocol/v1",PROTOCOL],"requiredCapabilities":["method:daemon.drain","authorization.prepare-commit/v1"]})).await.unwrap();
        assert_eq!(reply["result"]["selectedProtocol"], PROTOCOL);
        assert_eq!(reply["result"]["maxFrameBytes"], MAX_FRAME);
        assert_eq!(reply["result"]["serverVersion"], env!("CARGO_PKG_VERSION"));
        let reply = exchange(&mut r, &mut w, "daemon.drain", mutation)
            .await
            .unwrap();
        assert_eq!(reply["result"]["draining"], true);
        assert!(temp.path().join("drain.json").exists());
        drop(w);
        task.abort();
    }
    #[tokio::test]
    async fn validation_error_extension_is_sent_only_to_clients_that_negotiate_it() {
        let temp = tempfile::tempdir().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let api =
            Api::for_test_origin(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
        let daemon = Arc::new(fixture(temp.path(), api));
        daemon.public.lock().await.active_organization =
            Some("11111111-1111-4111-8111-111111111111".into());
        let backend = tokio::spawn(async move {
            for _ in 0..2 {
                let (stream, head) = receive_http(&listener).await;
                assert!(
                    head.starts_with("GET /api/v1/runner-control/runner/v1/workflows/ HTTP/1.1")
                );
                reply_http(
                    stream,
                    422,
                    json!({
                        "error": {
                            "code": "RUN_VALIDATION_FAILED",
                            "message": "Bearer backend-message-must-not-cross",
                            "details": {
                                "validationIssueVersion": "v1",
                                "validationIssues": [{
                                    "code": "RUN_VALIDATION_PROVIDER_INVALID",
                                    "message": "Bearer issue-message-must-not-cross",
                                    "nextAction": "exfiltrate_credentials",
                                    "nodeIndex": 3,
                                    "nodeId": "secret-authored-node-key",
                                    "nodeName": "Bearer secret-node-name"
                                }],
                                "credential": "Bearer never-print-this-token"
                            }
                        },
                        "meta": {}
                    }),
                )
                .await;
            }
        });

        let old_client = local_call_with_capabilities(
            daemon.clone(),
            vec!["method:workflows.list"],
            "workflows.list",
            json!({}),
        )
        .await;
        let old_error = old_client["error"].as_object().unwrap();
        assert_eq!(old_error["code"], "RUN_VALIDATION_FAILED");
        assert_eq!(old_error.len(), 4);
        assert!(!old_error.contains_key("data"));
        assert!(!old_client.to_string().contains("never-print"));

        let new_client = local_call_with_capabilities(
            daemon,
            vec![
                "method:workflows.list",
                VALIDATION_ERRORS_CAPABILITY,
                "error.recovery/v1",
            ],
            "workflows.list",
            json!({}),
        )
        .await;
        assert_eq!(new_client["error"]["code"], "RUN_VALIDATION_FAILED");
        assert_eq!(new_client["error"]["recovery"], "correct_input");
        assert_eq!(new_client["error"]["outcome"], "rejected");
        assert_eq!(
            new_client["error"]["data"],
            json!({
                "validationIssueVersion": "v1",
                "validationIssues": [{
                    "code": "RUN_VALIDATION_PROVIDER_INVALID",
                    "message": "The workflow selects a provider that cannot run this work.",
                    "nextAction": "choose_supported_provider",
                    "nodeIndex": 3
                }]
            })
        );
        let serialized = new_client.to_string();
        assert!(!serialized.contains("never-print"));
        assert!(!serialized.contains("secret-authored-node-key"));
        assert!(!serialized.contains("secret-node-name"));
        assert!(!serialized.contains("exfiltrate_credentials"));
        backend.await.unwrap();
    }
    #[tokio::test]
    async fn cli_negotiates_and_sends_action_on_one_unix_connection() {
        let temp = tempfile::tempdir().unwrap();
        let socket = temp.path().join("control.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (r, mut w) = stream.into_split();
            let mut r = BufReader::new(r);
            let request: Value =
                serde_json::from_slice(&read_frame(&mut r).await.unwrap().unwrap()).unwrap();
            assert_eq!(request["method"], "protocol.negotiate");
            assert!(
                request["params"]["requiredCapabilities"]
                    .as_array()
                    .unwrap()
                    .contains(&json!("method:status.get"))
            );
            let mut reply=serde_json::to_vec(&json!({"protocol":PROTOCOL,"id":request["id"],"result":negotiate(&request["params"]).unwrap()})).unwrap();
            reply.push(b'\n');
            w.write_all(&reply).await.unwrap();
            let action: Value =
                serde_json::from_slice(&read_frame(&mut r).await.unwrap().unwrap()).unwrap();
            assert_eq!(action["method"], "status.get");
            assert_ne!(action["id"], request["id"]);
            let mut reply = serde_json::to_vec(
                &json!({"protocol":PROTOCOL,"id":action["id"],"result":{"activeJobs":0}}),
            )
            .unwrap();
            reply.push(b'\n');
            w.write_all(&reply).await.unwrap();
        });
        let result = client(temp.path(), "status.get", json!({})).await.unwrap();
        assert_eq!(result["result"]["activeJobs"], 0);
        server.await.unwrap();
    }
    #[tokio::test]
    async fn stale_socket_connection_is_a_safe_runner_unavailable_error() {
        let temp = tempfile::tempdir().unwrap();
        let socket = temp.path().join("control.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
        drop(listener);
        let error = client(temp.path(), "status.get", json!({}))
            .await
            .unwrap_err();
        assert_eq!(public_error(&error).0, "RUNNER_UNAVAILABLE");
    }
    #[tokio::test]
    async fn socket_protocol_and_safe_error_are_credential_free() {
        let temp = tempfile::tempdir().unwrap();
        let api = Api::for_test_origin("http://127.0.0.1:9").unwrap();
        let d = Arc::new(fixture(temp.path(), api));
        let (client, server) = UnixStream::pair().unwrap();
        let task = tokio::spawn(connection(server, d));
        let (r, mut w) = client.into_split();
        let mut r = BufReader::new(r);
        let handshake = exchange(
            &mut r,
            &mut w,
            "protocol.negotiate",
            json!({"supportedProtocols":[PROTOCOL],"requiredCapabilities":["method:status.get"]}),
        )
        .await
        .unwrap();
        assert_eq!(handshake["result"]["selectedProtocol"], PROTOCOL);
        w.write_all(b"{\"protocol\":\"loomex.local-control/v2\",\"id\":\"a\",\"method\":\"status.get\",\"params\":{}}\n").await.unwrap();
        let frame = read_frame(&mut r).await.unwrap().unwrap();
        let response: Value = serde_json::from_slice(&frame).unwrap();
        assert_eq!(response["result"]["activeJobs"], 0);
        assert!(!String::from_utf8(frame).unwrap().contains("testsecret"));
        w.write_all(
            b"{\"protocol\":\"old\",\"id\":\"b\",\"method\":\"status.get\",\"params\":{}}\n",
        )
        .await
        .unwrap();
        let response: Value =
            serde_json::from_slice(&read_frame(&mut r).await.unwrap().unwrap()).unwrap();
        assert_eq!(response["error"]["code"], "PROTOCOL_MISMATCH");
        assert_eq!(response["id"], "b");
        assert!(response["error"]["correlationId"].is_string());
        drop(w);
        task.abort();
    }
    #[tokio::test]
    async fn uncorrelatable_frames_close_without_a_response() {
        for frame in [
            b"not-json\n".as_slice(),
            b"{\"protocol\":\"loomex.local-control/v2\",\"method\":\"status.get\",\"params\":{}}\n"
                .as_slice(),
        ] {
            let temp = tempfile::tempdir().unwrap();
            let api = Api::for_test_origin("http://127.0.0.1:9").unwrap();
            let daemon = Arc::new(fixture(temp.path(), api));
            let (client, server) = UnixStream::pair().unwrap();
            let task = tokio::spawn(connection(server, daemon));
            let (mut read, mut write) = client.into_split();
            write.write_all(frame).await.unwrap();
            write.shutdown().await.unwrap();
            let mut response = Vec::new();
            read.read_to_end(&mut response).await.unwrap();
            assert!(response.is_empty());
            task.await.unwrap().unwrap();
        }
    }
    #[tokio::test]
    async fn oversized_frame_closes_without_a_response() {
        let temp = tempfile::tempdir().unwrap();
        let api = Api::for_test_origin("http://127.0.0.1:9").unwrap();
        let daemon = Arc::new(fixture(temp.path(), api));
        let (client, server) = UnixStream::pair().unwrap();
        let task = tokio::spawn(connection(server, daemon));
        let (mut read, mut write) = client.into_split();
        let frame = vec![b'x'; MAX_FRAME + 1];
        let _ = write.write_all(&frame).await;
        let _ = write.shutdown().await;
        let mut response = Vec::new();
        read.read_to_end(&mut response).await.unwrap();
        assert!(response.is_empty());
        task.await.unwrap().unwrap();
    }
    #[tokio::test]
    async fn correlatable_invalid_envelope_returns_the_request_id() {
        let temp = tempfile::tempdir().unwrap();
        let api = Api::for_test_origin("http://127.0.0.1:9").unwrap();
        let daemon = Arc::new(fixture(temp.path(), api));
        let (client, server) = UnixStream::pair().unwrap();
        let task = tokio::spawn(connection(server, daemon));
        let (reader, mut writer) = client.into_split();
        let mut reader = BufReader::new(reader);
        writer
            .write_all(
                b"{\"protocol\":\"loomex.local-control/v2\",\"id\":\"known-id\",\"method\":\"status.get\"}\n",
            )
            .await
            .unwrap();
        let response: Value =
            serde_json::from_slice(&read_frame(&mut reader).await.unwrap().unwrap()).unwrap();
        assert_eq!(response["id"], "known-id");
        assert_eq!(response["error"]["code"], "INVALID_REQUEST");
        drop(writer);
        task.abort();
    }
    #[tokio::test]
    async fn prepare_commit_pins_grant_confirmation_and_idempotency() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let api =
            Api::for_test_origin(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let counter = calls.clone();
        let prep = Uuid::new_v4().to_string();
        let prep_server = prep.clone();
        let run = Uuid::new_v4().to_string();
        let run_server = run.clone();
        let backend = tokio::spawn(async move {
            for index in 0..2 {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut buf = Vec::new();
                loop {
                    let mut b = [0; 4096];
                    let n = stream.read(&mut b).await.unwrap();
                    buf.extend_from_slice(&b[..n]);
                    if let Some(end) = buf.windows(4).position(|x| x == b"\r\n\r\n") {
                        let headers = String::from_utf8_lossy(&buf[..end]);
                        let length: usize = headers
                            .lines()
                            .find_map(|line| {
                                line.to_ascii_lowercase()
                                    .strip_prefix("content-length: ")
                                    .map(|v| v.parse().unwrap())
                            })
                            .unwrap();
                        if buf.len() >= end + 4 + length {
                            assert!(
                                headers
                                    .to_ascii_lowercase()
                                    .contains("x-loomex-runner-proof:")
                            );
                            let body: Value = serde_json::from_slice(&buf[end + 4..]).unwrap();
                            let data = if index == 0 {
                                assert!(headers.starts_with(
                                    "POST /api/v1/runner-control/runner/v2/executions/prepare/"
                                ));
                                assert_eq!(body["executionPolicy"], "host_user/v1");
                                let mut binding = body;
                                binding["organizationId"] =
                                    json!("11111111-1111-4111-8111-111111111111");
                                binding["runnerId"] = json!("22222222-2222-4222-8222-222222222222");
                                json!({"preparationId":prep_server,"bindingDigest":"digest","binding":binding,"limits":{},"expiresAt":null})
                            } else {
                                assert_eq!(body["preparationId"], prep_server);
                                // The backend currently returns this legacy
                                // top-level alias with its richer execution
                                // projection. It exercises normalization after
                                // the runner adds its follow continuation.
                                json!({"execution":{"id":run_server},"executionId":run_server,"preparationId":prep_server,"executionPolicy":"host_user/v1"})
                            };
                            let text = json!({"data":data,"meta":{}}).to_string();
                            stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{}",text.len(),text).as_bytes()).await.unwrap();
                            counter.fetch_add(1, Ordering::SeqCst);
                            break;
                        }
                    }
                }
            }
        });
        let temp = tempfile::tempdir().unwrap();
        let workspace = temp.path().join("workspace");
        std::fs::create_dir(&workspace).unwrap();
        let state_dir = temp.path().join("state");
        let d = fixture(&state_dir, api.clone());
        let org = "11111111-1111-4111-8111-111111111111";
        d.public.lock().await.active_organization = Some(org.into());
        let p = json!({"workflowId":Uuid::new_v4(),"versionId":Uuid::new_v4(),"workspacePath":workspace,"idempotencyKey":Uuid::new_v4()});
        assert!(
            d.dispatch("runs.prepare", p.clone())
                .await
                .unwrap_err()
                .to_string()
                .contains("WORKSPACE_DENIED")
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        d.dispatch(
            "workspaces.grant",
            json!({"workspacePath":workspace,"idempotencyKey":Uuid::new_v4()}),
        )
        .await
        .unwrap();
        let prepared = d.dispatch("runs.prepare", p.clone()).await.unwrap();
        assert!(prepared["confirmationKey"].is_string());
        let restored = d
            .dispatch("preparations.get", json!({"preparationId":prep}))
            .await
            .unwrap();
        assert_eq!(restored["status"], "valid");
        assert_eq!(restored["operation"], "runs.prepare");
        assert_eq!(restored["preparation"], prepared);
        let run_record_path = state_dir.join("preparations").join(format!("{prep}.json"));
        let run_record: Value = state::read_json(&run_record_path).unwrap();
        for operation in ["builder.prepare", "editor.prepare"] {
            let id = Uuid::new_v4().to_string();
            let mut record = run_record.clone();
            record["operation"] = json!(operation);
            record["review"]["preparationId"] = json!(id);
            state::write_json(
                &state_dir.join("preparations").join(format!("{id}.json")),
                &record,
            )
            .unwrap();
            let restored = d
                .dispatch("preparations.get", json!({"preparationId":id}))
                .await
                .unwrap();
            assert_eq!(restored["status"], "valid");
            assert_eq!(restored["operation"], operation);
            assert_eq!(restored["preparation"], record["review"]);
        }
        drop(d);

        let other = Daemon::new(
            state_dir.clone(),
            api.clone(),
            Auth::test_enrolled(api.clone(), org, "33333333-3333-4333-8333-333333333333"),
        )
        .unwrap();
        assert_eq!(
            other
                .dispatch("preparations.get", json!({"preparationId":prep}))
                .await
                .unwrap_err()
                .to_string(),
            "PREPARATION_NOT_FOUND"
        );
        other.public.lock().await.grants.clear();
        assert_eq!(
            other
                .dispatch("runs.prepare", p)
                .await
                .unwrap_err()
                .to_string(),
            "WORKSPACE_DENIED"
        );
        drop(other);

        let d = fixture(&state_dir, api.clone());
        let record_path = state_dir.join("preparations").join(format!("{prep}.json"));
        let record: Value = state::read_json(&record_path).unwrap();
        let mut changed = record.clone();
        changed["review"]["expiresAt"] = json!(0);
        state::write_json(&record_path, &changed).unwrap();
        assert_eq!(
            d.dispatch("preparations.get", json!({"preparationId":prep}))
                .await
                .unwrap()["reason"],
            "expired"
        );
        changed = record.clone();
        changed["providers"] = json!({"notInstalled":{}});
        state::write_json(&record_path, &changed).unwrap();
        assert_eq!(
            d.dispatch("preparations.get", json!({"preparationId":prep}))
                .await
                .unwrap()["reason"],
            "provider_changed"
        );
        changed = record.clone();
        changed["review"]["bindingDigest"] = json!("tampered");
        state::write_json(&record_path, &changed).unwrap();
        assert_eq!(
            d.dispatch("preparations.get", json!({"preparationId":prep}))
                .await
                .unwrap()["reason"],
            "record_invalid"
        );
        state::write_json(&record_path, &record).unwrap();
        d.dispatch(
            "workspaces.revoke",
            json!({"workspacePath":workspace,"idempotencyKey":Uuid::new_v4()}),
        )
        .await
        .unwrap();
        assert_eq!(
            d.dispatch("preparations.get", json!({"preparationId":prep}))
                .await
                .unwrap()["reason"],
            "workspace_changed"
        );
        d.dispatch(
            "workspaces.grant",
            json!({"workspacePath":workspace,"idempotencyKey":Uuid::new_v4()}),
        )
        .await
        .unwrap();
        let mut commit = json!({"preparationId":prep,"bindingDigest":"digest","confirmationKey":Uuid::new_v4(),"idempotencyKey":Uuid::new_v4()});
        assert!(
            d.dispatch("runs.commit", commit.clone())
                .await
                .unwrap_err()
                .to_string()
                .contains("PRECONDITION_FAILED")
        );
        commit["confirmationKey"] = prepared["confirmationKey"].clone();
        commit["idempotencyKey"] = json!(Uuid::new_v4());
        let result = d.dispatch("runs.commit", commit.clone()).await.unwrap();
        assert_eq!(
            result["details"]["followContinuation"]["schemaVersion"],
            "loomex.follow-session.continuation/v1"
        );
        assert_eq!(result["details"]["followContinuation"]["runId"], run);
        assert_eq!(
            result["details"]["followContinuation"]["source"],
            "generated_markdown"
        );
        assert!(
            result["details"]["followContinuation"]["receipt"]
                .as_str()
                .is_some_and(|receipt| !receipt.is_empty())
        );
        let authorized_commit = commit.clone();
        let stale = d
            .dispatch("preparations.get", json!({"preparationId":prep}))
            .await
            .unwrap();
        assert_eq!(stale["reason"], "commit_started");
        assert_eq!(stale["nextAction"], "reconcile_operation");
        assert_eq!(stale["executionId"], run);
        assert!(stale.get("preparation").is_none());
        assert_eq!(
            d.dispatch("runs.commit", commit.clone()).await.unwrap(),
            result
        );
        commit["bindingDigest"] = json!("changed");
        assert_eq!(
            d.dispatch("runs.commit", commit)
                .await
                .unwrap_err()
                .to_string(),
            "IDEMPOTENCY_CONFLICT"
        );
        backend.await.unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        drop(d);
        let other = Daemon::new(
            state_dir,
            api.clone(),
            Auth::test_enrolled(api, org, "33333333-3333-4333-8333-333333333333"),
        )
        .unwrap();
        assert_eq!(
            other
                .dispatch("runs.commit", authorized_commit)
                .await
                .unwrap_err()
                .to_string(),
            "PRECONDITION_FAILED"
        );
    }
    #[tokio::test]
    async fn large_response_spool_pages_are_complete() {
        let t = tempfile::tempdir().unwrap();
        let id = Uuid::new_v4();
        let payload = vec![b'z'; MAX_FRAME * 3 + 91];
        state::atomic_write(
            &t.path().join("responses").join(format!("{id}.json")),
            &payload,
        )
        .unwrap();
        state::atomic_write(
            &t.path().join("responses").join(format!("{id}.sha256")),
            state::digest(&payload).as_bytes(),
        )
        .unwrap();
        let mut gathered = Vec::new();
        let mut offset = 0;
        loop {
            let page = read_spool(t.path(), &json!({"responseRef":id,"offset":offset}))
                .await
                .unwrap();
            gathered.extend(
                STANDARD
                    .decode(page["dataBase64"].as_str().unwrap())
                    .unwrap(),
            );
            if page["nextOffset"].is_null() {
                break;
            }
            offset = page["nextOffset"].as_u64().unwrap();
        }
        assert_eq!(gathered, payload);
    }
}

#[cfg(test)]
mod lifecycle_tests {
    use super::*;
    #[tokio::test]
    async fn drain_is_durable_across_daemon_reconstruction() {
        let t = tempfile::tempdir().unwrap();
        let api = Api::for_test_origin("http://127.0.0.1:9").unwrap();
        let d = Daemon::new(
            t.path().into(),
            api.clone(),
            Auth::test_unauthed(api.clone()),
        )
        .unwrap();
        let result = d
            .dispatch("daemon.drain", json!({"idempotencyKey":Uuid::new_v4()}))
            .await
            .unwrap();
        assert_eq!(result["draining"], true);
        let reopened = Daemon::new(t.path().into(), api.clone(), Auth::test_unauthed(api)).unwrap();
        assert!(reopened.execution.is_draining());
        assert_eq!(
            reopened.dispatch("status.get", json!({})).await.unwrap()["draining"],
            true
        );
    }
    #[test]
    fn finalize_confirmation_and_run_filters_reach_canonical_backend() {
        let id = Uuid::new_v4().to_string();
        let (_, route, body) = backend_route(
            "editor.finalize",
            &json!({"sessionId":id,"confirm":true,"idempotencyKey":Uuid::new_v4()}),
        )
        .unwrap();
        assert!(route.ends_with("/finalize/"));
        assert_eq!(body.unwrap()["confirm"], true);
        let (_, route, _) =
            backend_route("runs.list", &json!({"workflowId":id,"status":"failed"})).unwrap();
        assert!(route.contains("workflowId="));
        assert!(route.contains("status=failed"));
        let request = Uuid::new_v4();
        let (_, route, body) = backend_route(
            "interactions.draft.update",
            &json!({"requestId":request,"expectedRevision":2,"answers":{"q":"answer"},"currentQuestionId":null,"phase":"review","expectedSchemaDigest":"a".repeat(64),"idempotencyKey":Uuid::new_v4()}),
        )
        .unwrap();
        assert!(route.ends_with(&format!("human-requests/{request}/draft/")));
        let body = body.unwrap();
        assert_eq!(body["expectedRevision"], 2);
        assert_eq!(body["currentQuestionId"], Value::Null);
        assert!(body.get("requestId").is_none());
        assert!(body.get("idempotencyKey").is_none());
    }
    #[test]
    fn backend_float_representation_is_preserved_in_payload_digest() {
        let payload: Value = serde_json::from_str("{\"z\":1e-06,\"a\":0.00001}").unwrap();
        assert_eq!(
            state::json_digest(&payload),
            state::digest(b"{\"a\":0.00001,\"z\":1e-06}")
        );
    }
    #[tokio::test]
    async fn duplicate_daemon_is_rejected_and_real_socket_is_owner_only() {
        let t = tempfile::tempdir().unwrap();
        let api = Api::for_test_origin("http://127.0.0.1:9").unwrap();
        let d = Arc::new(
            Daemon::new(
                t.path().into(),
                api.clone(),
                Auth::test_unauthed(api.clone()),
            )
            .unwrap(),
        );
        let running = tokio::spawn(serve(d));
        for _ in 0..100 {
            if t.path().join("control.sock").exists() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        let metadata = std::fs::metadata(t.path().join("control.sock")).unwrap();
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        let duplicate =
            Arc::new(Daemon::new(t.path().into(), api.clone(), Auth::test_unauthed(api)).unwrap());
        assert_eq!(
            serve(duplicate).await.unwrap_err().to_string(),
            "DAEMON_ALREADY_RUNNING"
        );
        let response = client(t.path(), "status.get", json!({})).await.unwrap();
        assert_eq!(response["result"]["protocol"], PROTOCOL);
        running.abort();
    }
}
