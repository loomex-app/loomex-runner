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
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
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
    "auth.device-v2/v1",
    "transfer.chunked/v1",
    VALIDATION_ERRORS_CAPABILITY,
];
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
    pub draining: AtomicBool,
    pub active: AtomicUsize,
    pub quiescence: AtomicUsize,
    pub managed: AtomicUsize,
    pub cancellations: Mutex<HashMap<String, Arc<AtomicBool>>>,
    mutation_keys: std::sync::Mutex<HashMap<String, MutationKey>>,
    lifecycle_draining: AtomicBool,
    pub admission: std::sync::Mutex<()>,
}
struct ControlWriter<'a>(&'a Daemon);
impl Drop for ControlWriter<'_> {
    fn drop(&mut self) {
        self.0.managed.fetch_sub(1, Ordering::SeqCst);
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
            draining: AtomicBool::new(draining),
            active: AtomicUsize::new(0),
            quiescence: AtomicUsize::new(0),
            managed: AtomicUsize::new(0),
            cancellations: Mutex::new(HashMap::new()),
            mutation_keys: std::sync::Mutex::new(HashMap::new()),
            lifecycle_draining: AtomicBool::new(draining),
            admission: std::sync::Mutex::new(()),
        })
    }
    pub fn managed_work(&self) -> usize {
        self.managed.load(Ordering::SeqCst)
    }
    /// Work that owns or is about to own a provider process. Ordinary control
    /// RPCs are deliberately excluded: they must not make a connected account
    /// appear to have running workflow work or indefinitely block logout.
    pub fn execution_work(&self) -> usize {
        self.active
            .load(Ordering::SeqCst)
            .saturating_add(self.quiescence.load(Ordering::SeqCst))
    }
    fn reported_work(&self) -> usize {
        if self.draining.load(Ordering::SeqCst) {
            self.managed_work()
        } else {
            self.active.load(Ordering::SeqCst)
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
        let _admission = self
            .admission
            .lock()
            .map_err(|_| anyhow::anyhow!("INTERNAL"))?;
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
                self.managed
                    .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |count| {
                        count.checked_add(1).filter(|_| count > 0)
                    })
                    .map_err(|_| anyhow::anyhow!("RUNNER_NOT_READY"))?;
                return Ok(Some(ControlWriter(self)));
            }
        } else if self.draining.load(Ordering::SeqCst)
            && write
            && ![
                "auth.login",
                "auth.poll",
                "auth.logout",
                "organizations.select",
                "daemon.drain",
                "runs.cancel",
            ]
            .contains(&method)
        {
            bail!("RUNNER_NOT_READY");
        }
        self.managed.fetch_add(1, Ordering::SeqCst);
        if method == "daemon.drain" {
            self.lifecycle_draining.store(true, Ordering::SeqCst);
            self.draining.store(true, Ordering::SeqCst);
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
        let key = params.get("idempotencyKey").and_then(Value::as_str);
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
        let operation = (!method.starts_with("recovery."))
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
                if !(method == "auth.poll" && result["status"] == "pending") {
                    state::write_json(
                        path,
                        &json!({"digest":identity,"method":method,"cachedAt":state::now(),"executionId":execution,"result":result}),
                    )?;
                }
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
                    json!({"version":env!("CARGO_PKG_VERSION"),"protocol":PROTOCOL,"activeJobs":self.reported_work(),"draining":self.draining.load(Ordering::SeqCst),"updateDeferred":self.dir.join("pending-update.json").exists()}),
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
            "auth.poll" => return self.auth.poll(key.unwrap(), required(p, "flowId")?).await,
            "auth.status" => return self.auth.status().await,
            "auth.logout" => {
                {
                    let _admission = self
                        .admission
                        .lock()
                        .map_err(|_| anyhow::anyhow!("INTERNAL"))?;
                    // Refuse before changing a cancellation token when a
                    // provider execution is live or in its fenced admission
                    // window. Ordinary control reads do not count as work.
                    if self.execution_work() > 0 {
                        bail!("ACTIVE_WORK_REQUIRES_DRAIN");
                    }
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
                    let _admission = self
                        .admission
                        .lock()
                        .map_err(|_| anyhow::anyhow!("INTERNAL"))?;
                    if !self.lifecycle_draining.load(Ordering::SeqCst) {
                        self.draining.store(false, Ordering::SeqCst);
                    }
                }
                return Ok(result);
            }
            "daemon.drain" => {
                {
                    let _admission = self
                        .admission
                        .lock()
                        .map_err(|_| anyhow::anyhow!("INTERNAL"))?;
                    self.draining.store(true, Ordering::SeqCst);
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
        let (verb, route, body) = backend_route(method, p)?;
        let mut result = self.backend(&org, &verb, &route, body, key).await?;
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
                let tokens = self.cancellations.lock().await;
                for job in jobs {
                    if let Some(c) = job["id"].as_str().and_then(|id| tokens.get(id)) {
                        c.store(true, Ordering::SeqCst)
                    }
                }
            }
        }
        if matches!(method, "interactions.respond" | "interactions.decide") {
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
        Ok(())
    }

    /// Bind a runner-issued app handoff before returning it to the UI.  The
    /// caller cannot select its workspace or identity: both come from the
    /// sealed run binding created at commit time.  This closes the gap where
    /// an app-originated `ui/message` did not produce a UserPromptSubmit hook,
    /// leaving a later Stop callback with nothing to protect.
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
        let binding: Value =
            state::read_json(&self.dir.join("run-bindings").join(format!("{run}.json")))
                .map_err(|_| anyhow::anyhow!("BACKEND_PROTOCOL_ERROR"))?;
        let workspace = required(&binding, "workspacePath")?;
        let account = self.auth.credential(org).await?.subject;
        let installation = self.auth.installation_id().await?;
        self.follow
            .activate_ui_handoff(org, &account, &installation, run, workspace, receipt)
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
        if existing.is_some() {
            return Ok(result);
        }
        let org = org.context("ORGANIZATION_REQUIRED")?;
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
        Ok(result)
    }
    async fn prepare(&self, method: &str, org: &str, p: &Value) -> Result<Value> {
        if self.draining.load(Ordering::SeqCst) {
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
    async fn commit(&self, method: &str, org: &str, p: &Value) -> Result<Value> {
        if self.draining.load(Ordering::SeqCst) {
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
fn normalize_catalog_output(value: Value, output_schema: &Value) -> Result<Value> {
    let object = value.as_object().context("BACKEND_PROTOCOL_ERROR")?;
    let schemas = output_schema["oneOf"]
        .as_array()
        .context("BACKEND_PROTOCOL_ERROR")?;
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
            .map(&type_matches)
            .or_else(|| {
                s["type"]
                    .as_array()
                    .map(|types| types.iter().filter_map(Value::as_str).any(type_matches))
            })
            .unwrap_or(false);
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
    let (verb, route) = match method {
        "workflows.list" => ("GET", "v1/workflows/".into()),
        "workflows.get" => (
            "GET",
            format!("v1/workflows/{}/", required(p, "workflowId")?),
        ),
        "workflows.create" => ("POST", "v2/workflows/".into()),
        "workflows.update" => (
            "POST",
            format!("v1/workflows/{}/draft/", required(p, "workflowId")?),
        ),
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
    let jobs = daemon.clone();
    tokio::spawn(async move {
        crate::jobs::run(jobs).await;
    });
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    loop {
        tokio::select! {
         result=listener.accept()=>{let(stream,_)=result?;if stream.peer_cred()?.uid()!=unsafe{libc::geteuid()}{continue};let d=daemon.clone();tokio::spawn(async move{let _=connection(stream,d).await;});},
         _=tokio::signal::ctrl_c()=>{daemon.draining.store(true,Ordering::SeqCst);break;},
         _=term.recv()=>{daemon.draining.store(true,Ordering::SeqCst);break;}
        }
    }
    while daemon.managed_work() > 0 {
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }
    std::fs::remove_file(socket)?;
    drop(lock);
    Ok(())
}
async fn connection(stream: UnixStream, daemon: Arc<Daemon>) -> Result<()> {
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut negotiated = false;
    let mut validation_errors_negotiated = false;
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
        let response = match parsed {
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
    } else {
        ("INTERNAL".into(), false, None)
    }
}
pub async fn client(dir: &Path, method: &str, params: Value) -> Result<Value> {
    let socket = dir.join("control.sock");
    let metadata = std::fs::symlink_metadata(&socket)?;
    if metadata.uid() != unsafe { libc::geteuid() } || metadata.permissions().mode() & 0o077 != 0 {
        bail!("UNSAFE_SOCKET")
    }
    let stream = UnixStream::connect(socket).await?;
    if stream.peer_cred()?.uid() != unsafe { libc::geteuid() } {
        bail!("UNSAFE_SOCKET")
    };
    let (read, mut write) = stream.into_split();
    let mut read = BufReader::new(read);
    let mut required: Vec<String> = REQUIRED_SEMANTICS
        .iter()
        .map(|cap| cap.to_string())
        .collect();
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
    write.write_all(&bytes).await?;
    let frame = read_frame(read).await?.context("NETWORK_AMBIGUOUS")?;
    let result: Value = serde_json::from_slice(&frame)?;
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
    async fn connection_get_is_advertised_and_reports_local_active_work() {
        let temp = tempfile::tempdir().unwrap();
        let api = Api::for_test_origin("http://127.0.0.1:9").unwrap();
        let daemon = fixture(temp.path(), api);
        assert!(
            negotiate(&json!({
                "supportedProtocols":[PROTOCOL],
                "requiredCapabilities":["method:connection.get", "connection.projection/v1"]
            }))
            .is_ok()
        );
        daemon.public.lock().await.active_organization =
            Some("11111111-1111-4111-8111-111111111111".into());
        daemon.active.store(4, Ordering::SeqCst);
        let result = daemon.dispatch("connection.get", json!({})).await.unwrap();
        assert_eq!(result["state"], "authenticated");
        assert_eq!(result["organization"]["status"], "connected");
        assert_eq!(result["activeWork"], 4);
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
            .cancellations
            .lock()
            .await
            .insert("active-work".into(), token.clone());
        daemon.active.fetch_add(1, Ordering::SeqCst);

        assert_eq!(
            daemon
                .dispatch("auth.logout", json!({"idempotencyKey":Uuid::new_v4()}))
                .await
                .unwrap_err()
                .to_string(),
            "ACTIVE_WORK_REQUIRES_DRAIN"
        );
        assert!(!daemon.draining.load(Ordering::SeqCst));
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
        assert!(!daemon.draining.load(Ordering::SeqCst));
        assert!(daemon.public.lock().await.active_organization.is_none());
        assert!(
            state::read_json::<PublicState>(&temp.path().join("state.json"))
                .unwrap()
                .active_organization
                .is_none()
        );
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
            assert!(!d.draining.load(Ordering::SeqCst));
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
            vec!["method:workflows.list", VALIDATION_ERRORS_CAPABILITY],
            "workflows.list",
            json!({}),
        )
        .await;
        assert_eq!(new_client["error"]["code"], "RUN_VALIDATION_FAILED");
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
        assert!(reopened.draining.load(Ordering::SeqCst));
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
