//! Credential-free local API. Only explicitly catalogued backend routes are reachable.
use crate::{
    api::{Api, ApiError},
    auth::Auth,
    state::{self, PublicState, WorkspaceGrant},
};
use anyhow::{Context, Result, bail};
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
pub const REQUIRED_SEMANTICS: [&str; 4] = [
    "execution.host_user/v1",
    "authorization.prepare-commit/v1",
    "auth.device-v2/v1",
    "transfer.chunked/v1",
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
pub struct Daemon {
    pub dir: PathBuf,
    pub api: Api,
    pub auth: Auth,
    pub public: Mutex<PublicState>,
    pub draining: AtomicBool,
    pub active: AtomicUsize,
    pub quiescence: AtomicUsize,
    pub managed: AtomicUsize,
    pub cancellations: Mutex<HashMap<String, Arc<AtomicBool>>>,
    mutation: Mutex<()>,
    pub admission: std::sync::Mutex<()>,
}
impl Daemon {
    pub fn new(dir: PathBuf, api: Api, auth: Auth) -> Result<Self> {
        state::private_dir(&dir)?;
        let public = PublicState::load(&dir)?;
        let draining = dir.join("drain.json").exists();
        Ok(Self {
            dir,
            api,
            auth,
            public: Mutex::new(public),
            draining: AtomicBool::new(draining),
            active: AtomicUsize::new(0),
            quiescence: AtomicUsize::new(0),
            managed: AtomicUsize::new(0),
            cancellations: Mutex::new(HashMap::new()),
            mutation: Mutex::new(()),
            admission: std::sync::Mutex::new(()),
        })
    }
    pub fn managed_work(&self) -> usize {
        self.managed.load(Ordering::SeqCst)
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
    pub async fn dispatch(&self, method: &str, params: Value) -> Result<Value> {
        let catalog: Value =
            serde_json::from_str(include_str!("../contracts/method-catalog.json"))?;
        let entry = catalog["methods"]
            .as_array()
            .unwrap()
            .iter()
            .find(|m| m["name"] == method)
            .context("METHOD_NOT_FOUND")?;
        validate_params(&params, &entry["inputSchema"])?;
        let write = entry["mutating"] == true;
        let _guard = if write {
            Some(self.mutation.lock().await)
        } else {
            None
        };
        let key = params.get("idempotencyKey").and_then(Value::as_str);
        let scope = if method.starts_with("auth.") || method == "daemon.drain" {
            None
        } else {
            params["organizationId"].as_str().map(String::from).or(self
                .public
                .lock()
                .await
                .active_organization
                .clone())
        };
        let identity =
            state::json_digest(&json!({"method":method,"params":params,"organizationId":scope}));
        let operation = key.map(|k| self.dir.join("operations").join(format!("{k}.json")));
        if let Some(path) = &operation {
            if path.exists() {
                let record: Value = state::read_json(path)?;
                if record["digest"] != identity {
                    bail!("IDEMPOTENCY_CONFLICT")
                }
                if record["expired"] == true {
                    bail!("RESULT_EXPIRED")
                }
                if let Some(result) = record.get("result") {
                    return Ok(result.clone());
                }
            } else {
                state::write_json(
                    path,
                    &json!({"digest":identity,"method":method,"status":"pending"}),
                )?
            }
        }
        let result = normalize_output(
            self.handle(method, &params).await?,
            &entry["outputSchema"]["oneOf"][0],
        )?;
        if let Some(path) = operation {
            if !(method == "auth.poll" && result["status"] == "pending") {
                state::write_json(
                    &path,
                    &json!({"digest":identity,"method":method,"cachedAt":state::now(),"executionId":params.get("runId").or_else(||result.get("executionId")).or_else(||result.get("execution").and_then(|v|v.get("id"))),"result":result}),
                )?
            }
        }
        Ok(result)
    }
    async fn handle(&self, method: &str, p: &Value) -> Result<Value> {
        let key = p.get("idempotencyKey").and_then(Value::as_str);
        match method {
            "protocol.negotiate" => return negotiate(p),
            "status.get" => {
                return Ok(
                    json!({"version":env!("CARGO_PKG_VERSION"),"protocol":PROTOCOL,"activeJobs":self.reported_work(),"draining":self.draining.load(Ordering::SeqCst),"updateDeferred":self.dir.join("pending-update.json").exists()}),
                );
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
            "auth.poll" => return self.auth.poll(key.unwrap()).await,
            "auth.status" => return self.auth.status().await,
            "auth.logout" => {
                {
                    let _admission = self
                        .admission
                        .lock()
                        .map_err(|_| anyhow::anyhow!("INTERNAL"))?;
                    self.draining.store(true, Ordering::SeqCst);
                }
                for token in self.cancellations.lock().await.values() {
                    token.store(true, Ordering::SeqCst);
                }
                return self.auth.logout().await;
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
                    if !self.dir.join("drain.json").exists() {
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
        let org = match p["organizationId"].as_str() {
            Some(x) => x.to_owned(),
            None => self.selected_org().await?,
        };
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
                let mut public = self.public.lock().await;
                public
                    .grants
                    .retain(|g| !(g.organization_id == org && g.path == path));
                public.save(&self.dir)?;
                return Ok(json!({"revoked":true}));
            }
            "runs.prepare" | "builder.prepare" | "editor.prepare" => {
                return self.prepare(method, &org, p).await;
            }
            "runs.commit" | "builder.commit" | "editor.commit" => {
                return self.commit(method, &org, p).await;
            }
            "artifacts.download" => return self.download(&org, p).await,
            "builder.create" | "editor.create" => {
                self.granted(Path::new(required(p, "workspacePath")?), &org)
                    .await?;
            }
            _ => {}
        }
        let (verb, route, body) = backend_route(method, p)?;
        let mut result = self.backend(&org, &verb, &route, body, key).await?;
        if method == "runs.delete" {
            let run = required(p, "runId")?;
            crate::retention::mark_deleted_tree(&self.dir, run, &result)?;
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
        state::write_json(
            &record_path,
            &json!({"operation":method,"organizationId":org,"installationId":install,"workspacePath":workspace,"bindingDigest":result["bindingDigest"],"binding":result["binding"],"confirmationKey":confirmation,"providers":providers}),
        )?;
        Ok(result)
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
        object.insert("details".into(), Value::Object(extra));
    }
    for key in schema["required"].as_array().unwrap() {
        if !object.contains_key(key.as_str().unwrap()) {
            bail!("BACKEND_PROTOCOL_ERROR")
        }
    }
    Ok(value)
}
fn required<'a>(p: &'a Value, key: &str) -> Result<&'a str> {
    p[key]
        .as_str()
        .filter(|v| !v.is_empty())
        .context("INVALID_REQUEST")
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
        let valid = match s["type"].as_str() {
            Some("string") => value.is_string(),
            Some("object") => value.is_object(),
            Some("integer") => value.as_u64().is_some(),
            Some("boolean") => value.is_boolean(),
            Some("array") => value.as_array().is_some_and(|items| {
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
        if !valid {
            bail!("INVALID_REQUEST")
        };
        if let Some(expected) = s.get("const") {
            if expected != value {
                bail!("INVALID_REQUEST")
            }
        }
        if s["format"] == "uuid" {
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
    let mut providers = serde_json::Map::new();
    for (name, adapter) in [("codex", "codex"), ("claude", "claude"), ("gemini", "agy")] {
        if let Some(path) = find_executable(adapter) {
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
    let p = Path::new(name);
    if p.is_absolute() {
        return std::fs::canonicalize(p).ok();
    }
    let path = std::env::var_os("PATH").unwrap_or_default();
    std::env::split_paths(&path)
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
        .and_then(|p| std::fs::canonicalize(p).ok())
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

pub async fn serve(daemon: Arc<Daemon>) -> Result<()> {
    let lock_path = daemon.dir.join("daemon.lock");
    let lock = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(&lock_path)?;
    lock.try_lock_exclusive()
        .map_err(|_| anyhow::anyhow!("DAEMON_ALREADY_RUNNING"))?;
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
    loop {
        let frame = match read_frame(&mut reader).await {
            Ok(Some(frame)) => frame,
            Ok(None) => return Ok(()),
            Err(error) => {
                let (code, retryable) = public_error(&error);
                let mut response = serde_json::to_vec(
                    &json!({"protocol":PROTOCOL,"id":"","error":state::safe_error(&code,retryable)}),
                )?;
                response.push(b'\n');
                writer.write_all(&response).await?;
                return Ok(());
            }
        };
        let parsed = serde_json::from_slice::<Value>(&frame);
        let response = match parsed {
            Ok(request) => {
                let id = request["id"].as_str().unwrap_or("").to_owned();
                if request["protocol"] != PROTOCOL {
                    json!({"protocol":PROTOCOL,"id":id,"error":state::safe_error("PROTOCOL_MISMATCH",false)})
                } else if request.as_object().is_none_or(|m| m.len() != 4)
                    || !request["id"].is_string()
                    || id.is_empty()
                    || id.len() > 256
                {
                    json!({"protocol":PROTOCOL,"id":id,"error":state::safe_error("INVALID_REQUEST",false)})
                } else if !negotiated && request["method"] != "protocol.negotiate" {
                    json!({"protocol":PROTOCOL,"id":id,"error":state::safe_error("COMPATIBILITY_ERROR",false)})
                } else {
                    if request["method"] == "protocol.negotiate" {
                        negotiated = false;
                    }
                    match daemon
                        .dispatch(
                            request["method"].as_str().unwrap_or(""),
                            request["params"].clone(),
                        )
                        .await
                    {
                        Ok(mut result) => {
                            if request["method"] == "protocol.negotiate" {
                                negotiated = true;
                            }
                            let bytes = serde_json::to_vec(&result)?;
                            if bytes.len() > MAX_FRAME - 1024 {
                                let reference = Uuid::new_v4();
                                let checksum = state::digest(&bytes);
                                state::atomic_write(
                                    &daemon
                                        .dir
                                        .join("responses")
                                        .join(format!("{reference}.json")),
                                    &bytes,
                                )?;
                                state::atomic_write(
                                    &daemon
                                        .dir
                                        .join("responses")
                                        .join(format!("{reference}.sha256")),
                                    checksum.as_bytes(),
                                )?;
                                state::write_json(
                                    &daemon
                                        .dir
                                        .join("responses")
                                        .join(format!("{reference}.meta.json")),
                                    &json!({"executionId":request["params"]["runId"],"lastAccessAt":state::now()}),
                                )?;
                                result = json!({"responseRef":reference,"sizeBytes":bytes.len(),"encoding":"json","nextOffset":0,"checksumSha256":checksum});
                            }
                            json!({"protocol":PROTOCOL,"id":id,"result":result})
                        }
                        Err(error) => {
                            let (code, retryable) = public_error(&error);
                            json!({"protocol":PROTOCOL,"id":id,"error":state::safe_error(&code,retryable)})
                        }
                    }
                }
            }
            Err(_) => {
                json!({"protocol":PROTOCOL,"id":"","error":state::safe_error("INVALID_REQUEST",false)})
            }
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
pub fn public_error(error: &anyhow::Error) -> (String, bool) {
    if let Some(api) = error.downcast_ref::<ApiError>() {
        return (api.code.clone(), api.retryable);
    }
    let text = error.to_string();
    if text.len() < 100 && text.bytes().all(|b| b.is_ascii_uppercase() || b == b'_') {
        (text, false)
    } else {
        ("INTERNAL".into(), false)
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
        assert!(response["error"]["correlationId"].is_string());
        drop(w);
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
                                json!({"preparationId":prep_server,"bindingDigest":"digest","binding":body,"limits":{},"expiresAt":null})
                            } else {
                                assert_eq!(body["preparationId"], prep_server);
                                json!({"execution":{"id":run},"preparationId":prep_server,"executionPolicy":"host_user/v1"})
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
        let d = fixture(&temp.path().join("state"), api);
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
        let prepared = d.dispatch("runs.prepare", p).await.unwrap();
        assert!(prepared["confirmationKey"].is_string());
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
