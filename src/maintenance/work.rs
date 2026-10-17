//! No server, provider poller, delivery sender, supervisor, or scheduler is started.
use super::*;
use crate::{follow::FollowStore, presentation::PresentationStore};
use anyhow::Context as _;
use serde_json::json;
#[path = "domain_reconciliation.rs"]
mod domain_reconciliation;

/// Bootstrap writes this immutable context before spawning the release-verified
/// daemon. Every output path is derived from the UUID, never supplied by callers.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WorkContext {
    schema: String,
    operation_id: uuid::Uuid,
    attempt_id: uuid::Uuid,
    state_dir: PathBuf,
    install_base: PathBuf,
    launch_agents_dir: PathBuf,
    journal_sha256: String,
    receipt_sha256: String,
    binary_sha256: String,
    action: String,
    expected_assessment_sha256: Option<String>,
    expected_identity: crate::auth::CredentialIdentity,
    api_origin: Option<String>,
    singleton_fd: i32,
    #[serde(default)]
    authorize_keychain_transition: bool,
}

fn result_path(context: &WorkContext) -> PathBuf {
    context
        .state_dir
        .join(format!("uninstall-work-result-{}.json", context.attempt_id))
}
fn candidates(
    follow: &Option<FollowStore>,
    presentation: &Option<PresentationStore>,
) -> Result<Vec<Value>> {
    let mut values = Vec::new();
    if let Some(store) = follow {
        values.extend(store.maintenance_candidates()?);
    }
    if let Some(store) = presentation {
        values.extend(store.maintenance_candidates()?);
        values.extend(store.maintenance_operation_candidates()?);
    }
    Ok(values)
}
fn apply(
    follow: &Option<FollowStore>,
    presentation: &Option<PresentationStore>,
    request: &Value,
    observation: Option<&Value>,
) -> Result<Value> {
    match request["kind"].as_str() {
        Some("follow_session") => {
            let store = follow
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("MANAGED_WORK_CHANGED"))?;
            match observation {
                Some(value) => store.maintenance_reconcile(request, value),
                None => store.maintenance_retire(request),
            }
        }
        Some("presentation_delivery") => {
            let store = presentation
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("MANAGED_WORK_CHANGED"))?;
            match observation {
                Some(value) => store.maintenance_reconcile(request, value),
                None => store.maintenance_retire(request),
            }
        }
        Some("presentation_operation") => presentation
            .as_ref()
            .context("MANAGED_WORK_CHANGED")?
            .maintenance_operation_settle(request, observation.context("INVALID_REQUEST")?),
        _ => bail!("INVALID_REQUEST"),
    }
}
async fn read_run(
    api: &Api,
    auth: &Auth,
    candidate: &Value,
    identity: &crate::auth::CredentialIdentity,
) -> Result<Value> {
    let org = candidate["organizationId"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("INVALID_REQUEST"))?;
    let run = candidate["runId"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("INVALID_REQUEST"))?;
    uuid::Uuid::parse_str(run).map_err(|_| anyhow::anyhow!("INVALID_REQUEST"))?;
    let mut params = json!({"runId":run,"timeoutSeconds":0,"limit":200});
    let mut method = "runs.get";
    let mut previous = None;
    let mut terminal_status: Option<String> = None;
    loop {
        ensure!(
            auth.maintenance_identity()
                .await?
                .as_ref()
                .is_some_and(|actual| actual.installation_id == identity.installation_id
                    && (identity.device_id.is_none() || actual.device_id == identity.device_id)),
            "AUTH_IDENTITY_CHANGED"
        );
        ensure!(
            auth.enrolled_organizations()
                .await?
                .iter()
                .any(|id| id == org),
            "ORGANIZATION_NOT_ENROLLED"
        );
        let credential = auth.credential(org).await?;
        ensure!(
            auth.maintenance_identity()
                .await?
                .as_ref()
                .is_some_and(|actual| actual.installation_id == identity.installation_id
                    && (identity.device_id.is_none() || actual.device_id == identity.device_id)),
            "AUTH_IDENTITY_CHANGED"
        );
        ensure!(
            credential.subject == candidate["accountSubject"].as_str().unwrap_or(""),
            "AUTH_IDENTITY_CHANGED"
        );
        let (verb, route, body) = control::backend_route(method, &params)?;
        let value = api
            .request(&verb, &route, body, Some(&credential), None)
            .await?;
        ensure!(
            value.pointer("/execution/id").and_then(Value::as_str) == Some(run),
            "MANAGED_WORK_OBSERVATION_INCOMPLETE"
        );
        ensure!(
            value.get("responseRef").is_none()
                && value.get("hasMore").and_then(Value::as_bool) != Some(true)
                && value.get("nextOffset").is_none_or(Value::is_null),
            "MANAGED_WORK_OBSERVATION_INCOMPLETE"
        );
        if value["hasMoreEvents"] == true {
            let cursor = value["events"]
                .as_array()
                .and_then(|events| events.last())
                .and_then(|event| event["sequence"].as_u64())
                .ok_or_else(|| anyhow::anyhow!("MANAGED_WORK_OBSERVATION_INCOMPLETE"))?;
            ensure!(
                previous.is_none_or(|old| cursor > old),
                "MANAGED_WORK_OBSERVATION_INCOMPLETE"
            );
            previous = Some(cursor);
            params["afterSequence"] = json!(cursor);
            method = "runs.events";
            continue;
        }
        ensure!(
            value["hasMoreEvents"] == false,
            "MANAGED_WORK_OBSERVATION_INCOMPLETE"
        );
        if !FollowStore::terminal_snapshot(&value) {
            return Ok(json!({"snapshot":value}));
        }
        let status = value["execution"]["status"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("MANAGED_WORK_OBSERVATION_INCOMPLETE"))?;
        if method == "runs.result" {
            ensure!(
                terminal_status.as_deref() == Some(status),
                "MANAGED_WORK_OBSERVATION_INCOMPLETE"
            );
            // The direct canonical backend returns one complete inline result
            // projection. responseRef belongs to runner transport and is refused.
            return Ok(json!({"snapshot":value,"terminalResult":value}));
        }
        terminal_status = Some(status.into());
        method = "runs.result";
    }
}

fn candidate_set_digest(values: &[Value]) -> String {
    let mut items = values
        .iter()
        .map(|value| {
            json!([
                value["kind"],
                value["organizationId"],
                value["accountSubject"],
                value["installationId"],
                value["recordId"],
                value["runId"],
                value["recordDigest"]
            ])
        })
        .collect::<Vec<_>>();
    items.sort_by_key(Value::to_string);
    state::json_digest(&json!(items))
}
fn dependency_entries(dir: &Path) -> Result<Vec<Value>> {
    fn walk(root: &Path, path: &Path, files: &mut Vec<Value>) -> Result<()> {
        let metadata = std::fs::symlink_metadata(path)?;
        ensure!(
            !metadata.file_type().is_symlink() && metadata.uid() == unsafe { libc::geteuid() },
            "UNSAFE_STATE"
        );
        if metadata.is_dir() {
            let mut entries = std::fs::read_dir(path)?.collect::<std::io::Result<Vec<_>>>()?;
            entries.sort_by_key(|entry| entry.file_name());
            for entry in entries {
                walk(root, &entry.path(), files)?;
            }
        } else {
            ensure!(metadata.is_file() && metadata.nlink() == 1, "UNSAFE_STATE");
            files.push(json!([
                path.strip_prefix(root)?,
                state::digest(&std::fs::read(path)?)
            ]));
        }
        Ok(())
    }
    let mut files = Vec::new();
    for name in [
        "jobs",
        "operations",
        "responses",
        "workflow-patches",
        "recovery.sqlite3",
        "recovery.sqlite3-wal",
        "recovery.sqlite3-shm",
    ] {
        let path = dir.join(name);
        if path.try_exists()? {
            walk(dir, &path, &mut files)?;
        }
    }
    Ok(files)
}
fn dependencies_digest(dir: &Path) -> Result<String> {
    Ok(state::json_digest(&json!(dependency_entries(dir)?)))
}
fn cache_transition_path(context: &WorkContext, index: usize) -> PathBuf {
    context.state_dir.join(format!(
        "uninstall-work-cache-{}-{index}.json",
        context.attempt_id
    ))
}
fn frozen_cache_transition(
    context: &WorkContext,
    index: usize,
    request: &Value,
) -> Result<Option<Value>> {
    let path = cache_transition_path(context, index);
    if !path.try_exists()? {
        return Ok(None);
    }
    let value: Value = serde_json::from_slice(&read_private(&path, 16 * 1024 * 1024)?)?;
    ensure!(
        value["schema"] == "app.loomex.runner.uninstall-work-cache-transition/v1"
            && value["operationId"] == context.operation_id.to_string()
            && value["attemptId"] == context.attempt_id.to_string()
            && value["index"] == index
            && value["requestDigest"] == state::json_digest(request),
        "MANAGED_WORK_CHANGED"
    );
    control::maintenance_cache_validate(request, &value["transition"])?;
    Ok(Some(value["transition"].clone()))
}
fn transition_targets(transition: &Value) -> impl Iterator<Item = &Value> {
    std::iter::once(transition).chain(
        transition["relatedTargets"]
            .as_array()
            .into_iter()
            .flatten(),
    )
}
fn verify_dependencies(context: &WorkContext, saved: &Value) -> Result<()> {
    let mut actual = dependency_entries(&context.state_dir)?;
    let original = saved["dependencyEntries"]
        .as_array()
        .context("MANAGED_WORK_CHANGED")?;
    let requests = saved["requests"]
        .as_array()
        .context("MANAGED_WORK_CHANGED")?;
    let mut changed = std::collections::HashSet::new();
    for (index, request) in requests.iter().enumerate() {
        if let Some(transition) = frozen_cache_transition(context, index, request)? {
            for target in transition_targets(&transition) {
                let path = target["path"].as_str().context("MANAGED_WORK_CHANGED")?;
                ensure!(changed.insert(path.to_owned()), "MANAGED_WORK_CHANGED");
                let before = &target["beforeSha256"];
                ensure!(
                    original
                        .iter()
                        .any(|entry| entry[0] == path && entry[1] == *before),
                    "MANAGED_WORK_CHANGED"
                );
                let current = actual
                    .iter_mut()
                    .find(|entry| entry[0] == path)
                    .context("MANAGED_WORK_CHANGED")?;
                ensure!(
                    current[1] == *before || current[1] == target["afterSha256"],
                    "MANAGED_WORK_CHANGED"
                );
                current[1] = before.clone();
            }
        }
    }
    ensure!(
        actual == *original && saved["dependenciesDigest"] == state::json_digest(&json!(original)),
        "MANAGED_WORK_CHANGED"
    );
    Ok(())
}
fn settle_cache(
    context: &WorkContext,
    index: usize,
    request: &Value,
    receipt: &Value,
) -> Result<()> {
    let saved: Value = serde_json::from_slice(&read_private(
        &context.state_dir.join(format!(
            "uninstall-work-requests-{}.json",
            context.attempt_id
        )),
        16 * 1024 * 1024,
    )?)?;
    verify_dependencies(context, &saved)?;
    let transition = match frozen_cache_transition(context, index, request)? {
        Some(value) => {
            ensure!(
                value["canonicalReceipt"] == *receipt,
                "MANAGED_WORK_CHANGED"
            );
            Some(value)
        }
        None => {
            let cache = control::maintenance_cache_prepare(&context.state_dir, request, receipt)?;
            let patch = control::maintenance_patch_prepare(&context.state_dir, request, receipt)?;
            match (cache, patch) {
                (Some(mut cache), Some(patch)) => {
                    cache["relatedTargets"] = json!([patch]);
                    Some(cache)
                }
                (cache, patch) => cache.or(patch),
            }
        }
    };
    let Some(transition) = transition else {
        return Ok(());
    };

    let original = saved["dependencyEntries"]
        .as_array()
        .context("MANAGED_WORK_CHANGED")?;
    for target in transition_targets(&transition) {
        ensure!(
            original
                .iter()
                .any(|entry| entry[0] == target["path"] && entry[1] == target["beforeSha256"]),
            "MANAGED_WORK_CHANGED"
        );
    }
    let path = cache_transition_path(context, index);
    if !path.try_exists()? {
        immutable_json(
            &path,
            &json!({"schema":"app.loomex.runner.uninstall-work-cache-transition/v1","operationId":context.operation_id,"attemptId":context.attempt_id,"index":index,"requestDigest":state::json_digest(request),"transition":transition}),
        )?;
    }
    verify_dependencies(context, &saved)?;
    control::maintenance_cache_apply(&context.state_dir, request, &transition)
}
fn attach_patch_journals(context: &WorkContext, values: &mut [Value]) -> Result<()> {
    for candidate in values.iter_mut().filter(|candidate| {
        candidate["kind"] == "presentation_operation" && candidate["method"] == "workflows.patch"
    }) {
        let reference = state::json_digest(
            &json!({"organizationId":candidate["organizationId"],"accountSubject":candidate["accountSubject"],"idempotencyKey":candidate["operationKey"]}),
        );
        let parent = context.state_dir.join("workflow-patches");
        if !parent.try_exists()? {
            continue;
        }
        let metadata = std::fs::symlink_metadata(&parent)?;
        ensure!(
            metadata.is_dir()
                && !metadata.file_type().is_symlink()
                && metadata.uid() == unsafe { libc::geteuid() },
            "UNSAFE_STATE"
        );
        let path = parent.join(format!("{reference}.json"));
        if path.try_exists()? {
            let record: Value = serde_json::from_slice(&read_private(&path, 16 * 1024 * 1024)?)?;
            candidate["nativePatchResolved"] = json!(
                control::native_patch_acknowledged(&record)?
                    || crate::presentation::maintenance_native_patch_resolved(&record)?
            );
            candidate["nativePatchJournal"] = record;
        }
    }
    Ok(())
}
fn immutable_json(path: &Path, value: &Value) -> Result<()> {
    use std::io::Write;
    let bytes = serde_json::to_vec(value)?;
    ensure!(
        bytes.len() <= 16 * 1024 * 1024,
        "MANAGED_WORK_PREVIEW_LIMIT"
    );
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    File::open(path.parent().unwrap())?.sync_all()?;
    Ok(())
}
fn scoped_requests(context: &WorkContext, values: &[Value]) -> Result<Vec<Value>> {
    let path = context.state_dir.join(format!(
        "uninstall-work-requests-{}.json",
        context.attempt_id
    ));
    if path.try_exists()? {
        let saved: Value = serde_json::from_slice(&read_private(&path, 16 * 1024 * 1024)?)?;
        ensure!(
            saved["schema"] == "app.loomex.runner.uninstall-work-requests/v1"
                && saved["operationId"] == context.operation_id.to_string()
                && saved["attemptId"] == context.attempt_id.to_string()
                && saved["candidateSetDigest"] == candidate_set_digest(values),
            "MANAGED_WORK_CHANGED"
        );
        verify_dependencies(context, &saved)?;
        return Ok(saved["requests"]
            .as_array()
            .ok_or_else(|| anyhow::anyhow!("INVALID_REQUEST"))?
            .clone());
    }
    let mut requests = values
        .iter()
        .filter(|value| {
            (value["resolution"]["state"] == "unresolved"
                || (context.action == "reconcile"
                    && value["kind"] == "presentation_operation"
                    && value["method"] == "workflows.patch"
                    && value["status"] == "completed"
                    && value["nativePatchJournal"].is_object()
                    && value["nativePatchResolved"] != true))
                && (context.action == "reconcile"
                    || value["kind"] == "follow_session"
                    || (value["kind"] == "presentation_delivery"
                        && value["retirementEligible"] == true))
        })
        .cloned()
        .collect::<Vec<_>>();
    ensure!(requests.len() <= 256, "MANAGED_WORK_PREVIEW_LIMIT");
    for request in &mut requests {
        request["idempotencyKey"] = json!(uuid::Uuid::new_v4());
    }
    immutable_json(
        &path,
        &json!({"schema":"app.loomex.runner.uninstall-work-requests/v1","operationId":context.operation_id,"attemptId":context.attempt_id,"candidateSetDigest":candidate_set_digest(values),"dependenciesDigest":dependencies_digest(&context.state_dir)?,"dependencyEntries":dependency_entries(&context.state_dir)?,"acceptanceDependencies":crate::uninstall_state::maintenance_acceptance_dependencies(&context.state_dir)?,"requests":requests}),
    )?;
    Ok(requests)
}
fn record_settlement(
    context: &WorkContext,
    index: usize,
    request: &Value,
    receipt: &Value,
) -> Result<()> {
    let path = context.state_dir.join(format!(
        "uninstall-work-checkpoint-{}-{index}.json",
        context.attempt_id
    ));
    let value = json!({"schema":"app.loomex.runner.uninstall-work-record/v1","operationId":context.operation_id,"attemptId":context.attempt_id,"index":index,"requestDigest":state::json_digest(request),"receipt":receipt});
    if path.try_exists()? {
        ensure!(
            serde_json::from_slice::<Value>(&read_private(&path, 16 * 1024 * 1024)?)? == value,
            "MANAGED_WORK_CHANGED"
        );
    } else {
        immutable_json(&path, &value)?;
    }
    Ok(())
}
fn settled(
    context: &WorkContext,
    index: usize,
    request: &Value,
    values: &[Value],
) -> Result<Option<Value>> {
    let path = context.state_dir.join(format!(
        "uninstall-work-checkpoint-{}-{index}.json",
        context.attempt_id
    ));
    if !path.try_exists()? {
        return Ok(None);
    }
    let value: Value = serde_json::from_slice(&read_private(&path, 16 * 1024 * 1024)?)?;
    ensure!(
        value["requestDigest"] == state::json_digest(request)
            && value["operationId"] == context.operation_id.to_string()
            && value["attemptId"] == context.attempt_id.to_string()
            && value["index"] == index,
        "MANAGED_WORK_CHANGED"
    );
    let candidate = values
        .iter()
        .find(|candidate| {
            candidate["kind"] == request["kind"]
                && candidate["organizationId"] == request["organizationId"]
                && candidate["accountSubject"] == request["accountSubject"]
                && candidate["installationId"] == request["installationId"]
                && candidate["recordId"] == request["recordId"]
        })
        .ok_or_else(|| anyhow::anyhow!("MANAGED_WORK_CHANGED"))?;
    let historical_patch = if request["kind"] == "presentation_operation"
        && request["method"] == "workflows.patch"
        && request["status"] == "completed"
        && candidate["status"] == "completed"
        && candidate["recordDigest"] == request["recordDigest"]
    {
        let transition =
            frozen_cache_transition(context, index, request)?.context("MANAGED_WORK_CHANGED")?;
        value["receipt"]
            == crate::presentation::maintenance_operation_summary(
                request,
                &transition["canonicalReceipt"],
            )?
    } else {
        false
    };
    ensure!(
        candidate["resolution"] == value["receipt"]
            || candidate["backendObservation"] == value["receipt"]
            || historical_patch,
        "MANAGED_WORK_CHANGED"
    );
    Ok(Some(value["receipt"].clone()))
}
fn authorization_needed(explicit_required: bool, readable: bool) -> bool {
    explicit_required && !readable
}
async fn owned_probe<F>(lock: &Arc<File>, probe: F) -> Result<()>
where
    F: FnOnce() -> &'static str + Send + 'static,
{
    let owner = lock.clone();
    let code = tokio::task::spawn_blocking(move || {
        let _owner = owner;
        probe()
    })
    .await
    .map_err(|_| anyhow::anyhow!("STORE_UNAVAILABLE"))?;
    ensure!(code == "AUTHORIZED", "STORE_ACCESS_REQUIRED");
    Ok(())
}
async fn authorize_transition(context: &WorkContext, auth: &Auth, lock: &Arc<File>) -> Result<()> {
    if !context.authorize_keychain_transition {
        return Ok(());
    }
    ensure!(cfg!(debug_assertions), "STORE_UNAVAILABLE");
    let path = context.state_dir.join(format!(
        "uninstall-work-authorization-{}.json",
        context.attempt_id
    ));
    // Retry first observes native access, before considering another foreground
    // prompt. A completed authorization checkpoint is never treated as identity.
    let readable = match auth.maintenance_identity().await {
        Ok(Some(actual)) => {
            ensure!(
                actual.installation_id == context.expected_identity.installation_id
                    && (context.expected_identity.device_id.is_none()
                        || actual.device_id == context.expected_identity.device_id),
                "AUTH_IDENTITY_CHANGED"
            );
            true
        }
        Ok(None) => return Err(anyhow::anyhow!("AUTH_RECONCILIATION_REQUIRED")),
        Err(error)
            if matches!(
                error.to_string().as_str(),
                "STORE_ACCESS_REQUIRED" | "STORE_ACCESS_DENIED"
            ) =>
        {
            false
        }
        Err(error) => return Err(error),
    };
    if readable && path.try_exists()? {
        let prior: Value = serde_json::from_slice(&read_private(&path, 65536)?)?;
        ensure!(
            prior["operationId"] == context.operation_id.to_string()
                && prior["attemptId"] == context.attempt_id.to_string(),
            "MANAGED_WORK_CHANGED"
        );
        if prior["phase"] == "native_access_verified" {
            return Ok(());
        }
    }
    if authorization_needed(context.authorize_keychain_transition, readable) {
        state::write_json(
            &path,
            &json!({"schema":"app.loomex.runner.uninstall-work-authorization/v1","operationId":context.operation_id,"attemptId":context.attempt_id,"phase":"prepared"}),
        )?;
        // The blocking native call owns the singleton even if its async observer
        // is abandoned or the bootstrap's observation budget expires.
        owned_probe(lock, || {
            #[cfg(target_os = "macos")]
            {
                crate::auth::credential_store_probe(true)
            }
            #[cfg(not(target_os = "macos"))]
            {
                "UNAVAILABLE"
            }
        })
        .await?;
    }
    let actual = auth
        .maintenance_identity()
        .await?
        .ok_or_else(|| anyhow::anyhow!("AUTH_RECONCILIATION_REQUIRED"))?;
    ensure!(
        actual.installation_id == context.expected_identity.installation_id
            && (context.expected_identity.device_id.is_none()
                || actual.device_id == context.expected_identity.device_id),
        "AUTH_IDENTITY_CHANGED"
    );
    state::write_json(
        &path,
        &json!({"schema":"app.loomex.runner.uninstall-work-authorization/v1","operationId":context.operation_id,"attemptId":context.attempt_id,"phase":"native_access_verified","foregroundAttempted":!readable}),
    )?;
    Ok(())
}
fn verify_current_domain(presentation: &Option<PresentationStore>, request: &Value) -> Result<()> {
    let current = presentation
        .as_ref()
        .context("MANAGED_WORK_CHANGED")?
        .maintenance_operation_candidates()?
        .into_iter()
        .find(|candidate| {
            candidate["recordId"] == request["recordId"]
                && candidate["organizationId"] == request["organizationId"]
                && candidate["accountSubject"] == request["accountSubject"]
        })
        .context("MANAGED_WORK_CHANGED")?;
    for field in [
        "kind",
        "organizationId",
        "accountSubject",
        "installationId",
        "recordId",
        "operationId",
        "viewSessionId",
        "revision",
        "generation",
        "attemptId",
        "method",
        "params",
        "operationKey",
        "reconciliation",
        "createdAt",
        "recordDigest",
    ] {
        ensure!(current[field] == request[field], "MANAGED_WORK_CHANGED");
    }
    Ok(())
}
fn settle_domain_locally(
    context: &WorkContext,
    index: usize,
    presentation: &Option<PresentationStore>,
    request: &Value,
    receipt: &Value,
) -> Result<Value> {
    verify_current_domain(presentation, request)?;
    settle_cache(context, index, request, receipt)?;
    apply(&None, presentation, request, Some(receipt))
}
async fn execute(context: &WorkContext, lock: &Arc<File>) -> Result<Value> {
    let resuming = context
        .state_dir
        .join(format!(
            "uninstall-work-requests-{}.json",
            context.attempt_id
        ))
        .try_exists()?;
    if context.action == "retire-local" && !resuming {
        let assessment = crate::uninstall_state::assess_state(&context.state_dir)?;
        ensure!(
            context.expected_assessment_sha256.as_deref() == Some(&assessment.assessment_digest),
            "MANAGED_WORK_CHANGED"
        );
    }
    let api = Api::from_installation_origin(context.api_origin.as_deref())?;
    let auth = Auth::new(api.clone())?;
    auth.retain_store_owner(lock);
    authorize_transition(context, &auth, lock).await?;
    let actual = auth
        .maintenance_identity()
        .await?
        .ok_or_else(|| anyhow::anyhow!("AUTH_REQUIRED"))?;
    ensure!(
        actual.installation_id == context.expected_identity.installation_id
            && (context.expected_identity.device_id.is_none()
                || actual.device_id == context.expected_identity.device_id),
        "AUTH_IDENTITY_CHANGED"
    );
    let mut values = crate::uninstall_state::maintenance_preview(&context.state_dir)?;
    attach_patch_journals(context, &mut values)?;
    let requests = scoped_requests(context, &values)?;
    for candidate in &requests {
        let install = candidate["installationId"].as_str().unwrap_or("");
        ensure!(
            install.is_empty() || install == context.expected_identity.installation_id,
            "AUTH_IDENTITY_CHANGED"
        );
        let org = candidate["organizationId"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("INVALID_REQUEST"))?;
        uuid::Uuid::parse_str(org).map_err(|_| anyhow::anyhow!("INVALID_REQUEST"))?;
        if context.action == "retire-local" {
            let (account, installation) = auth.current_child_identity(org).await?;
            ensure!(
                Some(account.as_str()) == candidate["accountSubject"].as_str()
                    && installation == context.expected_identity.installation_id,
                "AUTH_IDENTITY_CHANGED"
            );
        } else {
            ensure!(
                auth.enrolled_organizations()
                    .await?
                    .iter()
                    .any(|id| id == org),
                "ORGANIZATION_NOT_ENROLLED"
            );
            let credential = auth.credential(org).await?;
            ensure!(
                Some(credential.subject.as_str()) == candidate["accountSubject"].as_str(),
                "AUTH_IDENTITY_CHANGED"
            );
            ensure!(
                auth.maintenance_identity()
                    .await?
                    .as_ref()
                    .is_some_and(|identity| identity.installation_id
                        == context.expected_identity.installation_id),
                "AUTH_IDENTITY_CHANGED"
            );
        }
    }
    let schema_before = crate::uninstall_state::maintenance_schema_digest(&context.state_dir)?;
    let follow = context
        .state_dir
        .join("follow.sqlite3")
        .try_exists()?
        .then(|| FollowStore::open(&context.state_dir))
        .transpose()?;
    let presentation = context
        .state_dir
        .join("presentation.sqlite3")
        .try_exists()?
        .then(|| PresentationStore::open(&context.state_dir))
        .transpose()?;
    // A migration is an explicit fresh-review boundary. Transient WAL/SHM
    // creation is not a migration; original record and dependency fences remain.
    if context.action == "retire-local" && !resuming {
        ensure!(
            schema_before == crate::uninstall_state::maintenance_schema_digest(&context.state_dir)?,
            "MANAGED_WORK_MIGRATION_CHANGED"
        );
    }
    ensure!(
        candidate_set_digest(&values) == candidate_set_digest(&candidates(&follow, &presentation)?),
        "MANAGED_WORK_CHANGED"
    );
    let mut receipts = Vec::new();
    let mut domain_pending = false;
    for (index, request) in requests.iter().enumerate() {
        if let Some(receipt) = settled(context, index, request, &values)? {
            receipts.push(receipt);
            continue;
        }
        let receipt = if context.action == "reconcile" {
            if request["kind"] == "presentation_operation" {
                let observation =
                    if let Some(transition) = frozen_cache_transition(context, index, request)? {
                        transition["canonicalReceipt"].clone()
                    } else {
                        match domain_reconciliation::read(
                            &api,
                            &auth,
                            request,
                            &context.expected_identity,
                        )
                        .await
                        {
                            Ok(value) => value,
                            Err(error)
                                if matches!(
                                    error.to_string().as_str(),
                                    "MANAGED_DOMAIN_OUTCOME_PENDING"
                                        | "MANAGED_WORK_RECONCILIATION_UNSUPPORTED"
                                ) =>
                            {
                                domain_pending = true;
                                continue;
                            }
                            Err(error) => return Err(error),
                        }
                    };
                // Revalidate the current journal before native cache I/O. The
                // owner revalidates again in its short settlement transaction.
                settle_domain_locally(context, index, &presentation, request, &observation)?
            } else {
                let observation =
                    read_run(&api, &auth, request, &context.expected_identity).await?;
                apply(&follow, &presentation, request, Some(&observation))?
            }
        } else {
            ensure!(context.action == "retire-local", "INVALID_REQUEST");
            apply(&follow, &presentation, request, None)?
        };
        record_settlement(context, index, request, &receipt)?;
        receipts.push(receipt);
    }
    drop(follow);
    drop(presentation);
    ensure!(!domain_pending, "MANAGED_DOMAIN_OUTCOME_PENDING");
    Ok(json!({"resolvedRecords":receipts.len(),"receipts":receipts}))
}

pub async fn run(path: &Path) -> Result<Value> {
    let context: WorkContext = serde_json::from_slice(&read_private(path, 262144)?)?;
    ensure!(
        context.schema == "app.loomex.runner.uninstall-work-context/v1"
            && matches!(context.action.as_str(), "reconcile" | "retire-local"),
        "INVALID_REQUEST"
    );
    ensure!(
        path == context.state_dir.join(format!(
            "uninstall-work-context-{}.json",
            context.attempt_id
        )),
        "UNSAFE_STATE"
    );
    let bytes = read_private(
        &context.state_dir.join("bootstrap-uninstall.json"),
        16 * 1024 * 1024,
    )?;
    ensure!(
        state::digest(&bytes) == context.journal_sha256,
        "LIFECYCLE_OPERATION_PENDING"
    );
    let journal: Value = serde_json::from_slice(&bytes)?;
    ensure!(
        journal["cleanup"]["stateDeletingStarted"] != true && journal["phase"] == "prepared",
        "LIFECYCLE_OPERATION_PENDING"
    );
    ensure!(
        state::json_digest(&journal["receipt"]) == context.receipt_sha256
            && journal["receipt"]["developmentApiOrigin"].as_str() == context.api_origin.as_deref(),
        "INVALID_API_ORIGIN"
    );
    let owner: Value = serde_json::from_slice(&read_private(
        &context.state_dir.join("uninstall-work.json"),
        262144,
    )?)?;
    ensure!(
        owner["operationId"] == context.operation_id.to_string()
            && owner["attempt"]["id"] == context.attempt_id.to_string()
            && owner["journalSha256"] == context.journal_sha256
            && owner["attempt"]["contextSha256"] == state::digest(&read_private(path, 262144)?),
        "LIFECYCLE_OPERATION_PENDING"
    );
    ensure!(
        state::digest(&std::fs::read(std::env::current_exe()?)?) == context.binary_sha256,
        "UNSAFE_STATE"
    );
    let operation: crate::lifecycle::Operation = serde_json::from_slice(&read_private(
        &context.state_dir.join("lifecycle-operation.json"),
        16 * 1024 * 1024,
    )?)?;
    operation.validate()?;
    ensure!(
        operation.id == context.operation_id
            && operation.phase == "work_maintenance"
            && operation
                .uninstall_fence
                .as_ref()
                .is_some_and(|fence| fence.journal_sha256 == context.journal_sha256
                    || journal["fenceJournalSha256"] == fence.journal_sha256),
        "LIFECYCLE_OPERATION_PENDING"
    );
    let credential_context = Context {
        schema: String::new(),
        operation_id: context.operation_id,
        state_dir: context.state_dir.clone(),
        install_base: context.install_base.clone(),
        launch_agents_dir: context.launch_agents_dir.clone(),
        journal_sha256: context.journal_sha256.clone(),
        receipt_sha256: context.receipt_sha256.clone(),
        expected_identity: None,
        api_origin: context.api_origin.clone(),
        singleton_fd: Some(context.singleton_fd),
        delete_credential: false,
    };
    let lock = Arc::new(singleton(&credential_context)?);
    let result = execute(&context, &lock).await;
    let report = match result {
        Ok(value) => {
            json!({"schema":"app.loomex.runner.uninstall-work-result/v1","operationId":context.operation_id,"attemptId":context.attempt_id,"ok":true,"result":value})
        }
        Err(error) => {
            let code = match error.to_string().as_str() {
                "MANAGED_WORK_OBSERVATION_INCOMPLETE" => "MANAGED_WORK_OBSERVATION_INCOMPLETE",
                "MANAGED_WORK_CHANGED" => "MANAGED_WORK_CHANGED",
                "MANAGED_WORK_MIGRATION_CHANGED" => "MANAGED_WORK_MIGRATION_CHANGED",
                "MANAGED_WORK_RECONCILIATION_REQUIRED" => "MANAGED_WORK_RECONCILIATION_REQUIRED",
                "AUTH_IDENTITY_CHANGED" => "AUTH_IDENTITY_CHANGED",
                "MANAGED_DOMAIN_OUTCOME_PENDING" => "MANAGED_DOMAIN_OUTCOME_PENDING",
                "MANAGED_WORK_RECEIPT_MISMATCH" => "MANAGED_WORK_RECEIPT_MISMATCH",
                "MANAGED_WORK_RECONCILIATION_UNSUPPORTED" => {
                    "MANAGED_WORK_RECONCILIATION_UNSUPPORTED"
                }
                _ => "UNINSTALL_WORK_NATIVE_FAILED",
            };
            json!({"schema":"app.loomex.runner.uninstall-work-result/v1","operationId":context.operation_id,"attemptId":context.attempt_id,"ok":false,"failureCode":code,"error":control::public_error_record(&error)})
        }
    };
    // Native/store workers retain lock ownership until runtime shutdown. The
    // parent still requires observed child exit before treating this as settled.
    state::write_json(&result_path(&context), &report)?;
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;
    fn context(dir: &Path, action: &str) -> WorkContext {
        let canonical = std::fs::canonicalize(dir).unwrap();
        let dir = canonical.as_path();
        WorkContext {
            schema: "app.loomex.runner.uninstall-work-context/v1".into(),
            operation_id: Uuid::new_v4(),
            attempt_id: Uuid::new_v4(),
            state_dir: dir.into(),
            install_base: dir.join("install"),
            launch_agents_dir: dir.join("agents"),
            journal_sha256: "a".repeat(64),
            receipt_sha256: "b".repeat(64),
            binary_sha256: "c".repeat(64),
            action: action.into(),
            expected_assessment_sha256: None,
            expected_identity: crate::auth::CredentialIdentity {
                installation_id: Uuid::new_v4().to_string(),
                device_id: None,
            },
            api_origin: None,
            singleton_fd: 7,
            authorize_keychain_transition: false,
        }
    }
    fn observation(run: &Value) -> Value {
        json!({"snapshot":{"execution":{"id":run,"status":"running"},"events":[],"latestSequence":0,"hasMoreEvents":false}})
    }

    #[test]
    fn historical_13_ready_14_pending_reconcile_then_exact_retire_and_requalify() {
        let root = tempfile::tempdir().unwrap();
        state::private_dir(root.path()).unwrap();
        let original =
            b"{\"schema\":\"app.loomex.runner.bootstrap-uninstall/v1\",\"phase\":\"prepared\"}\n";
        state::atomic_write(&root.path().join("bootstrap-uninstall.json"), original).unwrap();
        let mut ctx = context(root.path(), "reconcile");
        ctx.journal_sha256 = state::digest(original);
        std::fs::create_dir(&ctx.install_base).unwrap();
        std::fs::create_dir(&ctx.launch_agents_dir).unwrap();
        let paths = crate::lifecycle::Paths {
            state_dir: ctx.state_dir.clone(),
            install_base: ctx.install_base.clone(),
            launch_agents_dir: ctx.launch_agents_dir.clone(),
        };
        let _lifecycle = crate::lifecycle::LifecycleLock::acquire(&paths).unwrap();
        let mut prior = crate::lifecycle::Operation::new(
            crate::lifecycle::OperationKind::Install,
            "completed",
            None,
        );
        prior.auth_baseline = Some(crate::lifecycle::AuthBaseline::SignedOut {
            installation_id: Some(Uuid::parse_str(&ctx.expected_identity.installation_id).unwrap()),
        });
        prior.previous_target = Some(ctx.install_base.join("versions/1.2.3"));
        state::write_json(&root.path().join("lifecycle-operation.json"), &prior).unwrap();
        let prior_bytes = std::fs::read(root.path().join("lifecycle-operation.json")).unwrap();
        crate::lifecycle::begin_uninstall_work_locked(
            &paths,
            ctx.operation_id,
            &ctx.journal_sha256,
        )
        .unwrap();
        state::write_json(
            &root.path().join("uninstall-work.json"),
            &json!({"schema":"app.loomex.runner.uninstall-work/v1","phase":"work_maintenance","operationId":ctx.operation_id,"journalSha256":ctx.journal_sha256}),
        )
        .unwrap();
        let follow = Some(FollowStore::open(root.path()).unwrap());
        let presentation = Some(PresentationStore::open(root.path()).unwrap());
        for index in 0..14 {
            let run = Uuid::new_v4().to_string();
            let receipt = follow
                .as_ref()
                .unwrap()
                .issue_continuation(
                    "org",
                    "account",
                    &ctx.expected_identity.installation_id,
                    &run,
                    "run_commit",
                    None,
                )
                .unwrap();
            follow
                .as_ref()
                .unwrap()
                .activate_ui_handoff(
                    "org",
                    "account",
                    &ctx.expected_identity.installation_id,
                    &run,
                    &receipt,
                    None,
                )
                .unwrap();
            if index < 13 {
                presentation.as_ref().unwrap().register_delivery("org","account",&format!("follow:{run}:run_started"),&json!({"kind":"follow","schemaVersion":"loomex.follow-session.continuation/v1","runId":run,"receipt":receipt,"trigger":"run_commit","requestId":null})).unwrap();
            }
        }
        let before = crate::uninstall_state::assess_state(root.path()).unwrap();
        assert!(!before.resolved);
        let values = candidates(&follow, &presentation).unwrap();
        assert_eq!(values.len(), 27);
        let requests = scoped_requests(&ctx, &values).unwrap();
        for (index, request) in requests.iter().enumerate() {
            let receipt = apply(
                &follow,
                &presentation,
                request,
                Some(&observation(&request["runId"])),
            )
            .unwrap();
            record_settlement(&ctx, index, request, &receipt).unwrap();
        }
        assert_eq!(
            scoped_requests(&ctx, &candidates(&follow, &presentation).unwrap()).unwrap(),
            requests
        );
        assert!(
            candidates(&follow, &presentation)
                .unwrap()
                .iter()
                .all(|candidate| candidate["resolution"]["state"] == "unresolved")
        );
        drop(follow);
        drop(presentation);
        assert!(
            !crate::uninstall_state::assess_state(root.path())
                .unwrap()
                .resolved,
            "canonical active reads never manufacture local closure"
        );
        let mut retire = context(root.path(), "retire-local");
        retire.operation_id = ctx.operation_id;
        retire.journal_sha256 = ctx.journal_sha256.clone();
        let follow = Some(FollowStore::open(root.path()).unwrap());
        let presentation = Some(PresentationStore::open(root.path()).unwrap());
        let requests =
            scoped_requests(&retire, &candidates(&follow, &presentation).unwrap()).unwrap();
        // Crash after the first durable closure, before its observer checkpoint.
        let first = apply(&follow, &presentation, &requests[0], None).unwrap();
        drop(follow);
        drop(presentation);
        let follow = Some(FollowStore::open(root.path()).unwrap());
        let presentation = Some(PresentationStore::open(root.path()).unwrap());
        let resumed =
            scoped_requests(&retire, &candidates(&follow, &presentation).unwrap()).unwrap();
        assert_eq!(requests, resumed);
        assert_eq!(
            apply(&follow, &presentation, &resumed[0], None).unwrap(),
            first
        );
        for (index, request) in resumed.iter().enumerate() {
            let receipt = apply(&follow, &presentation, request, None).unwrap();
            record_settlement(&retire, index, request, &receipt).unwrap();
        }
        for candidate in presentation
            .as_ref()
            .unwrap()
            .maintenance_candidates()
            .unwrap()
        {
            assert_eq!(
                candidate["status"], "ready",
                "retirement never fabricates host acknowledgement"
            );
        }
        for candidate in follow.as_ref().unwrap().maintenance_candidates().unwrap() {
            assert_eq!(candidate["lifecycle"], "handoff_pending");
        }
        drop(follow);
        drop(presentation);
        assert!(
            crate::uninstall_state::assess_state(root.path())
                .unwrap()
                .resolved
        );
        assert!(crate::uninstall_state::inventory_resolved_state(root.path()).is_ok());
        assert_eq!(
            std::fs::read(root.path().join("bootstrap-uninstall.json")).unwrap(),
            original
        );
        let owner: crate::lifecycle::Operation =
            state::read_json(&root.path().join("lifecycle-operation.json")).unwrap();
        assert_eq!(
            owner
                .uninstall_fence
                .unwrap()
                .original_operation_snapshot
                .unwrap()
                .as_bytes(),
            prior_bytes
        );
        let operations = root.path().join("operations");
        state::private_dir(&operations).unwrap();
        state::write_json(
            &operations.join(format!("{}.json", Uuid::new_v4())),
            &json!({"status":"pending","method":"builder.start"}),
        )
        .unwrap();
        let blocked = crate::uninstall_state::assess_state(root.path()).unwrap();
        assert!(!blocked.resolved);
        assert!(
            blocked.blockers.iter().any(
                |item| item.category == crate::uninstall_state::BlockerCategory::OperationCache
            )
        );
        std::fs::remove_dir_all(&operations).unwrap();
        assert!(
            crate::uninstall_state::assess_state(root.path())
                .unwrap()
                .resolved
        );
        let recovery = crate::recovery::RecoveryStore::open(root.path()).unwrap();
        let binding = json!({"hostId":"local","hostTaskId":"fixture-task","runId":Uuid::new_v4()});
        recovery.dispatch("org","account",&ctx.expected_identity.installation_id,"recovery.update",&json!({"binding":binding,"expectedRevision":0,"initialization":"run_started","idempotencyKey":Uuid::new_v4()})).unwrap();
        recovery.dispatch("org","account",&ctx.expected_identity.installation_id,"recovery.operations.begin",&json!({"binding":binding,"expectedRevision":1,"operation":{"kind":"create","arguments":{},"idempotencyKey":Uuid::new_v4()},"idempotencyKey":Uuid::new_v4()})).unwrap();
        drop(recovery);
        let blocked = crate::uninstall_state::assess_state(root.path()).unwrap();
        assert!(!blocked.resolved);
        assert!(
            blocked
                .blockers
                .iter()
                .any(|item| item.category
                    == crate::uninstall_state::BlockerCategory::RecoverySchedule)
        );
    }

    fn domain_fixture(dir: &Path) -> (Option<PresentationStore>, Value) {
        let store = PresentationStore::open(dir).unwrap();
        let session=store.dispatch("org-a","user-a","presentation.sessions.create",&json!({"kind":"monitor","entityType":"execution","entityId":Uuid::new_v4(),"state":{},"idempotencyKey":Uuid::new_v4()})).unwrap();
        let key = Uuid::new_v4();
        let params = json!({"workflowId":Uuid::new_v4(),"expectedVersion":2,"notes":"PRIVATE_DOMAIN_ARGUMENT","idempotencyKey":key});
        store.dispatch("org-a","user-a","presentation.sessions.update",&json!({"viewSessionId":session["viewSessionId"],"expectedRevision":0,"state":{},"operation":{"method":"workflows.publish","params":params,"idempotencyKey":key,"reconciliation":{"method":"workflow.operations.get","params":{"operation":"workflows.publish","idempotencyKey":key}}},"idempotencyKey":Uuid::new_v4()})).unwrap();
        let candidate = store.maintenance_operation_candidates().unwrap().remove(0);
        let (path, identity) = control::maintenance_cache_identity(&candidate).unwrap();
        state::private_dir(&dir.join("operations")).unwrap();
        state::write_json(
            &dir.join(path),
            &json!({"method":"workflows.publish","digest":identity,"status":"pending"}),
        )
        .unwrap();
        (Some(store), candidate)
    }
    fn domain_receipt(candidate: &Value) -> Value {
        json!({"operation":"workflows.publish","idempotencyKey":candidate["operationKey"],"status":"completed","response":{"workflow":{"id":candidate["params"]["workflowId"],"name":"PRIVATE_DOMAIN_RESPONSE"},"version":{"id":Uuid::new_v4(),"number":2}}})
    }
    #[test]
    fn native_patch_related_transition_resumes_between_files_and_preserves_original_intent() {
        for ordinary_completed in [false, true] {
            let root = tempfile::tempdir().unwrap();
            state::private_dir(root.path()).unwrap();
            let ctx = context(root.path(), "reconcile");
            let store = PresentationStore::open(root.path()).unwrap();
            let session=store.dispatch("org-a","user-a","presentation.sessions.create",&json!({"kind":"monitor","entityType":"execution","entityId":Uuid::new_v4(),"state":{},"idempotencyKey":Uuid::new_v4()})).unwrap();
            let key = Uuid::new_v4();
            let workflow = Uuid::new_v4();
            let params = json!({"workflowId":workflow,"expectedVersion":2,"expectedDefinitionChecksum":"a".repeat(64),"operations":[{"nodeKey":"node","op":"replace","path":"/prompt","value":"PRIVATE_PATCH_ARGUMENT"}],"idempotencyKey":key});
            store.dispatch("org-a","user-a","presentation.sessions.update",&json!({"viewSessionId":session["viewSessionId"],"expectedRevision":0,"state":{},"operation":{"method":"workflows.patch","params":params,"idempotencyKey":key,"reconciliation":{"method":"workflow.operations.get","params":{"operation":"workflows.update","idempotencyKey":key}}},"idempotencyKey":Uuid::new_v4()})).unwrap();
            let body = json!({"definition":{"nodes":[{"key":"node","prompt":"PRIVATE_PATCH_RESPONSE"}]},"expectedVersion":2});
            let identity = state::json_digest(
                &json!({"organizationId":"org-a","accountSubject":"user-a","workflowId":workflow,"expectedVersion":2,"expectedDefinitionChecksum":"a".repeat(64),"operations":params["operations"],"requestedNotes":null,"idempotencyKey":key}),
            );
            let original = json!({"identity":identity,"workflowId":workflow,"expectedVersion":2,"expectedDefinitionChecksum":"a".repeat(64),"updateBody":body,"updateDigest":state::json_digest(&body["definition"]),"payloadDigest":state::json_digest(&body),"notesProvided":false,"expectedNotes":"prior notes","status":"submitted"});
            let reference = state::json_digest(
                &json!({"organizationId":"org-a","accountSubject":"user-a","idempotencyKey":key}),
            );
            let native = root
                .path()
                .join("workflow-patches")
                .join(format!("{reference}.json"));
            state::write_json(&native, &original).unwrap();
            if ordinary_completed {
                let pending = store.maintenance_operation_candidates().unwrap().remove(0);
                store.dispatch("org-a","user-a","presentation.operations.settle",&json!({"viewSessionId":pending["viewSessionId"],"operationId":pending["operationId"],"status":"completed","resultReference":{"historical":"preserve"},"idempotencyKey":Uuid::new_v4()})).unwrap();
            }
            let mut values = store.maintenance_operation_candidates().unwrap();
            attach_patch_journals(&ctx, &mut values).unwrap();
            let (cache, identity) = control::maintenance_cache_identity(&values[0]).unwrap();
            let receipt = json!({"operation":"workflows.update","idempotencyKey":key,"status":"completed","response":{"workflow":{"id":workflow},"draft":{"definition":body["definition"],"notes":"prior notes"}}});
            let cached = if ordinary_completed {
                json!({"method":"workflows.patch","digest":identity,"cachedAt":state::now(),"executionId":null,"result":receipt["response"]})
            } else {
                json!({"method":"workflows.patch","digest":identity,"status":"pending"})
            };
            state::write_json(&root.path().join(cache), &cached).unwrap();
            let requests = scoped_requests(&ctx, &values).unwrap();
            let request = &requests[0];
            let cache = control::maintenance_cache_prepare(root.path(), request, &receipt).unwrap();
            let patch = control::maintenance_patch_prepare(root.path(), request, &receipt)
                .unwrap()
                .unwrap();
            let primary = if let Some(mut cache) = cache {
                cache["relatedTargets"] = json!([patch]);
                cache
            } else {
                patch
            };
            immutable_json(&cache_transition_path(&ctx,0),&json!({"schema":"app.loomex.runner.uninstall-work-cache-transition/v1","operationId":ctx.operation_id,"attemptId":ctx.attempt_id,"index":0,"requestDigest":state::json_digest(request),"transition":primary})).unwrap();
            // Death after the first file and before the native intent receipt. Only
            // these two exact pre/post states are accepted by the original attempt.
            if !ordinary_completed {
                state::atomic_write(
                    &root.path().join(primary["path"].as_str().unwrap()),
                    primary["after"].as_str().unwrap().as_bytes(),
                )
                .unwrap();
            } else {
                assert_eq!(primary["kind"], "native_patch");
            }
            assert_eq!(state::read_json::<Value>(&native).unwrap(), original);
            assert_eq!(scoped_requests(&ctx, &values).unwrap(), requests);
            settle_cache(&ctx, 0, request, &receipt).unwrap();
            let resolved: Value = state::read_json(&native).unwrap();
            assert!(crate::presentation::maintenance_native_patch_resolved(&resolved).unwrap());
            assert_eq!(resolved["status"], "submitted");
            let mut historical = resolved;
            historical
                .as_object_mut()
                .unwrap()
                .remove("maintenanceResolution");
            assert_eq!(historical, original);
            let presentation = Some(store);
            let summary = apply(&None, &presentation, request, Some(&receipt)).unwrap();
            record_settlement(&ctx, 0, request, &summary).unwrap();
            let current = candidates(&None, &presentation).unwrap();
            assert_eq!(settled(&ctx, 0, request, &current).unwrap(), Some(summary));
            if ordinary_completed {
                assert_eq!(
                    current[0]["resultReference"],
                    json!({"historical":"preserve"})
                );
            }
            drop(presentation);
            assert!(
                crate::uninstall_state::assess_state(root.path())
                    .unwrap()
                    .resolved
            );
            assert!(
                crate::uninstall_state::inventory_resolved_state(root.path())
                    .unwrap()
                    .contains(&native)
            );
            let mut wrong = state::read_json::<Value>(&native).unwrap();
            wrong["maintenanceResolution"]["receiptDigest"] = json!("0".repeat(64));
            state::write_json(&native, &wrong).unwrap();
            assert!(scoped_requests(&ctx, &values).is_err());
            assert!(
                !crate::uninstall_state::assess_state(root.path())
                    .unwrap()
                    .resolved
            );
        }
    }

    #[tokio::test]
    async fn domain_exact_receipt_cache_then_store_interruption_resumes_original_attempt() {
        let root = tempfile::tempdir().unwrap();
        state::private_dir(root.path()).unwrap();
        let ctx = context(root.path(), "reconcile");
        let (presentation, candidate) = domain_fixture(root.path());
        let values = vec![candidate];
        let requests = scoped_requests(&ctx, &values).unwrap();
        let request = &requests[0];
        let original = domain_receipt(request);
        let copy = original.clone();
        let owner = domain_reconciliation::Owner {
            organization: "org-a",
            account: "user-a",
            installation: &ctx.expected_identity.installation_id,
        };
        let canonical =
            domain_reconciliation::read_with(request, &owner, |verb, route, body| async move {
                assert_eq!(verb, "POST");
                assert_eq!(route, "v2/workflow-operations/get/");
                assert_eq!(body.unwrap().as_object().unwrap().len(), 2);
                Ok(copy)
            })
            .await
            .unwrap();
        verify_current_domain(&presentation, request).unwrap();
        settle_cache(&ctx, 0, request, &canonical).unwrap();
        // Simulate death after durable cache replacement and before SQL owner
        // settlement. The original requestset and receipt authorize exact resume.
        assert_eq!(
            presentation
                .as_ref()
                .unwrap()
                .maintenance_operation_candidates()
                .unwrap()[0]["status"],
            "pending"
        );
        let replay = scoped_requests(&ctx, &candidates(&None, &presentation).unwrap()).unwrap();
        assert_eq!(replay, requests);
        let frozen = frozen_cache_transition(&ctx, 0, &replay[0])
            .unwrap()
            .unwrap();
        assert_eq!(frozen["canonicalReceipt"], original);
        settle_cache(&ctx, 0, &replay[0], &frozen["canonicalReceipt"]).unwrap();
        let summary = apply(
            &None,
            &presentation,
            &replay[0],
            Some(&frozen["canonicalReceipt"]),
        )
        .unwrap();
        assert!(!summary.to_string().contains("PRIVATE_DOMAIN"));
        // Death after owner commit but before the maintenance checkpoint reuses
        // the same owner idempotency receipt, with no second backend mutation.
        assert_eq!(
            apply(&None, &presentation, &replay[0], Some(&original)).unwrap(),
            summary
        );
        record_settlement(&ctx, 0, &replay[0], &summary).unwrap();
        let current = candidates(&None, &presentation).unwrap();
        assert_eq!(
            settled(&ctx, 0, &replay[0], &current).unwrap(),
            Some(summary)
        );
        assert_eq!(scoped_requests(&ctx, &current).unwrap(), requests);
        let cache = &frozen["path"].as_str().unwrap();
        let mut different: Value = state::read_json(&root.path().join(cache)).unwrap();
        different["result"]["workflow"]["name"] = json!("changed externally");
        state::write_json(&root.path().join(cache), &different).unwrap();
        assert!(scoped_requests(&ctx, &current).is_err());
    }
    #[test]
    fn domain_cache_refuses_wrong_params_scope_key_receipt_and_replaced_journal() {
        let root = tempfile::tempdir().unwrap();
        state::private_dir(root.path()).unwrap();
        let ctx = context(root.path(), "reconcile");
        let (presentation, candidate) = domain_fixture(root.path());
        let values = vec![candidate];
        let retire = context(root.path(), "retire-local");
        assert!(
            scoped_requests(&retire, &values).unwrap().is_empty(),
            "domain mutations are never local handoff retirement candidates"
        );
        let requests = scoped_requests(&ctx, &values).unwrap();
        let request = &requests[0];
        let receipt = domain_receipt(request);
        for field in ["organizationId", "accountSubject", "operationKey"] {
            let mut changed = request.clone();
            changed[field] = json!(Uuid::new_v4());
            assert!(settle_domain_locally(&ctx, 0, &presentation, &changed, &receipt).is_err());
        }
        let mut changed = request.clone();
        changed["params"]["notes"] = json!("different");
        assert!(settle_domain_locally(&ctx, 0, &presentation, &changed, &receipt).is_err());
        let mut wrong = receipt.clone();
        wrong["idempotencyKey"] = json!(Uuid::new_v4());
        assert!(settle_cache(&ctx, 0, request, &wrong).is_err());
        assert!(!cache_transition_path(&ctx, 0).exists());
        let current = presentation
            .as_ref()
            .unwrap()
            .maintenance_operation_candidates()
            .unwrap()
            .remove(0);
        presentation.as_ref().unwrap().dispatch("org-a","user-a","presentation.sessions.update",&json!({"viewSessionId":current["viewSessionId"],"expectedRevision":current["revision"],"state":{"newRevision":true},"idempotencyKey":Uuid::new_v4()})).unwrap();
        assert!(verify_current_domain(&presentation, request).is_err());
        let (path, _) = control::maintenance_cache_identity(request).unwrap();
        let pending: Value = state::read_json(&root.path().join(path)).unwrap();
        assert_eq!(pending["status"], "pending");
    }

    #[test]
    fn immutable_attempt_scope_refuses_replacement_and_dependency_drift() {
        let root = tempfile::tempdir().unwrap();
        state::private_dir(root.path()).unwrap();
        let ctx = context(root.path(), "retire-local");
        let values = vec![
            json!({"kind":"follow_session","organizationId":"org","accountSubject":"account","installationId":ctx.expected_identity.installation_id,"recordId":Uuid::new_v4(),"runId":Uuid::new_v4(),"recordDigest":"a".repeat(64),"resolution":{"state":"unresolved"}}),
        ];
        let original = scoped_requests(&ctx, &values).unwrap();
        assert_eq!(scoped_requests(&ctx, &values).unwrap(), original);
        let mut changed = values.clone();
        changed[0]["recordDigest"] = json!("b".repeat(64));
        assert!(scoped_requests(&ctx, &changed).is_err());
        state::private_dir(&root.path().join("operations")).unwrap();
        state::write_json(
            &root.path().join("operations/new.json"),
            &json!({"status":"unknown"}),
        )
        .unwrap();
        assert!(scoped_requests(&ctx, &values).is_err());
    }
}

#[cfg(test)]
mod authorization_tests {
    use super::*;
    #[tokio::test]
    async fn explicit_needed_transition_only_and_abandoned_probe_retains_singleton() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let root = tempfile::tempdir().unwrap();
        state::private_dir(root.path()).unwrap();
        let lock = Arc::new(acquire_singleton(root.path()).unwrap());
        let count = Arc::new(AtomicUsize::new(0));
        for (explicit, readable) in [(false, false), (false, true), (true, true), (true, false)] {
            if authorization_needed(explicit, readable) {
                let count = count.clone();
                owned_probe(&lock, move || {
                    count.fetch_add(1, Ordering::SeqCst);
                    "AUTHORIZED"
                })
                .await
                .unwrap();
            }
        }
        assert_eq!(count.load(Ordering::SeqCst), 1);
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let owner = lock.clone();
        let task = tokio::spawn(async move {
            owned_probe(&owner, move || {
                started_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                "AUTHORIZED"
            })
            .await
        });
        started_rx.await.unwrap();
        task.abort();
        let _ = task.await;
        drop(lock);
        assert!(
            acquire_singleton(root.path()).is_err(),
            "native probe owns singleton after observer cancellation"
        );
        release_tx.send(()).unwrap();
        for _ in 0..100 {
            if acquire_singleton(root.path()).is_ok() {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        panic!("finished mock probe did not release singleton");
    }
}
