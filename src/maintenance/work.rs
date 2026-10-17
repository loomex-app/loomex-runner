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
    #[serde(default)]
    maintenance_generation: Option<u64>,
    #[serde(default)]
    release_manifest_sha256: Option<String>,
    // The parent binds these exact immutable context bytes externally.
    #[serde(skip)]
    context_sha256: String,
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
    #[serde(default = "default_retirement_scope")]
    retirement_scope: String,
    expected_identity: crate::auth::CredentialIdentity,
    api_origin: Option<String>,
    singleton_fd: i32,
    #[serde(default)]
    authorize_keychain_transition: bool,
}

fn default_retirement_scope() -> String {
    "continuations".into()
}

fn generation_context(context: &WorkContext) -> bool {
    context.schema == "app.loomex.runner.uninstall-work-context/v2"
}

fn validate_context_owner(context: &WorkContext, owner: &Value, digest: &str) -> Result<()> {
    ensure!(
        owner["operationId"] == context.operation_id.to_string()
            && owner["attempt"]["id"] == context.attempt_id.to_string()
            && owner["journalSha256"] == context.journal_sha256
            && owner["attempt"]["contextSha256"] == digest,
        "LIFECYCLE_OPERATION_PENDING"
    );
    if generation_context(context) {
        let generation = context.maintenance_generation.context("INVALID_REQUEST")?;
        let manifest = context
            .release_manifest_sha256
            .as_deref()
            .context("INVALID_REQUEST")?;
        ensure!(
            valid_work_digest(manifest)
                && owner["schema"] == "app.loomex.runner.uninstall-work/v2"
                && matches!(
                    owner["attempt"]["state"].as_str(),
                    Some("spawn_pending" | "running")
                )
                && owner["currentGeneration"].as_u64() == Some(generation)
                && owner["attempt"]["maintenanceGeneration"].as_u64() == Some(generation)
                && owner["attempt"]["releaseManifestSha256"] == manifest
                && owner["releaseManifestSha256"] == manifest
                && owner["generations"].as_array().is_some_and(|generations| {
                    generations
                        .iter()
                        .filter(|entry| entry["generation"].as_u64() == Some(generation))
                        .count()
                        == 1
                        && generations.iter().any(|entry| {
                            entry["generation"].as_u64() == Some(generation)
                                && entry["releaseManifestSha256"] == manifest
                                && entry["releasePath"] == owner["releasePath"]
                        })
                }),
            "LIFECYCLE_OPERATION_PENDING"
        );
    } else {
        ensure!(
            context.schema == "app.loomex.runner.uninstall-work-context/v1"
                && context.maintenance_generation.is_none()
                && context.release_manifest_sha256.is_none()
                && owner["schema"] == "app.loomex.runner.uninstall-work/v1",
            "LIFECYCLE_OPERATION_PENDING"
        );
    }
    Ok(())
}

fn valid_work_digest(digest: &str) -> bool {
    digest.len() == 64
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn current_context_owner(context: &WorkContext) -> Result<()> {
    let owner: Value = serde_json::from_slice(&read_private(
        &context.state_dir.join("uninstall-work.json"),
        16 * 1024 * 1024,
    )?)?;
    let bytes = read_private(
        &context.state_dir.join(format!(
            "uninstall-work-context-{}.json",
            context.attempt_id
        )),
        262144,
    )?;
    let digest = state::digest(&bytes);
    ensure!(
        digest == context.context_sha256,
        "LIFECYCLE_OPERATION_PENDING"
    );
    validate_context_owner(context, &owner, &digest)
}

// v1 records remain byte-compatible with their original historical attempt.
// v2 records add the immutable release/generation/context binding without
// replacing the original request, idempotency key, candidate digest or scope.
fn bind_record(context: &WorkContext, mut value: Value) -> Value {
    if generation_context(context) {
        value["maintenanceGeneration"] = json!(context.maintenance_generation);
        value["releaseManifestSha256"] = json!(context.release_manifest_sha256);
        value["contextSha256"] = json!(context.context_sha256);
    }
    value
}
fn validate_record_binding(context: &WorkContext, value: &Value) -> Result<()> {
    if generation_context(context) {
        ensure!(
            value["maintenanceGeneration"].as_u64() == context.maintenance_generation
                && value["releaseManifestSha256"].as_str()
                    == context.release_manifest_sha256.as_deref()
                && value["contextSha256"] == context.context_sha256,
            "MANAGED_WORK_CHANGED"
        );
    } else {
        ensure!(
            [
                "maintenanceGeneration",
                "releaseManifestSha256",
                "contextSha256"
            ]
            .iter()
            .all(|field| value.get(field).is_none()),
            "MANAGED_WORK_CHANGED"
        );
    }
    Ok(())
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
fn current_candidates(
    context: &WorkContext,
    follow: &Option<FollowStore>,
    presentation: &Option<PresentationStore>,
) -> Result<Vec<Value>> {
    let mut values = candidates(follow, presentation)?;
    values.extend(crate::operation_cache::inspect(&context.state_dir)?);
    enrich_candidates(context, &mut values)?;
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

fn cache_has_exact_owner(cache: &Value, owner: &Value) -> bool {
    cache["kind"] == "operation_cache"
        && owner["kind"] == "presentation_operation"
        && control::maintenance_cache_identity(owner).is_ok_and(|(path, digest)| {
            cache["path"] == path && cache["record"]["digest"] == digest
        })
}
fn candidate_set_digest(values: &[Value]) -> String {
    let mut items = values
        .iter()
        // The exact owner already identifies this cache's operation. Full cache
        // bytes remain fenced by dependencyEntries and any recorded pre/post
        // transition, so an owner repair cannot alter candidate-set identity.
        .filter(|value| {
            !values
                .iter()
                .any(|owner| cache_has_exact_owner(value, owner))
        })
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
    validate_record_binding(context, &value)?;
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
    if generation_context(context) {
        current_context_owner(context)?;
    }
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
            let (cache_path, identity) = control::maintenance_cache_identity(request)?;
            let versioned_pending = if context.state_dir.join(&cache_path).try_exists()? {
                let source: Value = serde_json::from_slice(&crate::operation_cache::read(
                    &context.state_dir,
                    &cache_path,
                )?)?;
                ensure!(
                    source["digest"] == identity && source["method"] == request["method"],
                    "MANAGED_WORK_CHANGED"
                );
                !source["binding"].is_null()
                    && source["status"] == "pending"
                    && crate::operation_cache::known_record(&source)
            } else {
                false
            };
            let cache = if versioned_pending {
                None
            } else {
                control::maintenance_cache_prepare(&context.state_dir, request, receipt)?
            };
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
            &bind_record(
                context,
                json!({"schema":"app.loomex.runner.uninstall-work-cache-transition/v1","operationId":context.operation_id,"attemptId":context.attempt_id,"index":index,"requestDigest":state::json_digest(request),"transition":transition}),
            ),
        )?;
    }
    verify_dependencies(context, &saved)?;
    control::maintenance_cache_apply(&context.state_dir, request, &transition)
}
fn enrich_candidates(context: &WorkContext, values: &mut [Value]) -> Result<()> {
    attach_patch_journals(context, values)?;
    attach_operation_owners(context, values)
}

fn attach_operation_owners(context: &WorkContext, values: &mut [Value]) -> Result<()> {
    let owners = values
        .iter()
        .filter(|value| value["kind"] == "presentation_operation")
        .cloned()
        .collect::<Vec<_>>();
    let catalog: Value = serde_json::from_str(include_str!("../../contracts/method-catalog.json"))?;
    for cache in values
        .iter_mut()
        .filter(|value| value["kind"] == "operation_cache" && value["binding"].is_null())
    {
        let matches = owners
            .iter()
            .filter(|owner| {
                control::maintenance_cache_identity(owner).is_ok_and(|(path, digest)| {
                    cache["path"] == path && cache["record"]["digest"] == digest
                })
            })
            .collect::<Vec<_>>();
        ensure!(matches.len() <= 1, "MANAGED_WORK_RECEIPT_MISMATCH");
        let Some(owner) = matches.first() else {
            continue;
        };
        let method = owner["method"].as_str().context("MANAGED_WORK_CHANGED")?;
        let schema = catalog["methods"]
            .as_array()
            .context("INTERNAL")?
            .iter()
            .find(|entry| entry["name"] == method)
            .context("INTERNAL")?;
        let installation = owner["installationId"]
            .as_str()
            .filter(|value| !value.is_empty())
            .unwrap_or(&context.expected_identity.installation_id);
        ensure!(
            installation == context.expected_identity.installation_id,
            "AUTH_IDENTITY_CHANGED"
        );
        let mut binding = crate::operation_cache::binding(
            method,
            owner["operationKey"]
                .as_str()
                .context("MANAGED_WORK_CHANGED")?,
            cache["record"]["digest"]
                .as_str()
                .context("MANAGED_WORK_CHANGED")?,
            &schema["inputSchema"],
            &owner["params"],
            crate::operation_cache::BindingOrigin {
                organization: owner["organizationId"].as_str(),
                account: owner["accountSubject"].as_str(),
                installation,
                control_reference: None,
            },
        );
        if let Some(receipt) = control::interaction_cache_receipt(method, &owner["params"])? {
            binding["backendSubmissionDigest"] = receipt["params"]["submissionFingerprint"].clone();
            binding["receipt"] = receipt;
        }
        cache["reconciliationSupported"] =
            json!(crate::operation_cache::raw_reconciliation_supported(
                method,
                &binding,
                cache["runId"].as_str()
            ));
        cache["binding"] = binding;
        cache["organizationId"] = owner["organizationId"].clone();
        cache["accountSubject"] = owner["accountSubject"].clone();
        cache["installationId"] = json!(installation);
        cache["ownerJournalDigest"] = owner["recordDigest"].clone();
        cache["ownerJournal"] = (*owner).clone();
    }
    Ok(())
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
    if std::fs::symlink_metadata(path).is_ok() {
        ensure!(
            read_private(path, 16 * 1024 * 1024)? == bytes,
            "MANAGED_WORK_CHANGED"
        );
        return Ok(());
    }
    let parent = path.parent().context("UNSAFE_STATE")?;
    let temporary = parent.join(format!(
        ".uninstall-work-publication-{}",
        uuid::Uuid::new_v4()
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&temporary)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    drop(file);
    // Both lifecycle and daemon singleton owners are held by callers. A crash
    // can leave only an unreferenced private temporary, never a partial final
    // request, transition or settlement that prevents the same intent resuming.
    ensure!(
        matches!(std::fs::symlink_metadata(path),Err(error) if error.kind()==std::io::ErrorKind::NotFound),
        "MANAGED_WORK_CHANGED"
    );
    std::fs::rename(&temporary, path)?;
    File::open(parent)?.sync_all()?;
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
                && saved["candidateSetDigest"] == candidate_set_digest(values)
                && saved["retirementScope"].as_str().unwrap_or("continuations")
                    == context.retirement_scope,
            "MANAGED_WORK_CHANGED"
        );
        validate_record_binding(context, &saved)?;
        verify_dependencies(context, &saved)?;
        return Ok(saved["requests"]
            .as_array()
            .ok_or_else(|| anyhow::anyhow!("INVALID_REQUEST"))?
            .clone());
    }
    let mut requests = values
        .iter()
        .filter(|value| {
            // A selected presentation owner repairs its exact three-field
            // legacy source. Do not schedule the same mutable source twice.
            let paired_legacy = value["kind"] == "operation_cache"
                && value["record"]
                    .as_object()
                    .is_some_and(|record| record.len() == 3)
                && value["record"]["status"] == "pending"
                && values.iter().any(|owner| {
                    cache_has_exact_owner(value, owner)
                        && owner["resolution"]["state"] == "unresolved"
                });
            !paired_legacy
                && (value["resolution"]["state"] == "unresolved"
                    || (context.action == "reconcile"
                        && value["kind"] == "presentation_operation"
                        && value["method"] == "workflows.patch"
                        && value["status"] == "completed"
                        && value["nativePatchJournal"].is_object()
                        && value["nativePatchResolved"] != true))
                && (context.action == "reconcile"
                    || (context.retirement_scope == "operation-observations"
                        && value["kind"] == "operation_cache"
                        && value["retirementEligible"] == true)
                    || (context.retirement_scope == "continuations"
                        && (value["kind"] == "follow_session"
                            || (value["kind"] == "presentation_delivery"
                                && value["retirementEligible"] == true))))
        })
        .cloned()
        .collect::<Vec<_>>();
    ensure!(requests.len() <= 256, "MANAGED_WORK_PREVIEW_LIMIT");
    for request in &mut requests {
        request["idempotencyKey"] = json!(uuid::Uuid::new_v4());
    }
    immutable_json(
        &path,
        &bind_record(
            context,
            json!({"schema":"app.loomex.runner.uninstall-work-requests/v1","operationId":context.operation_id,"attemptId":context.attempt_id,"candidateSetDigest":candidate_set_digest(values),"retirementScope":context.retirement_scope,"dependenciesDigest":dependencies_digest(&context.state_dir)?,"dependencyEntries":dependency_entries(&context.state_dir)?,"acceptanceDependencies":crate::uninstall_state::maintenance_acceptance_dependencies(&context.state_dir)?,"requests":requests}),
        ),
    )?;
    Ok(requests)
}
fn record_settlement(
    context: &WorkContext,
    index: usize,
    request: &Value,
    receipt: &Value,
) -> Result<()> {
    if generation_context(context) {
        current_context_owner(context)?;
    }
    let path = context.state_dir.join(format!(
        "uninstall-work-checkpoint-{}-{index}.json",
        context.attempt_id
    ));
    let value = bind_record(
        context,
        json!({"schema":"app.loomex.runner.uninstall-work-record/v1","operationId":context.operation_id,"attemptId":context.attempt_id,"index":index,"requestDigest":state::json_digest(request),"receipt":receipt}),
    );
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
fn settle_operation_observation(
    context: &WorkContext,
    request: &Value,
    observation: &Value,
) -> Result<Value> {
    if generation_context(context) {
        current_context_owner(context)?;
    }
    let slot = request["legacySlot"]
        .as_str()
        .context("MANAGED_WORK_CHANGED")?;
    let path = context.state_dir.join(format!(
        "recovery-evidence/operation-canonical-{}.json",
        state::digest(slot.as_bytes())
    ));
    let bytes = crate::operation_cache::read(
        &context.state_dir,
        request["path"].as_str().context("MANAGED_WORK_CHANGED")?,
    )?;
    ensure!(
        request["recordDigest"] == state::digest(&bytes),
        "MANAGED_WORK_CHANGED"
    );
    let proof = json!({"schema":"loomex.operation-cache-canonical-observation/v1","legacySlot":slot,"originalCacheSha256":state::digest(&bytes),"method":request["method"],"binding":request["binding"],"ownerJournal":request["ownerJournal"],"operationId":context.operation_id,"attemptId":context.attempt_id,"journalSha256":context.journal_sha256,"receiptSha256":context.receipt_sha256,"observation":observation});
    crate::uninstall_state::validate_canonical_operation_completion(
        &request["record"],
        &proof,
        slot,
        &state::digest(&bytes),
    )?;
    state::private_dir(path.parent().context("UNSAFE_STATE")?)?;
    if path.try_exists()? {
        let existing: Value = serde_json::from_slice(&read_private(&path, 16 * 1024 * 1024)?)?;
        ensure!(
            existing["originalCacheSha256"] == proof["originalCacheSha256"]
                && existing["method"] == proof["method"],
            "MANAGED_WORK_CHANGED"
        );
    } else {
        let temporary = path
            .parent()
            .unwrap()
            .join(format!(".operation-canonical-{}", uuid::Uuid::new_v4()));
        immutable_json(&temporary, &proof)?;
        ensure!(
            matches!(std::fs::symlink_metadata(&path),Err(error) if error.kind()==std::io::ErrorKind::NotFound),
            "MANAGED_WORK_CHANGED"
        );
        std::fs::rename(temporary, &path)?;
        File::open(path.parent().unwrap())?.sync_all()?;
    }
    let receipt = operation_receipt(context, request)?;
    ensure!(
        receipt["state"] == "completed",
        "MANAGED_WORK_RECEIPT_MISMATCH"
    );
    Ok(receipt)
}

fn operation_receipt(context: &WorkContext, request: &Value) -> Result<Value> {
    let slot = request["legacySlot"]
        .as_str()
        .context("MANAGED_WORK_CHANGED")?;
    let current = crate::operation_cache::inspect(&context.state_dir)?
        .into_iter()
        .find(|value| value["legacySlot"] == slot)
        .context("MANAGED_WORK_CHANGED")?;
    ensure!(
        current["recordDigest"] == request["recordDigest"],
        "MANAGED_WORK_CHANGED"
    );
    Ok(current["resolution"].clone())
}

/// Publication is private, immutable and crash atomic. The original observation
/// stays untouched until the independently qualified uninstall inventory runs.
fn retire_operation(context: &WorkContext, request: &Value, observation: &Value) -> Result<Value> {
    if generation_context(context) {
        current_context_owner(context)?;
    }
    ensure!(
        context.action == "retire-local" && context.retirement_scope == "operation-observations",
        "INVALID_REQUEST"
    );
    let relative = request["path"].as_str().context("MANAGED_WORK_CHANGED")?;
    let bytes = crate::operation_cache::read(&context.state_dir, relative)?;
    ensure!(
        request["recordDigest"] == state::digest(&bytes),
        "MANAGED_WORK_CHANGED"
    );
    if crate::operation_cache::verify_record_retired(&context.state_dir, relative, &bytes)? {
        let slot = request["legacySlot"]
            .as_str()
            .context("MANAGED_WORK_CHANGED")?;
        let evidence: Value = serde_json::from_slice(&crate::operation_cache::read(
            &context.state_dir,
            &crate::operation_cache::retirement_relative(slot)?,
        )?)?;
        let provenance = &evidence["provenance"];
        ensure!(
            provenance["operationId"] == context.operation_id.to_string()
                && provenance["attemptId"] == context.attempt_id.to_string()
                && provenance["journalSha256"] == context.journal_sha256
                && provenance["receiptSha256"] == context.receipt_sha256
                && provenance["expectedAssessmentSha256"].as_str()
                    == context.expected_assessment_sha256.as_deref()
                && provenance["installationId"] == context.expected_identity.installation_id,
            "MANAGED_WORK_CHANGED"
        );
        return operation_receipt(context, request);
    }
    ensure!(
        request["retirementEligible"] == true,
        "MANAGED_WORK_RECONCILIATION_UNSUPPORTED"
    );
    let slot = request["legacySlot"]
        .as_str()
        .context("MANAGED_WORK_CHANGED")?;
    let request_path = context.state_dir.join(format!(
        "uninstall-work-requests-{}.json",
        context.attempt_id
    ));
    let context_path = context.state_dir.join(format!(
        "uninstall-work-context-{}.json",
        context.attempt_id
    ));
    let provenance = json!({"operationId":context.operation_id,"attemptId":context.attempt_id,"journalSha256":context.journal_sha256,"receiptSha256":context.receipt_sha256,"expectedAssessmentSha256":context.expected_assessment_sha256,"requestSetSha256":state::digest(&read_private(&request_path,16*1024*1024)?),"contextSha256":state::digest(&read_private(&context_path,262144)?),"installationId":context.expected_identity.installation_id,"retirementScope":context.retirement_scope,"canonicalObservation":observation});
    let evidence = crate::operation_cache::retirement_evidence(slot, &bytes, &provenance)?;
    let path = context
        .state_dir
        .join(crate::operation_cache::retirement_relative(slot)?);
    let parent = path.parent().context("UNSAFE_STATE")?;
    state::private_dir(parent)?;
    let temporary = parent.join(format!(
        ".operation-cache-publication-{}",
        uuid::Uuid::new_v4()
    ));
    immutable_json(&temporary, &evidence)?;
    // The lifecycle and inherited daemon singleton serialize all supported
    // publishers. Rename publishes a fully synced inode without a two-link
    // crash window; a preexisting immutable record is never replaced.
    ensure!(
        matches!(std::fs::symlink_metadata(&path),Err(error) if error.kind()==std::io::ErrorKind::NotFound),
        "MANAGED_WORK_CHANGED"
    );
    std::fs::rename(&temporary, &path)?;
    File::open(parent)?.sync_all()?;
    ensure!(
        crate::operation_cache::verify_record_retired(&context.state_dir, relative, &bytes)?,
        "MANAGED_WORK_CHANGED"
    );
    operation_receipt(context, request)
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
    validate_record_binding(context, &value)?;
    let candidate = values
        .iter()
        .find(|candidate| {
            candidate["kind"] == request["kind"]
                && candidate["organizationId"] == request["organizationId"]
                && candidate["accountSubject"] == request["accountSubject"]
                && candidate["installationId"] == request["installationId"]
                && candidate["recordId"] == request["recordId"]
                && (request["kind"] != "operation_cache"
                    || candidate["legacySlot"] == request["legacySlot"])
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
    let operation_observation = request["kind"] == "operation_cache"
        && context.action == "reconcile"
        && candidate["recordDigest"] == request["recordDigest"]
        && value["receipt"]["remoteOutcome"] == "unknown";
    ensure!(
        operation_observation
            || candidate["resolution"] == value["receipt"]
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
    if generation_context(context) {
        current_context_owner(context)?;
    }
    verify_current_domain(presentation, request)?;
    settle_cache(context, index, request, receipt)?;
    apply(&None, presentation, request, Some(receipt))
}
async fn execute(context: &WorkContext, lock: &Arc<File>) -> Result<Value> {
    let api = Api::from_installation_origin(context.api_origin.as_deref())?;
    let auth = Auth::new(api.clone())?;
    auth.retain_store_owner(lock);
    execute_with_services(context, lock, &api, &auth).await
}
async fn execute_with_services(
    context: &WorkContext,
    lock: &Arc<File>,
    api: &Api,
    auth: &Auth,
) -> Result<Value> {
    if generation_context(context) {
        current_context_owner(context)?;
    }
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
    authorize_transition(context, auth, lock).await?;
    if context.action == "retire-local" && context.retirement_scope == "operation-observations" {
        auth.maintenance_observation_quiescent().await?;
    }
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
    enrich_candidates(context, &mut values)?;
    if generation_context(context) {
        current_context_owner(context)?;
    }
    let requests = scoped_requests(context, &values)?;
    for candidate in &requests {
        if candidate["kind"] == "operation_cache" && candidate["binding"].is_null() {
            // Legacy slots retain no canonical account/request binding. The
            // reviewed retirement scope closes only local tracking.
            continue;
        }
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
        candidate_set_digest(&values)
            == candidate_set_digest(&current_candidates(context, &follow, &presentation)?),
        "MANAGED_WORK_CHANGED"
    );
    let mut receipts = Vec::new();
    let mut domain_pending = false;
    for (index, request) in requests.iter().enumerate() {
        if generation_context(context) {
            current_context_owner(context)?;
        }
        if let Some(receipt) = settled(context, index, request, &values)? {
            receipts.push(receipt);
            continue;
        }
        let receipt = if request["kind"] == "operation_cache" {
            let observation = domain_reconciliation::read_operation(
                api,
                auth,
                request,
                &context.expected_identity,
            )
            .await?;
            if matches!(
                observation["remoteOutcome"].as_str(),
                Some("terminal" | "completed")
            ) {
                settle_operation_observation(context, request, &observation)?
            } else if context.action == "retire-local" {
                retire_operation(context, request, &observation)?
            } else {
                // The observation describes canonical authority only. Keeping
                // original bytes makes historical cached queued data immutable.
                observation
            }
        } else if context.action == "reconcile" {
            if request["kind"] == "presentation_operation" {
                let observation =
                    if let Some(transition) = frozen_cache_transition(context, index, request)? {
                        transition["canonicalReceipt"].clone()
                    } else {
                        match domain_reconciliation::read(
                            api,
                            auth,
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
                let observation = read_run(api, auth, request, &context.expected_identity).await?;
                if generation_context(context) {
                    current_context_owner(context)?;
                }
                apply(&follow, &presentation, request, Some(&observation))?
            }
        } else {
            ensure!(context.action == "retire-local", "INVALID_REQUEST");
            if generation_context(context) {
                current_context_owner(context)?;
            }
            apply(&follow, &presentation, request, None)?
        };
        record_settlement(context, index, request, &receipt)?;
        receipts.push(receipt);
    }
    drop(follow);
    drop(presentation);
    ensure!(!domain_pending, "MANAGED_DOMAIN_OUTCOME_PENDING");
    Ok(json!({"actionCompleted":true,"resolvedRecords":receipts.len(),"receipts":receipts}))
}

pub async fn run(path: &Path) -> Result<Value> {
    let context_bytes = read_private(path, 262144)?;
    let mut context: WorkContext = serde_json::from_slice(&context_bytes)?;
    context.context_sha256 = state::digest(&context_bytes);
    ensure!(
        matches!(
            context.schema.as_str(),
            "app.loomex.runner.uninstall-work-context/v1"
                | "app.loomex.runner.uninstall-work-context/v2"
        ) && matches!(context.action.as_str(), "reconcile" | "retire-local")
            && matches!(
                context.retirement_scope.as_str(),
                "continuations" | "operation-observations"
            ),
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
        16 * 1024 * 1024,
    )?)?;
    validate_context_owner(&context, &owner, &context.context_sha256)?;
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
            && (!generation_context(&context)
                || operation.schema == crate::lifecycle::GENERATION_UNINSTALL_WORK_SCHEMA)
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
    current_context_owner(&context)?;
    let result = execute(&context, &lock).await;
    current_context_owner(&context)?;
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
    let mut report = bind_record(&context, report);
    if generation_context(&context) {
        report["schema"] = json!("app.loomex.runner.uninstall-work-result/v2");
    }
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
            maintenance_generation: None,
            release_manifest_sha256: None,
            context_sha256: String::new(),
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
            retirement_scope: default_retirement_scope(),
            expected_identity: crate::auth::CredentialIdentity {
                installation_id: Uuid::new_v4().to_string(),
                device_id: None,
            },
            api_origin: None,
            singleton_fd: 7,
            authorize_keychain_transition: false,
        }
    }
    #[test]
    fn child_generation_context_rejects_stale_owner_and_exact_binding_changes() {
        let temp = tempfile::tempdir().unwrap();
        let mut ctx = context(temp.path(), "reconcile");
        ctx.schema = "app.loomex.runner.uninstall-work-context/v2".into();
        ctx.maintenance_generation = Some(2);
        ctx.release_manifest_sha256 = Some("d".repeat(64));
        ctx.context_sha256 = "e".repeat(64);
        let owner = json!({"schema":"app.loomex.runner.uninstall-work/v2","operationId":ctx.operation_id,"journalSha256":ctx.journal_sha256,"currentGeneration":2,"releasePath":"/fixture/release","releaseManifestSha256":ctx.release_manifest_sha256,"generations":[{"generation":1,"releasePath":"/fixture/old","releaseManifestSha256":"f".repeat(64)},{"generation":2,"releasePath":"/fixture/release","releaseManifestSha256":ctx.release_manifest_sha256}],"attempt":{"id":ctx.attempt_id,"state":"spawn_pending","contextSha256":ctx.context_sha256,"maintenanceGeneration":2,"releaseManifestSha256":ctx.release_manifest_sha256}});
        validate_context_owner(&ctx, &owner, &ctx.context_sha256).unwrap();
        for pointer in [
            "/currentGeneration",
            "/attempt/maintenanceGeneration",
            "/attempt/state",
            "/attempt/contextSha256",
            "/attempt/releaseManifestSha256",
            "/releaseManifestSha256",
            "/generations/1/releaseManifestSha256",
            "/generations/1/releasePath",
            "/attempt/id",
            "/operationId",
        ] {
            let mut changed = owner.clone();
            *changed.pointer_mut(pointer).unwrap() = json!("changed");
            assert!(
                validate_context_owner(&ctx, &changed, &ctx.context_sha256).is_err(),
                "{pointer}"
            );
        }
        assert!(validate_context_owner(&ctx, &owner, &"f".repeat(64)).is_err());
        let mut duplicate = owner.clone();
        duplicate["generations"]
            .as_array_mut()
            .unwrap()
            .push(owner["generations"][1].clone());
        assert!(validate_context_owner(&ctx, &duplicate, &ctx.context_sha256).is_err());
    }

    #[test]
    fn late_child_cannot_publish_checkpoint_after_generation_changes() {
        let temp = tempfile::tempdir().unwrap();
        let mut ctx = context(temp.path(), "reconcile");
        ctx.schema = "app.loomex.runner.uninstall-work-context/v2".into();
        ctx.maintenance_generation = Some(2);
        ctx.release_manifest_sha256 = Some("d".repeat(64));
        let context_bytes = b"immutable exact context snapshot";
        ctx.context_sha256 = state::digest(context_bytes);
        let context_path = ctx
            .state_dir
            .join(format!("uninstall-work-context-{}.json", ctx.attempt_id));
        state::atomic_write(&context_path, context_bytes).unwrap();
        let mut owner = json!({"schema":"app.loomex.runner.uninstall-work/v2","operationId":ctx.operation_id,"journalSha256":ctx.journal_sha256,"currentGeneration":2,"releasePath":"/fixture/release","releaseManifestSha256":ctx.release_manifest_sha256,"generations":[{"generation":2,"releasePath":"/fixture/release","releaseManifestSha256":ctx.release_manifest_sha256}],"attempt":{"id":ctx.attempt_id,"state":"spawn_pending","contextSha256":ctx.context_sha256,"maintenanceGeneration":2,"releaseManifestSha256":ctx.release_manifest_sha256}});
        let owner_path = ctx.state_dir.join("uninstall-work.json");
        state::write_json(&owner_path, &owner).unwrap();
        current_context_owner(&ctx).unwrap();
        owner["currentGeneration"] = json!(3);
        state::write_json(&owner_path, &owner).unwrap();
        let before = std::fs::read(&owner_path).unwrap();
        assert!(
            record_settlement(
                &ctx,
                0,
                &json!({"idempotencyKey":Uuid::new_v4()}),
                &json!({"remoteOutcome":"terminal"})
            )
            .is_err()
        );
        assert!(
            !ctx.state_dir
                .join(format!(
                    "uninstall-work-checkpoint-{}-0.json",
                    ctx.attempt_id
                ))
                .exists()
        );
        assert_eq!(std::fs::read(&owner_path).unwrap(), before);
        owner["currentGeneration"] = json!(2);
        state::write_json(&owner_path, &owner).unwrap();
        state::atomic_write(&context_path, b"replacement context").unwrap();
        assert!(current_context_owner(&ctx).is_err());
    }

    #[test]
    fn reserved_generation_context_cannot_run_or_publish_even_when_file_exists() {
        let temp = tempfile::tempdir().unwrap();
        let mut ctx = context(temp.path(), "reconcile");
        ctx.schema = "app.loomex.runner.uninstall-work-context/v2".into();
        ctx.maintenance_generation = Some(2);
        ctx.release_manifest_sha256 = Some("d".repeat(64));
        let context_bytes = b"reserved immutable context snapshot";
        ctx.context_sha256 = state::digest(context_bytes);
        let context_path = ctx
            .state_dir
            .join(format!("uninstall-work-context-{}.json", ctx.attempt_id));
        state::atomic_write(&context_path, context_bytes).unwrap();
        let mut owner = json!({"schema":"app.loomex.runner.uninstall-work/v2","operationId":ctx.operation_id,"journalSha256":ctx.journal_sha256,"currentGeneration":2,"releasePath":"/fixture/release","releaseManifestSha256":ctx.release_manifest_sha256,"generations":[{"generation":2,"releasePath":"/fixture/release","releaseManifestSha256":ctx.release_manifest_sha256}],"attempt":{"id":ctx.attempt_id,"state":"context_pending","pendingContext":String::from_utf8_lossy(context_bytes),"contextSha256":ctx.context_sha256,"maintenanceGeneration":2,"releaseManifestSha256":ctx.release_manifest_sha256}});
        let owner_path = ctx.state_dir.join("uninstall-work.json");
        state::write_json(&owner_path, &owner).unwrap();
        let before = std::fs::read(&owner_path).unwrap();
        assert!(current_context_owner(&ctx).is_err());
        assert!(
            record_settlement(
                &ctx,
                0,
                &json!({"idempotencyKey":Uuid::new_v4()}),
                &json!({"remoteOutcome":"terminal"})
            )
            .is_err()
        );
        assert!(
            !ctx.state_dir
                .join(format!(
                    "uninstall-work-checkpoint-{}-0.json",
                    ctx.attempt_id
                ))
                .exists()
        );
        assert!(!result_path(&ctx).exists());
        assert_eq!(std::fs::read(&owner_path).unwrap(), before);
        assert_eq!(std::fs::read(&context_path).unwrap(), context_bytes);
        owner["attempt"]
            .as_object_mut()
            .unwrap()
            .remove("pendingContext");
        for state in ["spawn_pending", "running"] {
            owner["attempt"]["state"] = json!(state);
            state::write_json(&owner_path, &owner).unwrap();
            current_context_owner(&ctx).unwrap();
        }
        for state in [Value::Null, json!("settled"), json!("context_pending")] {
            owner["attempt"]["state"] = state;
            assert!(validate_context_owner(&ctx, &owner, &ctx.context_sha256).is_err());
        }
        owner["attempt"].as_object_mut().unwrap().remove("state");
        assert!(validate_context_owner(&ctx, &owner, &ctx.context_sha256).is_err());
    }

    #[test]
    fn child_v1_only_resumes_its_exact_historical_owner() {
        let temp = tempfile::tempdir().unwrap();
        let mut ctx = context(temp.path(), "reconcile");
        let mut owner = json!({"schema":"app.loomex.runner.uninstall-work/v1","operationId":ctx.operation_id,"journalSha256":ctx.journal_sha256,"attempt":{"id":ctx.attempt_id,"contextSha256":"e".repeat(64)}});
        validate_context_owner(&ctx, &owner, &"e".repeat(64)).unwrap();
        owner["schema"] = json!("app.loomex.runner.uninstall-work/v2");
        owner["currentGeneration"] = json!(1);
        assert!(validate_context_owner(&ctx, &owner, &"e".repeat(64)).is_err());
        owner["schema"] = json!("app.loomex.runner.uninstall-work/v1");
        ctx.maintenance_generation = Some(1);
        assert!(validate_context_owner(&ctx, &owner, &"e".repeat(64)).is_err());
        ctx.maintenance_generation = None;
        ctx.release_manifest_sha256 = Some("d".repeat(64));
        assert!(validate_context_owner(&ctx, &owner, &"e".repeat(64)).is_err());
    }

    #[test]
    fn child_generation_records_preserve_original_requests_and_reject_late_records() {
        let temp = tempfile::tempdir().unwrap();
        let mut ctx = context(temp.path(), "reconcile");
        let original = json!({"schema":"app.loomex.runner.uninstall-work-requests/v1","operationId":ctx.operation_id,"attemptId":ctx.attempt_id,"retirementScope":"continuations","requests":[{"idempotencyKey":Uuid::new_v4(),"method":"runs.get","operationKey":"original"}]});
        assert_eq!(bind_record(&ctx, original.clone()), original);
        validate_record_binding(&ctx, &original).unwrap();
        ctx.schema = "app.loomex.runner.uninstall-work-context/v2".into();
        ctx.maintenance_generation = Some(2);
        ctx.release_manifest_sha256 = Some("d".repeat(64));
        ctx.context_sha256 = "e".repeat(64);
        let record = bind_record(&ctx, original.clone());
        validate_record_binding(&ctx, &record).unwrap();
        assert_eq!(record["requests"], original["requests"]);
        assert_eq!(record["retirementScope"], original["retirementScope"]);
        for field in [
            "maintenanceGeneration",
            "releaseManifestSha256",
            "contextSha256",
        ] {
            let mut changed = record.clone();
            changed[field] = json!("changed");
            assert!(validate_record_binding(&ctx, &changed).is_err(), "{field}");
        }
        assert!(validate_record_binding(&ctx, &original).is_err());
        ctx.schema = "app.loomex.runner.uninstall-work-context/v1".into();
        assert!(validate_record_binding(&ctx, &record).is_err());
    }

    fn observation(run: &Value) -> Value {
        json!({"snapshot":{"execution":{"id":run,"status":"running"},"events":[],"latestSequence":0,"hasMoreEvents":false}})
    }

    fn seven_operation_fixture(dir: &Path) -> Vec<(String, Vec<u8>)> {
        state::private_dir(&dir.join("operations")).unwrap();
        let slots = [
            (
                "7d5441529b08a9edb67c3d1ae0f6617481371e2152e1c2227365d9806878f071",
                "interactions.respond",
            ),
            (
                "3233cdf38f2730dfd5e334f886f498567616a5b4352045cc5ceb6a77962c295c",
                "interactions.draft.delete",
            ),
            (
                "9e652a558dd62a9f7603ecafac01acad144c16e09a9646066b54996dd10afe04",
                "interactions.respond",
            ),
            ("8f3e5fcd-aacb-4182-9168-c213e47ae91b", "auth.recover"),
            (
                "c5ad9fc9749a7ad2593624943ac2ebe5db24e45975af829d06c0d77410e74849",
                "builder.start",
            ),
            (
                "f76a886f365c51be49b757709a07e3ae982edfa22f8d81e950234753280f22dc",
                "interactions.respond",
            ),
            (
                "a856fed1096a5dd101617d97f4837ac8fdcc3190d0e10d59301feae94c08373a",
                "interactions.respond",
            ),
        ];
        slots.into_iter().map(|(slot, method)| {
            let value = if method == "builder.start" {
                json!({"digest":"a".repeat(64),"method":method,"executionId":"657523ef-0920-4e2c-b1e5-fc8ef5e9b72b","result":{"executionId":"657523ef-0920-4e2c-b1e5-fc8ef5e9b72b","status":"queued"},"cachedAt":1})
            } else {
                json!({"digest":"b".repeat(64),"method":method,"status":"pending"})
            };
            let bytes=serde_json::to_vec_pretty(&value).unwrap();
            state::atomic_write(&dir.join(format!("operations/{slot}.json")),&bytes).unwrap();
            (slot.into(),bytes)
        }).collect()
    }

    #[test]
    fn exact_seven_legacy_observations_require_fresh_explicit_scope_and_keep_original_bytes() {
        let root = tempfile::tempdir().unwrap();
        state::private_dir(root.path()).unwrap();
        let originals = seven_operation_fixture(root.path());
        let assessment = crate::uninstall_state::assess_state(root.path()).unwrap();
        assert!(!assessment.resolved);
        assert_eq!(assessment.blockers.len(), 1);
        assert_eq!(
            assessment.blockers[0].category,
            crate::uninstall_state::BlockerCategory::OperationCache
        );
        assert_eq!(assessment.blockers[0].count, 7);
        assert!(crate::uninstall_state::inventory_resolved_state(root.path()).is_err());
        let values = crate::uninstall_state::maintenance_preview(root.path()).unwrap();
        assert_eq!(values.len(), 7);
        assert!(
            values
                .iter()
                .all(|value| value["retirementEligible"] == true)
        );
        for value in &values {
            let (reason, reconciliation_supported) = match value["method"].as_str().unwrap() {
                "interactions.respond" | "interactions.draft.delete" => ("missing_binding", false),
                "auth.recover" => ("unsupported_family", false),
                "builder.start" => ("terminal_missing", true),
                method => panic!("unexpected fixture method {method}"),
            };
            assert_eq!(value["safeReason"], reason, "{}", value["method"]);
            assert_eq!(
                value["reconciliationSupported"], reconciliation_supported,
                "{}",
                value["method"]
            );
        }
        let default = context(root.path(), "retire-local");
        assert!(
            scoped_requests(&default, &values).unwrap().is_empty(),
            "legacy default scope never selects cache observations"
        );
        let mut retire = context(root.path(), "retire-local");
        retire.retirement_scope = "operation-observations".into();
        retire.expected_assessment_sha256 = Some(assessment.assessment_digest.clone());
        state::write_json(
            &root
                .path()
                .join(format!("uninstall-work-context-{}.json", retire.attempt_id)),
            &json!({"fixture":"sealed-context"}),
        )
        .unwrap();
        let requests = scoped_requests(&retire, &values).unwrap();
        assert_eq!(requests.len(), 7);
        let observation = json!({"remoteOutcome":"unknown","safeReason":"missing_binding"});
        // A crash after evidence publication and before the observer checkpoint
        // resumes the same selected bytes and never changes a pending result.
        let first = retire_operation(&retire, &requests[0], &observation).unwrap();
        assert_eq!(first["state"], "local_observation_retired");
        assert_eq!(
            retire_operation(&retire, &requests[0], &observation).unwrap(),
            first
        );
        for (index, request) in requests.iter().enumerate() {
            let receipt = retire_operation(&retire, request, &observation).unwrap();
            assert_eq!(receipt["state"], "local_observation_retired");
            record_settlement(&retire, index, request, &receipt).unwrap();
        }
        let current = crate::uninstall_state::maintenance_preview(root.path()).unwrap();
        assert_eq!(scoped_requests(&retire, &current).unwrap(), requests);
        for (index, request) in requests.iter().enumerate() {
            assert!(
                settled(&retire, index, request, &current)
                    .unwrap()
                    .is_some()
            );
        }
        for (slot, bytes) in originals {
            assert_eq!(
                std::fs::read(root.path().join(format!("operations/{slot}.json"))).unwrap(),
                bytes
            );
            assert_eq!(
                crate::operation_cache::deny_retired_slot(root.path(), &slot)
                    .unwrap_err()
                    .to_string(),
                "OPERATION_CACHE_RETIRED"
            );
        }
        let after = crate::uninstall_state::assess_state(root.path()).unwrap();
        assert!(after.resolved);
        assert_ne!(
            assessment.assessment_digest, after.assessment_digest,
            "retirement evidence invalidates an earlier review"
        );
        let inventory = crate::uninstall_state::inventory_resolved_state(root.path()).unwrap();
        assert_eq!(
            inventory
                .iter()
                .filter(|path| path.parent() == Some(&root.path().join("operations")))
                .count(),
            7
        );
        assert!(
            inventory
                .iter()
                .all(|path| !path.starts_with(root.path().join("recovery-evidence")))
        );
    }

    #[test]
    fn native_queued_cache_requires_exact_receipt_and_complete_terminal_observation() {
        let root = tempfile::tempdir().unwrap();
        state::private_dir(root.path()).unwrap();
        state::private_dir(&root.path().join("operations")).unwrap();
        let ctx = context(root.path(), "reconcile");
        let slot = "c5ad9fc9749a7ad2593624943ac2ebe5db24e45975af829d06c0d77410e74849";
        let run = "657523ef-0920-4e2c-b1e5-fc8ef5e9b72b";
        let session = Uuid::new_v4();
        let queued = json!({"schemaVersion":"loomex.native-authoring-session/v1","sessionId":session,"builderSessionId":session,"executionId":run,"status":"queued","systemWorkflowKey":"workflow_builder","systemWorkflowVersionId":Uuid::new_v4(),"systemWorkflowDefinitionChecksum":"d".repeat(64),"nextAction":"run_get"});
        let original=serde_json::to_vec_pretty(&json!({"method":"builder.start","digest":"a".repeat(64),"result":queued,"executionId":run,"cachedAt":1})).unwrap();
        let path = root.path().join(format!("operations/{slot}.json"));
        state::atomic_write(&path, &original).unwrap();
        let request = crate::uninstall_state::maintenance_preview(root.path())
            .unwrap()
            .remove(0);
        assert_eq!(request["cleanupEligible"], false);
        let receipt = json!({"operation":"builder.start","status":"completed","match":"exact_request_match","cacheRequestDigest":"a".repeat(64),"provenance":"native_authoring_queued_receipt","result":queued});
        let terminal = json!({"execution":{"id":run,"status":"completed"},"events":[],"hasMoreEvents":false,"latestSequence":12,"result":{"accepted":true}});
        let observed = json!({"remoteOutcome":"terminal","organizationId":"org","accountSubject":"account","installationId":ctx.expected_identity.installation_id,"canonicalReceipt":receipt,"observation":{"snapshot":terminal,"terminalResult":terminal}});
        let mut incomplete = observed.clone();
        incomplete["observation"]["terminalResult"]["hasMoreEvents"] = json!(true);
        assert!(settle_operation_observation(&ctx, &request, &incomplete).is_err());
        let proof = root.path().join(format!(
            "recovery-evidence/operation-canonical-{}.json",
            state::digest(slot.as_bytes())
        ));
        assert!(!proof.exists());
        let mut wrong = observed.clone();
        wrong["canonicalReceipt"]["match"] = json!("same_key_only");
        assert!(settle_operation_observation(&ctx, &request, &wrong).is_err());
        assert!(!proof.exists());
        let result = settle_operation_observation(&ctx, &request, &observed).unwrap();
        assert_eq!(result["state"], "completed");
        assert!(
            crate::uninstall_state::assess_state(root.path())
                .unwrap()
                .resolved
        );
        assert_eq!(
            std::fs::read(path).unwrap(),
            original,
            "queued historical receipt remains byte identical"
        );
        assert!(
            crate::operation_cache::deny_retired_slot(root.path(), slot).is_ok(),
            "canonical terminal observation never invents local retirement"
        );
    }

    #[test]
    fn interrupted_private_evidence_never_grants_cleanup_and_protected_auth_stays_pending() {
        let root = tempfile::tempdir().unwrap();
        state::private_dir(root.path()).unwrap();
        let originals = seven_operation_fixture(root.path());
        let mut retire = context(root.path(), "retire-local");
        retire.retirement_scope = "operation-observations".into();
        retire.expected_assessment_sha256 = Some(
            crate::uninstall_state::assess_state(root.path())
                .unwrap()
                .assessment_digest,
        );
        state::write_json(
            &root
                .path()
                .join(format!("uninstall-work-context-{}.json", retire.attempt_id)),
            &json!({"fixture":"sealed-context"}),
        )
        .unwrap();
        let values = crate::uninstall_state::maintenance_preview(root.path()).unwrap();
        let requests = scoped_requests(&retire, &values).unwrap();
        state::private_dir(&root.path().join("recovery-evidence")).unwrap();
        // A pre-publication partial file has no canonical retirement filename.
        state::atomic_write(
            &root
                .path()
                .join("recovery-evidence/.operation-cache-publication-interrupted"),
            b"{",
        )
        .unwrap();
        assert!(
            !crate::uninstall_state::assess_state(root.path())
                .unwrap()
                .resolved
        );
        assert!(crate::uninstall_state::inventory_resolved_state(root.path()).is_err());
        state::write_json(
            &root.path().join("auth-pending.json"),
            &json!({"schema":"loomex.auth-pending/v1","status":"pending","private":"untouched"}),
        )
        .unwrap();
        let protected = std::fs::read(root.path().join("auth-pending.json")).unwrap();
        let observation = json!({"remoteOutcome":"unknown","safeReason":"missing_binding"});
        for request in &requests {
            retire_operation(&retire, request, &observation).unwrap();
        }
        assert_eq!(
            std::fs::read(root.path().join("auth-pending.json")).unwrap(),
            protected
        );
        for (slot, bytes) in originals {
            assert_eq!(
                std::fs::read(root.path().join(format!("operations/{slot}.json"))).unwrap(),
                bytes
            );
        }
        // Unknown canonical evidence fails closed even if the source is known.
        let relative = crate::operation_cache::retirement_relative(
            requests[0]["legacySlot"].as_str().unwrap(),
        )
        .unwrap();
        state::atomic_write(&root.path().join(relative), b"{").unwrap();
        assert!(
            !crate::uninstall_state::assess_state(root.path())
                .unwrap()
                .resolved
        );
        assert!(crate::uninstall_state::inventory_resolved_state(root.path()).is_err());
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
        domain_fixture_for(dir, "org-a", "user-a")
    }
    fn domain_fixture_for(
        dir: &Path,
        org: &str,
        account: &str,
    ) -> (Option<PresentationStore>, Value) {
        let store = PresentationStore::open(dir).unwrap();
        let session=store.dispatch(org,account,"presentation.sessions.create",&json!({"kind":"monitor","entityType":"execution","entityId":Uuid::new_v4(),"state":{},"idempotencyKey":Uuid::new_v4()})).unwrap();
        let key = Uuid::new_v4();
        let params = json!({"workflowId":Uuid::new_v4(),"expectedVersion":2,"notes":"PRIVATE_DOMAIN_ARGUMENT","idempotencyKey":key});
        store.dispatch(org,account,"presentation.sessions.update",&json!({"viewSessionId":session["viewSessionId"],"expectedRevision":0,"state":{},"operation":{"method":"workflows.publish","params":params,"idempotencyKey":key,"reconciliation":{"method":"workflow.operations.get","params":{"operation":"workflows.publish","idempotencyKey":key}}},"idempotencyKey":Uuid::new_v4()})).unwrap();
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
    async fn actual_execute_joins_legacy_owner_and_preserves_versioned_pending_on_read_and_retry() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        for versioned in [false, true] {
            let root = tempfile::tempdir().unwrap();
            state::private_dir(root.path()).unwrap();
            let org = Uuid::new_v4().to_string();
            let account = Uuid::new_v4().to_string();
            let server = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let api =
                Api::for_test_origin(&format!("http://{}", server.local_addr().unwrap())).unwrap();
            let auth = Auth::test_enrolled(api.clone(), &org, &account);
            let mut ctx = context(root.path(), "reconcile");
            ctx.expected_identity = auth.maintenance_identity().await.unwrap().unwrap();
            let (presentation, candidate) = domain_fixture_for(root.path(), &org, &account);
            let (relative, digest) = control::maintenance_cache_identity(&candidate).unwrap();
            if versioned {
                let binding = crate::operation_cache::binding(
                    "workflows.publish",
                    candidate["operationKey"].as_str().unwrap(),
                    &digest,
                    &json!({}),
                    &candidate["params"],
                    crate::operation_cache::BindingOrigin {
                        organization: Some(&org),
                        account: Some(&account),
                        installation: &ctx.expected_identity.installation_id,
                        control_reference: None,
                    },
                );
                state::write_json(
                    &root.path().join(&relative),
                    &crate::operation_cache::pending(&digest, "workflows.publish", binding),
                )
                .unwrap();
            }
            let original = std::fs::read(root.path().join(&relative)).unwrap();
            let response = domain_receipt(&candidate);
            let response_copy = response.clone();
            let read = tokio::spawn(async move {
                let (mut socket, _) = server.accept().await.unwrap();
                let mut bytes = Vec::new();
                loop {
                    let mut buffer = [0u8; 4096];
                    let size = socket.read(&mut buffer).await.unwrap();
                    assert!(size > 0);
                    bytes.extend_from_slice(&buffer[..size]);
                    if let Some(end) = bytes.windows(4).position(|value| value == b"\r\n\r\n") {
                        let header = String::from_utf8_lossy(&bytes[..end]);
                        let length = header
                            .lines()
                            .find_map(|line| {
                                line.to_ascii_lowercase()
                                    .strip_prefix("content-length:")
                                    .and_then(|value| value.trim().parse::<usize>().ok())
                            })
                            .unwrap_or(0);
                        if bytes.len() >= end + 4 + length {
                            break;
                        }
                    }
                }
                let request = String::from_utf8(bytes).unwrap();
                assert!(
                    request
                        .lines()
                        .next()
                        .unwrap()
                        .contains("/v2/workflow-operations/get/")
                );
                assert!(!request.contains("PRIVATE_DOMAIN_ARGUMENT"));
                let body = serde_json::to_vec(&json!({"data":response_copy,"meta":{}})).unwrap();
                let header = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                socket.write_all(header.as_bytes()).await.unwrap();
                socket.write_all(&body).await.unwrap();
            });
            drop(presentation);
            let lock = Arc::new(acquire_singleton(root.path()).unwrap());
            let result = execute_with_services(&ctx, &lock, &api, &auth)
                .await
                .unwrap();
            read.await.unwrap();
            assert_eq!(result["actionCompleted"], true);
            let after = std::fs::read(root.path().join(&relative)).unwrap();
            if versioned {
                assert_eq!(
                    after, original,
                    "versioned binding and stage cannot be rewritten by legacy owner settlement"
                );
            } else {
                assert_eq!(
                    serde_json::from_slice::<Value>(&after).unwrap()["result"],
                    response["response"]
                );
            }
            let replay = execute_with_services(&ctx, &lock, &api, &auth)
                .await
                .unwrap();
            assert_eq!(
                result, replay,
                "the exact frozen operation and dependency transition resume without a second read or replacement key"
            );
            assert_eq!(std::fs::read(root.path().join(&relative)).unwrap(), after);
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
    fn immutable_work_publication_ignores_partial_temporary_and_preserves_first_complete_bytes() {
        let root = tempfile::tempdir().unwrap();
        state::private_dir(root.path()).unwrap();
        let partial = root.path().join(".uninstall-work-publication-interrupted");
        state::atomic_write(&partial, b"{\"schema\":").unwrap();
        let path = root.path().join("uninstall-work-requests-fixture.json");
        let expected = json!({"schema":"fixture","requests":[{"recordDigest":"a".repeat(64)}]});
        immutable_json(&path, &expected).unwrap();
        let original = read_private(&path, 1024).unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&original).unwrap(),
            expected
        );
        immutable_json(&path, &expected).unwrap();
        assert!(immutable_json(&path, &json!({"schema":"replacement"})).is_err());
        assert_eq!(read_private(&path, 1024).unwrap(), original);
        assert_eq!(std::fs::read(partial).unwrap(), b"{\"schema\":");
        let linked = root.path().join("uninstall-work-requests-symlink.json");
        std::os::unix::fs::symlink(root.path().join("missing"), &linked).unwrap();
        assert!(immutable_json(&linked, &expected).is_err());
        assert!(
            std::fs::symlink_metadata(linked)
                .unwrap()
                .file_type()
                .is_symlink()
        );
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
        let mut different_scope = context(root.path(), "retire-local");
        different_scope.operation_id = ctx.operation_id;
        different_scope.attempt_id = ctx.attempt_id;
        different_scope.retirement_scope = "operation-observations".into();
        assert!(
            scoped_requests(&different_scope, &values).is_err(),
            "an immutable reviewed attempt cannot change its retirement scope"
        );
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
