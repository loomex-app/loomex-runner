use super::*;

pub(super) async fn require_execution_authorization(
    daemon: &Daemon,
    journal: &Journal,
) -> Result<PathBuf> {
    require_execution_authorization_with(daemon, journal, provider_snapshot).await
}

pub(super) async fn require_execution_authorization_with(
    daemon: &Daemon,
    journal: &Journal,
    snapshot: impl FnOnce() -> Result<Value>,
) -> Result<PathBuf> {
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
    if record["providers"] != snapshot()? {
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
pub(super) fn verify_payload_digest(job: &Value) -> Result<()> {
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

/// A leased payload cannot reach an adapter without the bound local authority.
pub(super) struct AuthorizedJob {
    payload: Value,
    workspace: PathBuf,
}
impl AuthorizedJob {
    pub(super) fn payload(&self) -> &Value {
        &self.payload
    }
    pub(super) fn workspace(&self) -> &Path {
        &self.workspace
    }
}
pub(super) async fn authorize(daemon: &Daemon, journal: &Journal) -> Result<AuthorizedJob> {
    validate_job_kind(journal.job["kind"].as_str().unwrap_or(""))?;
    verify_payload_digest(&journal.job)?;
    let workspace = require_execution_authorization(daemon, journal).await?;
    let payload = &journal.job["payload"];
    if journal.job["kind"] == "http.request" {
        http_request(payload)?;
    } else {
        let argv = payload["command"]
            .as_array()
            .context("INVALID_COMMAND")?
            .iter()
            .map(|item| item.as_str().map(str::to_owned).context("INVALID_COMMAND"))
            .collect::<Result<Vec<_>>>()?;
        if argv.is_empty() {
            bail!("INVALID_COMMAND");
        }
        if payload.get("provider").is_some() {
            validate_provider_input(payload, &argv)?;
        } else if provider_contract_fields(payload) {
            bail!("PROVIDER_ADAPTER_INVALID");
        }
    }
    Ok(AuthorizedJob {
        payload: journal.job["payload"].clone(),
        workspace,
    })
}
