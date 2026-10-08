use super::*;

#[cfg(test)]
pub(super) async fn require_execution_authorization(
    daemon: &Daemon,
    journal: &Journal,
) -> Result<PathBuf> {
    let providers = daemon.provider_snapshot().await?;
    require_execution_authorization_with(daemon, journal, || Ok(providers)).await
}

#[cfg(test)]
pub(super) async fn require_execution_authorization_with(
    daemon: &Daemon,
    journal: &Journal,
    snapshot: impl FnOnce() -> Result<Value>,
) -> Result<PathBuf> {
    Ok(read_execution_authority(daemon, journal, snapshot()?)
        .await?
        .workspace)
}

struct LocalAuthority {
    workspace: PathBuf,
    extras: Vec<PathBuf>,
    record: Value,
    identity: (String, String),
}

async fn current_job_identity(daemon: &Daemon, organization: &str) -> Result<(String, String)> {
    // Keep the existing proof-journaled refresh/reconciliation path. A local
    // identity read alone must not reject a refreshable enrolled child.
    let credential = daemon.auth.credential(organization).await?;
    let identity = daemon.auth.current_child_identity(organization).await?;
    anyhow::ensure!(
        identity.0 == credential.subject,
        "LOCAL_EXECUTION_AUTHORIZATION_REQUIRED"
    );
    Ok(identity)
}

async fn read_execution_authority(
    daemon: &Daemon,
    journal: &Journal,
    providers: Value,
) -> Result<LocalAuthority> {
    let identity = current_job_identity(daemon, &journal.organization).await?;
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
        || record["installationId"] != identity.1
        || (record.get("accountSubject").is_some() && record["accountSubject"] != identity.0)
        || record["workspacePath"] != payload["workspacePath"]
        || !crate::workspace_set::same_set(binding, payload)
        || binding["executionPolicy"] != "host_user/v1"
        || payload["executionPolicy"] != "host_user/v1"
        || !payload["providerConfiguration"].is_object()
        || payload["providerConfiguration"] != binding["providerConfiguration"]
    {
        bail!("LOCAL_EXECUTION_AUTHORIZATION_REQUIRED")
    }
    if record["providers"] != providers {
        bail!("PROVIDER_CONFIGURATION_CHANGED")
    }
    // The refresh/reconciliation above is complete before projecting ANY local
    // authority facts. Grant/canonical path validation uses that verified local
    // installation; it does not introduce another refresh-capable auth await.
    let mut workspace_binding = binding.clone();
    workspace_binding["workspacePath"] = payload["workspacePath"].clone();
    let identities = crate::workspace_set::require_set(
        &*daemon.public.lock().await,
        &workspace_binding,
        &journal.organization,
        &identity.1,
    )?;
    if let Some(expected) = record.get("workspaceIdentities") {
        anyhow::ensure!(&identities == expected, "WORKSPACE_DENIED");
    }
    if binding.get("workspaceSetContract").is_some() {
        anyhow::ensure!(
            binding["workspaceIdentities"] == identities,
            "WORKSPACE_DENIED"
        );
    }
    // Reject an unbound output root before any command or provider can launch.
    if let Some(declarations) = payload["artifactOutputs"].as_array() {
        for declaration in declarations {
            crate::workspace_set::artifact_root(payload, declaration)?;
        }
    }
    let workspace = PathBuf::from(identities[0]["path"].as_str().context("WORKSPACE_DENIED")?);
    let extras = crate::workspace_set::bound_extras(payload)?;
    // Waiting for the grant projection can yield. The same preparation must
    // still be the actual committed record when this complete projection exits.
    let fresh_record: Value = state::read_json(
        &daemon
            .dir
            .join("preparations")
            .join(format!("{preparation}.json")),
    )
    .map_err(|_| anyhow::anyhow!("LOCAL_EXECUTION_AUTHORIZATION_REQUIRED"))?;
    anyhow::ensure!(
        fresh_record == record,
        "LOCAL_EXECUTION_AUTHORIZATION_REQUIRED"
    );
    Ok(LocalAuthority {
        workspace,
        extras,
        record,
        identity,
    })
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
    authority: LocalAuthority,
    providers: Value,
}
impl AuthorizedJob {
    pub(super) fn payload(&self) -> &Value {
        &self.payload
    }
    pub(super) fn workspace(&self) -> &Path {
        &self.authority.workspace
    }
    pub(super) fn additional_workspaces(&self) -> &[PathBuf] {
        &self.authority.extras
    }
    pub(super) async fn revalidate(&self, daemon: &Daemon, journal: &Journal) -> Result<()> {
        let fresh = read_execution_authority(daemon, journal, self.providers.clone()).await?;
        anyhow::ensure!(
            fresh.record == self.authority.record
                && fresh.identity == self.authority.identity
                && fresh.workspace == self.authority.workspace
                && fresh.extras == self.authority.extras,
            "LOCAL_EXECUTION_AUTHORIZATION_REQUIRED"
        );
        Ok(())
    }
}
pub(super) async fn authorize(daemon: &Daemon, journal: &Journal) -> Result<AuthorizedJob> {
    validate_job_kind(journal.job["kind"].as_str().unwrap_or(""))?;
    verify_payload_digest(&journal.job)?;
    let identity = current_job_identity(daemon, &journal.organization).await?;
    let providers = daemon.provider_snapshot().await?;
    let authority = read_execution_authority(daemon, journal, providers.clone()).await?;
    anyhow::ensure!(
        authority.identity == identity,
        "LOCAL_EXECUTION_AUTHORIZATION_REQUIRED"
    );
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
        authority,
        providers,
    })
}

#[cfg(test)]
mod fingerprint_revalidation_tests {
    use super::*;
    #[tokio::test]
    async fn workspace_set_job_rejects_substitution_and_unbound_artifacts_before_launch() {
        let temp = tempfile::tempdir().unwrap();
        let primary = temp.path().join("a");
        let extra = temp.path().join("b");
        std::fs::create_dir(&primary).unwrap();
        std::fs::create_dir(&extra).unwrap();
        let primary = primary.canonicalize().unwrap();
        let extra = extra.canonicalize().unwrap();
        let api = crate::api::Api::for_test_origin("http://127.0.0.1:9").unwrap();
        let daemon = Daemon::new(
            temp.path().join("state"),
            api.clone(),
            crate::auth::Auth::test_enrolled(api, "org", "runner"),
        )
        .unwrap();
        let install = daemon.auth.installation_id().await.unwrap();
        {
            let mut public = daemon.public.lock().await;
            for root in [&primary, &extra] {
                public
                    .grants
                    .push(crate::state::WorkspaceGrant::new(root, "org", &install, "key").unwrap());
            }
        }
        let mut binding = json!({"workspacePath":primary,"workspaceSetContract":crate::workspace_set::CONTRACT,"additionalWorkspacePaths":[extra],"executionPolicy":"host_user/v1","providerConfiguration":{"requested":{},"installed":{}}});
        let identities = crate::workspace_set::require_set(
            &*daemon.public.lock().await,
            &binding,
            "org",
            &install,
        )
        .unwrap();
        binding["workspaceIdentities"] = identities.clone();
        let prep = Uuid::new_v4();
        let record = json!({"organizationId":"org","accountSubject":"runner","installationId":install,"workspacePath":primary,"workspaceIdentities":identities,"bindingDigest":"fixed-binding","providers":{},"binding":binding,"commitAuthorization":{"preparationId":prep,"bindingDigest":"fixed-binding"}});
        state::write_json(
            &daemon.dir.join("preparations").join(format!("{prep}.json")),
            &record,
        )
        .unwrap();
        let mut journal = crate::jobs::protocol_tests::journal();
        journal.job["runnerId"] = json!("runner");
        journal.job["payload"] = binding;
        journal.job["payload"]["preparationId"] = json!(prep);
        journal.job["payload"]["bindingDigest"] = json!("fixed-binding");
        journal.job["payload"]["artifactOutputs"] =
            json!([{"path":"result.txt","name":"Result","workspaceRoot":extra}]);
        assert!(
            read_execution_authority(&daemon, &journal, json!({}))
                .await
                .is_ok()
        );
        journal.job["payload"]["artifactOutputs"][0]["workspaceRoot"] = json!(temp.path());
        assert!(
            read_execution_authority(&daemon, &journal, json!({}))
                .await
                .is_err()
        );
        journal.job["payload"]["artifactOutputs"] = json!([]);
        journal.job["payload"]["additionalWorkspacePaths"] = json!([temp.path()]);
        assert!(
            read_execution_authority(&daemon, &journal, json!({}))
                .await
                .is_err()
        );
        assert_eq!(daemon.managed_work(), 0);
    }

    async fn refresh_request(socket: &mut tokio::net::TcpStream) -> Value {
        use tokio::io::AsyncReadExt;
        let mut bytes = Vec::new();
        let mut buffer = [0; 2048];
        loop {
            let read = socket.read(&mut buffer).await.unwrap();
            assert!(read > 0);
            bytes.extend_from_slice(&buffer[..read]);
            if let Some(end) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
                let headers = String::from_utf8_lossy(&bytes[..end]);
                let length = headers
                    .lines()
                    .find_map(|line| {
                        line.split_once(':')
                            .filter(|(key, _)| key.eq_ignore_ascii_case("content-length"))
                            .map(|(_, value)| value.trim().parse::<usize>().unwrap())
                    })
                    .unwrap();
                if bytes.len() >= end + 4 + length {
                    assert!(
                        headers
                            .lines()
                            .next()
                            .unwrap()
                            .contains("v1/delegations/refresh/")
                    );
                    return serde_json::from_slice(&bytes[end + 4..end + 4 + length]).unwrap();
                }
            }
        }
    }
    #[tokio::test]
    async fn fingerprint_refreshable_child_uses_existing_recovery_and_preserves_bound_identity() {
        for mode in [
            "near_expiry",
            "lost_response",
            "subject_drift",
            "installation_drift",
            "grant_revoke",
            "grant_rebind",
            "prep_drift",
        ] {
            let temp = tempfile::tempdir().unwrap();
            let workspace = temp.path().join("workspace");
            std::fs::create_dir(&workspace).unwrap();
            let workspace = std::fs::canonicalize(workspace).unwrap();
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let api = crate::api::Api::for_test_origin(&format!(
                "http://{}",
                listener.local_addr().unwrap()
            ))
            .unwrap();
            let daemon = Arc::new(
                Daemon::new(
                    temp.path().join("state"),
                    api.clone(),
                    crate::auth::Auth::test_enrolled(api, "org", "runner"),
                )
                .unwrap(),
            );
            let install = daemon.auth.installation_id().await.unwrap();
            daemon.public.lock().await.grants.push(
                crate::state::WorkspaceGrant::new(&workspace, "org", &install, "key").unwrap(),
            );
            let prep = Uuid::new_v4();
            let providers = json!({});
            let config = json!({"requested":{},"installed":providers});
            let mut journal = crate::jobs::protocol_tests::journal();
            journal.organization = "org".into();
            journal.job["runnerId"] = json!("runner");
            journal.job["payload"] = json!({"preparationId":prep,"bindingDigest":"fixed-binding","workspacePath":workspace,"executionPolicy":"host_user/v1","providerConfiguration":config});
            let path = daemon.dir.join("preparations").join(format!("{prep}.json"));
            let record = json!({"organizationId":"org","accountSubject":"runner","installationId":install,
                "workspacePath":workspace,"bindingDigest":"fixed-binding","providers":providers,"expiresAtEpochMs":1,
                "binding":{"executionPolicy":"host_user/v1","providerConfiguration":config},
                "commitAuthorization":{"preparationId":prep,"bindingDigest":"fixed-binding"}});
            state::write_json(&path, &record).unwrap();
            let authority = read_execution_authority(&daemon, &journal, providers.clone())
                .await
                .unwrap();
            let authorized = AuthorizedJob {
                payload: journal.job["payload"].clone(),
                authority,
                providers,
            };
            daemon
                .auth
                .test_fingerprint_access_near_expiry("org")
                .await
                .unwrap();
            let server = tokio::spawn({
                let daemon = daemon.clone();
                let server_workspace = workspace.clone();
                let server_path = path.clone();
                async move {
                    use tokio::io::AsyncWriteExt;
                    let (mut socket, _) = listener.accept().await.unwrap();
                    let original = refresh_request(&mut socket).await;
                    assert!(original.get("recovery").is_none());
                    if mode == "lost_response" {
                        drop(socket);
                        socket = listener.accept().await.unwrap().0;
                        let recovery = refresh_request(&mut socket).await;
                        assert_eq!(recovery["refreshToken"], original["refreshToken"]);
                        assert_eq!(recovery["proof"], original["proof"]);
                        assert_eq!(recovery["recovery"], true);
                    }
                    let body = json!({"data":{"accessToken":"lmxr_synthetic_replacement","refreshToken":"synthetic-replacement","expiresInSeconds":3600}}).to_string();
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    if mode == "grant_revoke" {
                        daemon.public.lock().await.grants.clear();
                    } else if mode == "grant_rebind" {
                        let mut public = daemon.public.lock().await;
                        public.grants.clear();
                        public.grants.push(
                            crate::state::WorkspaceGrant::new(
                                &server_workspace,
                                "org",
                                "replacement-installation",
                                "rebound",
                            )
                            .unwrap(),
                        );
                    } else if mode == "prep_drift" {
                        let mut changed = state::read_json::<Value>(&server_path).unwrap();
                        changed["commitAuthorization"]["bindingDigest"] =
                            json!("changed-during-refresh");
                        state::write_json(&server_path, &changed).unwrap();
                    }
                    socket.write_all(response.as_bytes()).await.unwrap();
                    // The current-thread fixture queues the owner mutation behind
                    // the held refresh guard before its caller can re-read identity.
                    if mode == "subject_drift" {
                        daemon
                            .auth
                            .test_fingerprint_identity_drift(
                                "org",
                                None,
                                Some("replacement-runner"),
                            )
                            .await
                            .unwrap();
                    } else if mode == "installation_drift" {
                        daemon
                            .auth
                            .test_fingerprint_identity_drift(
                                "org",
                                Some(&Uuid::new_v4().to_string()),
                                None,
                            )
                            .await
                            .unwrap();
                    }
                    assert!(
                        tokio::time::timeout(
                            std::time::Duration::from_millis(100),
                            listener.accept()
                        )
                        .await
                        .is_err()
                    );
                }
            });
            let result = authorized.revalidate(&daemon, &journal).await;
            assert_eq!(
                result.is_ok(),
                matches!(mode, "near_expiry" | "lost_response"),
                "{mode}: {result:?}"
            );
            server.await.unwrap();
            if mode != "prep_drift" {
                assert_eq!(state::read_json::<Value>(&path).unwrap(), record);
            }
            assert_eq!(daemon.fingerprint_diagnostics()["started"], 0);
            assert_ne!(
                daemon.auth.status().await.unwrap()["state"],
                "recovery_pending"
            );
        }
    }
    #[tokio::test]
    async fn fingerprint_second_await_rereads_committed_local_authority_without_rehash_or_ttl() {
        for drift in [
            "none",
            "workspace",
            "installation",
            "child",
            "preparation",
            "organization",
            "providers",
        ] {
            let temp = tempfile::tempdir().unwrap();
            let workspace = temp.path().join("workspace");
            std::fs::create_dir(&workspace).unwrap();
            let workspace = std::fs::canonicalize(workspace).unwrap();
            let api = crate::api::Api::for_test_origin("http://127.0.0.1:9").unwrap();
            let daemon = Arc::new(
                Daemon::new(
                    temp.path().join("state"),
                    api.clone(),
                    crate::auth::Auth::test_enrolled(api, "org", "runner"),
                )
                .unwrap(),
            );
            let install = daemon.auth.installation_id().await.unwrap();
            daemon.public.lock().await.grants.push(
                crate::state::WorkspaceGrant::new(&workspace, "org", &install, "key").unwrap(),
            );
            let prep = Uuid::new_v4();
            let providers = json!({});
            let config = json!({"requested":{},"installed":providers});
            let mut journal = crate::jobs::protocol_tests::journal();
            journal.organization = "org".into();
            journal.job["runnerId"] = json!("runner");
            journal.job["payload"] = json!({"preparationId":prep,"bindingDigest":"fixed-binding","workspacePath":workspace,"executionPolicy":"host_user/v1","providerConfiguration":config});
            let path = daemon.dir.join("preparations").join(format!("{prep}.json"));
            // An expired preparation was already committed. Revalidation must not
            // introduce a new TTL rule for a leased/queued committed job.
            let mut record = json!({"organizationId":"org","accountSubject":"runner","installationId":install,
                "workspacePath":workspace,"bindingDigest":"fixed-binding","providers":providers,"expiresAtEpochMs":1,
                "binding":{"executionPolicy":"host_user/v1","providerConfiguration":config},
                "commitAuthorization":{"preparationId":prep,"bindingDigest":"fixed-binding"}});
            state::write_json(&path, &record).unwrap();
            let authority = read_execution_authority(&daemon, &journal, providers.clone())
                .await
                .unwrap();
            let authorized = AuthorizedJob {
                payload: journal.job["payload"].clone(),
                authority,
                providers,
            };
            let ready = Arc::new(tokio::sync::Notify::new());
            let resume = Arc::new(tokio::sync::Notify::new());
            let task = tokio::spawn({
                let daemon = daemon.clone();
                let ready = ready.clone();
                let resume = resume.clone();
                async move {
                    ready.notify_one();
                    resume.notified().await;
                    authorized.revalidate(&daemon, &journal).await
                }
            });
            ready.notified().await;
            match drift {
                "workspace" => daemon.public.lock().await.grants.clear(),
                "installation" => daemon
                    .auth
                    .test_fingerprint_identity_drift("org", Some(&Uuid::new_v4().to_string()), None)
                    .await
                    .unwrap(),
                "child" => daemon
                    .auth
                    .test_fingerprint_identity_drift("org", None, Some("changed-runner"))
                    .await
                    .unwrap(),
                "preparation" => {
                    record["commitAuthorization"]["bindingDigest"] = json!("changed");
                    state::write_json(&path, &record).unwrap();
                }
                "organization" => {
                    record["organizationId"] = json!("other");
                    state::write_json(&path, &record).unwrap();
                }
                "providers" => {
                    record["providers"] = json!({"changed":true});
                    state::write_json(&path, &record).unwrap();
                }
                _ => {}
            }
            resume.notify_one();
            let result = task.await.unwrap();
            assert_eq!(result.is_ok(), drift == "none", "{drift}: {result:?}");
            assert_eq!(daemon.fingerprint_diagnostics()["started"], 0);
            assert_eq!(state::read_json::<Value>(&path).unwrap(), record);
        }
    }
}
