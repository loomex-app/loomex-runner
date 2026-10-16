//! Credential maintenance runs in the daemon executable, without starting a
//! server. The bootstrap owns the lifecycle transaction and retains the same
//! singleton through this child and subsequent file cleanup.
use crate::{api::Api, auth::Auth, control, state};
use anyhow::{Result, bail, ensure};
use fs2::FileExt;
use serde::Deserialize;
use serde_json::Value;
use std::{
    fs::{File, OpenOptions},
    io::Read,
    os::{
        fd::FromRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
    sync::Arc,
};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Context {
    schema: String,
    operation_id: uuid::Uuid,
    state_dir: PathBuf,
    install_base: PathBuf,
    launch_agents_dir: PathBuf,
    journal_sha256: String,
    receipt_sha256: String,
    #[serde(default)]
    expected_identity: Option<crate::auth::CredentialIdentity>,
    #[serde(default)]
    api_origin: Option<String>,
    #[serde(default)]
    singleton_fd: Option<i32>,
    #[serde(default)]
    delete_credential: bool,
}

fn read_private(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file()
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.mode() & 0o077 == 0
            && metadata.len() <= limit,
        "UNSAFE_STATE"
    );
    let mut bytes = Vec::new();
    file.take(limit + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() as u64 <= limit, "UNSAFE_STATE");
    Ok(bytes)
}

fn validate_context(context: &Context, journal: &Value, identity_only: bool) -> Result<()> {
    ensure!(
        context.schema == "app.loomex.runner.credential-maintenance/v1",
        "INVALID_REQUEST"
    );
    for path in [
        &context.state_dir,
        &context.install_base,
        &context.launch_agents_dir,
    ] {
        ensure!(path.is_absolute(), "UNSAFE_STATE");
        let metadata = std::fs::symlink_metadata(path)?;
        ensure!(
            metadata.is_dir()
                && !metadata.file_type().is_symlink()
                && metadata.uid() == unsafe { libc::geteuid() },
            "UNSAFE_STATE"
        );
    }
    let schema = journal["schema"].as_str();
    ensure!(
        schema == Some("app.loomex.runner.bootstrap-uninstall/v2")
            || (identity_only && schema == Some("app.loomex.runner.bootstrap-uninstall/v1")),
        "LIFECYCLE_OPERATION_PENDING"
    );
    if schema == Some("app.loomex.runner.bootstrap-uninstall/v2") {
        ensure!(
            journal["operationId"] == context.operation_id.to_string(),
            "LIFECYCLE_OPERATION_PENDING"
        );
    }
    let receipt = &journal["receipt"];
    ensure!(
        state::json_digest(receipt) == context.receipt_sha256,
        "LIFECYCLE_OPERATION_PENDING"
    );
    ensure!(
        receipt["schema"] == "app.loomex.runner.install-receipt/v2"
            && receipt["launchAgent"].as_str()
                == Some(
                    context
                        .launch_agents_dir
                        .join("app.loomex.runner.plist")
                        .to_string_lossy()
                        .as_ref()
                ),
        "UNSAFE_STATE"
    );
    let version = receipt["version"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("UNSAFE_STATE"))?;
    ensure!(
        !version.is_empty()
            && version.split('.').count() == 3
            && version
                .split('.')
                .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit())),
        "UNSAFE_STATE"
    );
    ensure!(
        receipt["versionPath"].as_str()
            == Some(
                context
                    .install_base
                    .join("versions")
                    .join(version)
                    .to_string_lossy()
                    .as_ref()
            ),
        "UNSAFE_STATE"
    );
    let origin = receipt["developmentApiOrigin"].as_str();
    ensure!(
        origin == context.api_origin.as_deref(),
        "INVALID_API_ORIGIN"
    );
    ensure!(
        receipt["developmentOnly"] == true || context.api_origin.is_none(),
        "INVALID_API_ORIGIN"
    );
    if !identity_only {
        let identity = context
            .expected_identity
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("AUTH_RECONCILIATION_REQUIRED"))?;
        ensure!(
            journal["expectedIdentity"] == serde_json::to_value(identity)?,
            "AUTH_RECONCILIATION_REQUIRED"
        );
        ensure!(
            matches!(
                journal["phase"].as_str(),
                Some("stopped" | "revocation_pending" | "revoked")
            ),
            "LIFECYCLE_OPERATION_PENDING"
        );
        if context.delete_credential {
            ensure!(
                journal["phase"] == "revoked"
                    && (journal["remoteRevocation"] == "confirmed"
                        || (journal["remoteRevocation"] == "not_required"
                            && identity.device_id.is_none())),
                "AUTH_RECONCILIATION_REQUIRED"
            );
        }
    }
    Ok(())
}

/// Also used by the bootstrap so the parent can retain the lock through cleanup.
pub fn acquire_singleton(dir: &Path) -> Result<File> {
    control::daemon_lock(dir)
}

fn singleton(context: &Context) -> Result<File> {
    let Some(fd) = context.singleton_fd else {
        return acquire_singleton(&context.state_dir);
    };
    ensure!(fd >= 3, "UNSAFE_STATE");
    // This descriptor is explicitly inherited by the verified maintenance
    // invocation. It is the same open-file description retained by its parent.
    let file = unsafe { File::from_raw_fd(fd) };
    let actual = file.metadata()?;
    let expected = std::fs::symlink_metadata(context.state_dir.join("daemon.lock"))?;
    ensure!(
        actual.is_file()
            && expected.is_file()
            && !expected.file_type().is_symlink()
            && actual.uid() == unsafe { libc::geteuid() }
            && actual.mode() & 0o077 == 0
            && actual.dev() == expected.dev()
            && actual.ino() == expected.ino(),
        "UNSAFE_STATE"
    );
    file.try_lock_exclusive()
        .map_err(|_| anyhow::anyhow!("DAEMON_ALREADY_RUNNING"))?;
    Ok(file)
}

pub async fn run(path: &Path, identity_only: bool) -> Result<Value> {
    let context: Context = serde_json::from_slice(&read_private(path, 65_536)?)?;
    // Journal inventories can grow with retained releases. Their size is not an
    // execution/output quota; use the existing durable journal decoder.
    let journal_path = context.state_dir.join("bootstrap-uninstall.json");
    let journal_file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&journal_path)?;
    let metadata = journal_file.metadata()?;
    ensure!(
        metadata.is_file()
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.mode() & 0o077 == 0,
        "UNSAFE_STATE"
    );
    let mut journal_bytes = Vec::new();
    (&journal_file).read_to_end(&mut journal_bytes)?;
    ensure!(
        state::digest(&journal_bytes) == context.journal_sha256,
        "LIFECYCLE_OPERATION_PENDING"
    );
    let journal: Value = serde_json::from_slice(&journal_bytes)?;
    validate_context(&context, &journal, identity_only)?;
    verify_running_daemon(&journal)?;
    let lock = Arc::new(singleton(&context)?);
    let api = Api::from_installation_origin(context.api_origin.as_deref())?;
    let auth = Auth::new(api)?;
    auth.retain_store_owner(&lock);
    // Retain both ownership guards through native workers even if a caller
    // stops awaiting this local task. No remote operation is thereby canceled.
    tokio::spawn(async move {
        let _lock = lock;
        if identity_only {
            return Ok(serde_json::to_value(auth.maintenance_identity().await?)?);
        }
        let Some(identity) = context.expected_identity else { bail!("AUTH_RECONCILIATION_REQUIRED") };
        if context.delete_credential && auth.maintenance_identity().await?.is_none() {
            // The matching journal already records remote confirmation. Local
            // absence settles only deletion, never establishes revocation.
            return Ok(serde_json::json!({"identity":identity,"revoked":journal["remoteRevocation"] == "confirmed",
                "remoteRevocation":journal["remoteRevocation"],"protectedStoreRemoved":true}));
        }
        auth.maintenance_logout(&identity, context.delete_credential).await
    }).await.map_err(|_| anyhow::anyhow!("AUTH_LOGOUT_FAILED"))?
}

fn verify_running_daemon(journal: &Value) -> Result<()> {
    use sha2::Digest;
    let expected = Path::new(
        journal["maintenanceBinary"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("UNSAFE_STATE"))?,
    );
    let expected_sha = journal["maintenanceSha256"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("UNSAFE_STATE"))?;
    ensure!(
        expected.is_absolute()
            && expected_sha.len() == 64
            && expected_sha.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "UNSAFE_STATE"
    );
    let current = std::env::current_exe()?;
    ensure!(
        std::fs::canonicalize(&current)? == std::fs::canonicalize(expected)?,
        "UNSAFE_STATE"
    );
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(expected)?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file()
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.mode() & 0o022 == 0,
        "UNSAFE_STATE"
    );
    let mut hash = sha2::Sha256::new();
    let mut chunk = [0u8; 65_536];
    loop {
        let count = file.read(&mut chunk)?;
        if count == 0 {
            break;
        }
        hash.update(&chunk[..count]);
    }
    ensure!(hex::encode(hash.finalize()) == expected_sha, "UNSAFE_STATE");
    Ok(())
}

fn installed_daemon(dir: &Path) -> Result<(Value, PathBuf)> {
    let receipt: Value =
        serde_json::from_slice(&read_private(&dir.join("install-receipt.json"), 65_536)?)?;
    ensure!(
        receipt["schema"] == "app.loomex.runner.install-receipt/v2",
        "UNSAFE_STATE"
    );
    // Never send an unknown flag to an old daemon: historical versions could
    // interpret it as ordinary server startup rather than rejecting it.
    ensure!(
        receipt["version"] == env!("CARGO_PKG_VERSION"),
        "LIFECYCLE_RECOVERY_REQUIRED"
    );
    let target = PathBuf::from(
        receipt["versionPath"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("UNSAFE_STATE"))?,
    );
    ensure!(
        target.is_absolute() && !std::fs::symlink_metadata(&target)?.file_type().is_symlink(),
        "UNSAFE_STATE"
    );
    let owned: Value = state::read_json(&dir.join("owned-versions.json"))?;
    crate::lifecycle::verify_owned_version_from_inventory(&target, &owned)?;
    let daemon = target.join("bin/loomex-runner");
    ensure!(
        std::fs::symlink_metadata(&daemon)?.is_file()
            && !std::fs::symlink_metadata(&daemon)?.file_type().is_symlink(),
        "UNSAFE_STATE"
    );
    Ok((receipt, daemon))
}

#[derive(Debug)]
struct DelegatedFailure(Value);
impl std::fmt::Display for DelegatedFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0["code"].as_str().unwrap_or("AUTH_LOGOUT_FAILED"))
    }
}
impl std::error::Error for DelegatedFailure {}
pub(crate) fn delegated_error_record(error: &anyhow::Error) -> Option<Value> {
    error
        .downcast_ref::<DelegatedFailure>()
        .map(|error| error.0.clone())
}

/// The thin CLI delegates native credential work to its exact installed daemon.
pub async fn delegate_offline_logout(dir: &Path) -> Result<Value> {
    let (_, daemon) = installed_daemon(dir)?;
    let mut command = tokio::process::Command::new(daemon);
    command.arg("--maintenance-offline-logout").arg(dir);
    let (status, stdout, stderr) =
        observe_maintenance(command, std::time::Duration::from_secs(35)).await?;
    if !status.success() {
        let record: Value =
            serde_json::from_slice(&stderr).map_err(|_| anyhow::anyhow!("AUTH_LOGOUT_FAILED"))?;
        let code = record["code"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("AUTH_LOGOUT_FAILED"))?;
        ensure!(
            !code.is_empty()
                && code.len() < 100
                && code.bytes().all(|b| b.is_ascii_uppercase() || b == b'_'),
            "AUTH_LOGOUT_FAILED"
        );
        return Err(DelegatedFailure(record).into());
    }
    serde_json::from_slice(&stdout).map_err(|_| anyhow::anyhow!("AUTH_LOGOUT_FAILED"))
}

fn observation_pending() -> anyhow::Error {
    DelegatedFailure(state::safe_error("STORE_OPERATION_PENDING", false)).into()
}

async fn observe_maintenance(
    mut command: tokio::process::Command,
    budget: std::time::Duration,
) -> Result<(std::process::ExitStatus, Vec<u8>, Vec<u8>)> {
    use tokio::io::AsyncReadExt;
    command
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(false);
    let mut child = command.spawn()?;
    let stdout = child.stdout.take().ok_or_else(observation_pending)?;
    let stderr = child.stderr.take().ok_or_else(observation_pending)?;
    let observed = tokio::time::timeout(budget, async {
        let mut out = Vec::new();
        let mut err = Vec::new();
        let mut stdout = stdout.take(65_537);
        let mut stderr = stderr.take(65_537);
        let (status, _, _) = tokio::try_join!(
            child.wait(),
            stdout.read_to_end(&mut out),
            stderr.read_to_end(&mut err)
        )?;
        Ok::<_, std::io::Error>((status, out, err))
    })
    .await
    .map_err(|_| observation_pending())??;
    ensure!(
        observed.1.len() <= 65_536 && observed.2.len() <= 65_536,
        "STORE_OPERATION_PENDING"
    );
    Ok(observed)
}

pub async fn run_offline_logout(dir: &Path) -> Result<Value> {
    let (receipt, daemon) = installed_daemon(dir)?;
    ensure!(
        std::fs::canonicalize(std::env::current_exe()?)? == std::fs::canonicalize(daemon)?,
        "UNSAFE_STATE"
    );
    let version = PathBuf::from(receipt["versionPath"].as_str().unwrap());
    let paths = crate::lifecycle::Paths {
        state_dir: dir.to_owned(),
        install_base: version
            .parent()
            .and_then(Path::parent)
            .ok_or_else(|| anyhow::anyhow!("UNSAFE_STATE"))?
            .to_owned(),
        launch_agents_dir: PathBuf::from(
            receipt["launchAgent"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("UNSAFE_STATE"))?,
        )
        .parent()
        .ok_or_else(|| anyhow::anyhow!("UNSAFE_STATE"))?
        .to_owned(),
    };
    paths.validate()?;
    let lifecycle_lock = crate::lifecycle::LifecycleLock::acquire(&paths)?;
    crate::lifecycle::require_bootstrap_ownership_clear(&paths, None)?;
    crate::lifecycle::require_terminal_before_uninstall(&paths)?;
    let lock = Arc::new(acquire_singleton(dir)?);
    let auth = Auth::new(Api::from_installation_origin(
        receipt["developmentApiOrigin"].as_str(),
    )?)?;
    auth.retain_store_owner(&lock);
    tokio::spawn(async move {
        let _lifecycle_lock = lifecycle_lock;
        let _lock = lock;
        auth.offline_logout().await
    })
    .await
    .map_err(|_| anyhow::anyhow!("AUTH_LOGOUT_FAILED"))?
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn maintenance_context_reads_never_follow_symlinks_or_public_files() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("context");
        std::fs::write(&path, b"{}").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(read_private(&path, 16).unwrap(), b"{}");
        let link = root.path().join("link");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(read_private(&link, 16).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_private(&path, 16).is_err());
    }

    #[test]
    fn legacy_prepared_record_cannot_authorize_logout() {
        let value = json!({"schema":"app.loomex.runner.credential-maintenance/v1", "operationId":uuid::Uuid::new_v4(),
            "stateDir":"/tmp", "installBase":"/tmp", "launchAgentsDir":"/tmp", "journalSha256":"a".repeat(64), "receiptSha256":"b".repeat(64)});
        let context: Context = serde_json::from_value(value).unwrap();
        assert!(
            validate_context(
                &context,
                &json!({"schema":"app.loomex.runner.bootstrap-uninstall/v1"}),
                false
            )
            .is_err()
        );
    }

    fn fixture(root: &Path) -> (Value, Value) {
        for name in ["state", "runner", "agents"] {
            std::fs::create_dir(root.join(name)).unwrap();
        }
        let receipt = json!({"schema":"app.loomex.runner.install-receipt/v2", "version":"1.2.7",
            "versionPath":root.join("runner/versions/1.2.7"),"launchAgent":root.join("agents/app.loomex.runner.plist"),
            "developmentOnly":true,"developmentApiOrigin":"http://127.0.0.1:28080/"});
        let operation = uuid::Uuid::new_v4();
        let identity =
            json!({"installationId":uuid::Uuid::new_v4(), "deviceId":uuid::Uuid::new_v4()});
        let journal = json!({"schema":"app.loomex.runner.bootstrap-uninstall/v2", "phase":"stopped",
            "operationId":operation, "receipt":receipt,"expectedIdentity":identity});
        let context = json!({"schema":"app.loomex.runner.credential-maintenance/v1", "operationId":operation,
            "stateDir":root.join("state"),"installBase":root.join("runner"),"launchAgentsDir":root.join("agents"),
            "journalSha256":state::json_digest(&journal),"receiptSha256":state::json_digest(&receipt),
            "expectedIdentity":identity,"apiOrigin":"http://127.0.0.1:28080/"});
        (context, journal)
    }

    #[test]
    fn deletion_requires_identity_bound_external_revocation_checkpoint() {
        let root = tempfile::tempdir().unwrap();
        let (mut context, mut journal) = fixture(root.path());
        assert!(
            validate_context(
                &serde_json::from_value(context.clone()).unwrap(),
                &journal,
                false
            )
            .is_ok()
        );
        context["deleteCredential"] = json!(true);
        assert!(
            validate_context(
                &serde_json::from_value(context.clone()).unwrap(),
                &journal,
                false
            )
            .is_err()
        );
        journal["phase"] = json!("revoked");
        journal["remoteRevocation"] = json!("confirmed");
        assert!(
            validate_context(
                &serde_json::from_value(context.clone()).unwrap(),
                &journal,
                false
            )
            .is_ok()
        );
        journal["expectedIdentity"]["installationId"] = json!(uuid::Uuid::new_v4());
        assert!(
            validate_context(&serde_json::from_value(context).unwrap(), &journal, false).is_err()
        );
    }

    #[test]
    fn signed_out_cleanup_cannot_masquerade_as_device_revocation() {
        let root = tempfile::tempdir().unwrap();
        let (mut context, mut journal) = fixture(root.path());
        context["deleteCredential"] = json!(true);
        journal["phase"] = json!("revoked");
        journal["remoteRevocation"] = json!("not_required");
        assert!(
            validate_context(
                &serde_json::from_value(context.clone()).unwrap(),
                &journal,
                false
            )
            .is_err()
        );
        context["expectedIdentity"]["deviceId"] = Value::Null;
        journal["expectedIdentity"]["deviceId"] = Value::Null;
        assert!(
            validate_context(&serde_json::from_value(context).unwrap(), &journal, false).is_ok()
        );
    }

    #[test]
    fn destination_and_operation_substitution_are_rejected_before_native_access() {
        let root = tempfile::tempdir().unwrap();
        let (context, journal) = fixture(root.path());
        for (field, replacement) in [
            ("apiOrigin", json!("http://127.0.0.1:9/")),
            ("operationId", json!(uuid::Uuid::new_v4())),
            ("receiptSha256", json!("a".repeat(64))),
        ] {
            let mut changed = context.clone();
            changed[field] = replacement;
            assert!(
                validate_context(&serde_json::from_value(changed).unwrap(), &journal, false)
                    .is_err(),
                "{field}"
            );
        }
    }

    #[test]
    fn inherited_singleton_must_name_the_existing_locked_inode() {
        use std::os::fd::IntoRawFd;
        let root = tempfile::tempdir().unwrap();
        let (context, _) = fixture(root.path());
        let mut context: Context = serde_json::from_value(context).unwrap();
        let parent = acquire_singleton(&context.state_dir).unwrap();
        context.singleton_fd = Some(parent.try_clone().unwrap().into_raw_fd());
        let child = singleton(&context).unwrap();
        assert!(acquire_singleton(&context.state_dir).is_err());
        drop(child);
        assert!(acquire_singleton(&context.state_dir).is_err());
        let unrelated = File::create(root.path().join("other")).unwrap();
        context.singleton_fd = Some(unrelated.into_raw_fd());
        assert!(singleton(&context).is_err());
        drop(parent);
        assert!(acquire_singleton(&context.state_dir).is_ok());
    }

    #[test]
    fn direct_maintenance_refuses_another_executable_before_native_access() {
        let root = tempfile::tempdir().unwrap();
        let binary = root.path().join("other-daemon");
        std::fs::write(&binary, b"not the running daemon").unwrap();
        assert!(
            verify_running_daemon(&json!({"maintenanceBinary":binary,
            "maintenanceSha256":state::digest(b"not the running daemon")}))
            .is_err()
        );
        assert!(verify_running_daemon(&json!({})).is_err());
    }

    #[tokio::test]
    async fn observation_deadline_does_not_kill_its_disposable_child() {
        let root = tempfile::tempdir().unwrap();
        let pid_file = root.path().join("pid");
        let mut command = tokio::process::Command::new("/bin/sh");
        command
            .arg("-c")
            .arg("echo $$ > \"$1\"; exec /bin/sleep 30")
            .arg("maintenance-test")
            .arg(&pid_file);
        let result = observe_maintenance(command, std::time::Duration::from_millis(200)).await;
        assert_eq!(result.unwrap_err().to_string(), "STORE_OPERATION_PENDING");
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(2);
        while !pid_file.exists() {
            assert!(tokio::time::Instant::now() < deadline);
            tokio::task::yield_now().await;
        }
        let pid: i32 = std::fs::read_to_string(pid_file)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        // Only this test-created process is observed and stopped.
        assert_eq!(unsafe { libc::kill(pid, 0) }, 0);
        assert_eq!(unsafe { libc::kill(pid, libc::SIGTERM) }, 0);
    }
}
