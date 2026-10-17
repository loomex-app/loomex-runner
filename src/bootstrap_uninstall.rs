//! Resumable bootstrap-owned uninstall. Native credential IO is delegated only
//! to a release-verified daemon executable with the inherited singleton guard.
use super::*;
use anyhow::ensure;
use fs2::FileExt;
use std::os::{
    fd::AsRawFd,
    unix::{
        fs::{FileTypeExt, MetadataExt},
        process::CommandExt,
    },
};

const SCHEMA: &str = "app.loomex.runner.bootstrap-uninstall/v2";
const OLD_SCHEMA: &str = "app.loomex.runner.bootstrap-uninstall/v1";
#[path = "bootstrap_uninstall/work.rs"]
mod work;
pub(super) use work::{
    WorkRefusal, run_work, valid_work_digest, work_maintenance_reference, work_owner_reference,
    work_preflight,
};

fn regular_bytes(path: &Path) -> Result<Vec<u8>> {
    use std::io::Read;
    let before = fs::symlink_metadata(path)?;
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let meta = file.metadata()?;
    ensure!(
        meta.is_file()
            && !before.file_type().is_symlink()
            && meta.uid() == unsafe { libc::geteuid() }
            && meta.dev() == before.dev()
            && meta.ino() == before.ino(),
        "unsafe uninstall file"
    );
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    let after = fs::symlink_metadata(path)?;
    ensure!(
        meta.dev() == after.dev()
            && meta.ino() == after.ino()
            && meta.len() == after.len()
            && meta.mtime() == after.mtime()
            && meta.mtime_nsec() == after.mtime_nsec(),
        "uninstall file changed during read"
    );
    Ok(bytes)
}
fn digest_file(path: &Path) -> Result<String> {
    Ok(state::digest(&regular_bytes(path)?))
}
fn save(paths: &lifecycle::Paths, journal: &Value) -> Result<()> {
    state::write_json(&paths.state_dir.join("bootstrap-uninstall.json"), journal)
}
fn fault(name: &str) -> Result<()> {
    if std::env::var_os(format!("LOOMEX_TEST_UNINSTALL_FAIL_{name}")).is_some() {
        bail!("injected uninstall failure at {name}")
    }
    Ok(())
}
fn journal_owned(journal: &Value) -> Value {
    json!({"schema":"app.loomex.runner.owned-versions/v1","paths":journal["paths"],"inventories":journal["inventories"]})
}
fn expected_files<'a>(owned: &'a Value, target: &Path) -> Result<&'a Vec<Value>> {
    owned["inventories"]
        .as_array()
        .context("invalid owned inventory")?
        .iter()
        .find(|entry| entry["path"].as_str() == Some(target.to_string_lossy().as_ref()))
        .and_then(|entry| entry["files"].as_array())
        .context("owned version inventory is missing")
}
pub(super) fn validate_owned_installation(
    paths: &lifecycle::Paths,
    receipt: &Value,
    owned: &Value,
    allow_missing: bool,
) -> Result<()> {
    ensure!(
        receipt["schema"] == "app.loomex.runner.install-receipt/v2"
            && receipt["launchAgent"].as_str()
                == Some(
                    paths
                        .launch_agents_dir
                        .join("app.loomex.runner.plist")
                        .to_string_lossy()
                        .as_ref()
                ),
        "invalid owned installation receipt"
    );
    let versions = fs::canonicalize(paths.install_base.join("versions"))?;
    let entries = owned["paths"]
        .as_array()
        .context("invalid owned version inventory")?;
    ensure!(
        owned["schema"] == "app.loomex.runner.owned-versions/v1" && !entries.is_empty(),
        "invalid owned version inventory"
    );
    let receipt_target = PathBuf::from(
        receipt["versionPath"]
            .as_str()
            .context("owned receipt target missing")?,
    );
    ensure!(
        entries
            .iter()
            .any(|entry| entry.as_str() == Some(receipt_target.to_string_lossy().as_ref()))
            && receipt_target.file_name().and_then(|n| n.to_str()) == receipt["version"].as_str(),
        "owned receipt target is not inventoried"
    );
    let mut unique = std::collections::BTreeSet::new();
    for entry in entries {
        let path = PathBuf::from(entry.as_str().context("invalid owned version path")?);
        ensure!(
            path.is_absolute()
                && path.parent() == Some(versions.as_path())
                && unique.insert(path.clone())
                && path.file_name().and_then(|v| v.to_str()).is_some_and(|v| {
                    let parts: Vec<_> = v.split('.').collect();
                    parts.len() == 3
                        && parts
                            .iter()
                            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
                }),
            "unsafe owned version path"
        );
        let files = expected_files(owned, &path)?;
        match fs::symlink_metadata(&path) {
            Ok(meta) if meta.is_dir() && !meta.file_type().is_symlink() => {
                lifecycle::prune_quarantine_inventory(&path, files, allow_missing)?;
            }
            Err(e) if allow_missing && e.kind() == std::io::ErrorKind::NotFound => (),
            _ => bail!("unsafe owned version path"),
        }
    }
    ensure!(
        owned["inventories"]
            .as_array()
            .is_some_and(|v| v.len() == entries.len()),
        "inconsistent owned inventory"
    );
    Ok(())
}
fn validate_helper(paths: &lifecycle::Paths, journal: &Value) -> Result<PathBuf> {
    let helper = PathBuf::from(
        journal["helper"]
            .as_str()
            .context("uninstall helper missing")?,
    );
    ensure!(
        helper == paths.state_dir.join("bootstrap-uninstall-helper")
            && journal["helperSha256"] == journal["receipt"]["bootstrapSha256"]
            && digest_file(&helper)? == journal["helperSha256"],
        "uninstall helper identity mismatch"
    );
    Ok(helper)
}
fn validate_journal(paths: &lifecycle::Paths, journal: &Value) -> Result<()> {
    ensure!(
        journal["schema"] == SCHEMA
            && matches!(
                journal["phase"].as_str(),
                Some(
                    "prepared"
                        | "idle_verified"
                        | "stop_intent"
                        | "stopped"
                        | "revoked"
                        | "cleanup"
                        | "terminal"
                )
            ),
        "unsupported uninstall journal; use explicit recover-uninstall with the reviewed old journal digest"
    );
    Uuid::parse_str(
        journal["operationId"]
            .as_str()
            .context("uninstall operation identity missing")?,
    )?;
    Uuid::parse_str(
        journal["drainKey"]
            .as_str()
            .context("uninstall drain identity missing")?,
    )?;
    ensure!(
        journal["receiptSha256"]
            .as_str()
            .is_some_and(|s| s.len() == 64)
            && journal["fenceJournalSha256"]
                .as_str()
                .is_some_and(|s| s.len() == 64),
        "uninstall binding missing"
    );
    validate_helper(paths, journal)?;
    let receipt_path = paths.state_dir.join("install-receipt.json");
    if receipt_path.exists() {
        ensure!(
            digest_file(&receipt_path)?
                == journal
                    .get("receiptFileSha256")
                    .unwrap_or(&journal["receiptSha256"])
                    .as_str()
                    .context("uninstall receipt file binding missing")?,
            "uninstall receipt changed"
        );
    } else {
        ensure!(
            matches!(journal["phase"].as_str(), Some("cleanup" | "terminal")),
            "uninstall receipt missing before cleanup"
        );
    }
    let live_owned = paths.state_dir.join("owned-versions.json");
    if live_owned.exists() {
        let value: Value = serde_json::from_slice(&regular_bytes(&live_owned)?)?;
        ensure!(
            value == journal_owned(journal),
            "uninstall owned inventory changed"
        );
    }
    let target = PathBuf::from(
        journal["receipt"]["versionPath"]
            .as_str()
            .context("uninstall target missing")?,
    );
    ensure!(
        journal["paths"].as_array().is_some_and(|v| v
            .iter()
            .any(|p| p.as_str() == Some(target.to_string_lossy().as_ref()))),
        "uninstall target is not inventoried"
    );
    // Payloads already renamed to quarantine are intentionally absent here.
    validate_owned_installation(
        paths,
        &journal["receipt"],
        &journal_owned(journal),
        matches!(journal["phase"].as_str(), Some("cleanup" | "terminal")),
    )?;
    Ok(())
}

fn public_identity(status: &Value) -> Result<Value> {
    ensure!(
        status["loginPending"] == false
            && matches!(
                (status["code"].as_str(), status["authenticated"].as_bool()),
                (Some("AUTHENTICATED"), Some(true)) | (Some("AUTH_REQUIRED"), Some(false))
            ),
        "uninstall authentication recovery is unresolved"
    );
    if status["code"] == "AUTH_REQUIRED"
        && status["installationId"].is_null()
        && status["authenticated"] == false
    {
        return Ok(Value::Null);
    }
    let installation = status["installationId"]
        .as_str()
        .context("uninstall installation identity missing")?;
    Uuid::parse_str(installation)?;
    Ok(json!({"installationId":installation,"deviceId":null}))
}
fn record_native_identity(journal: &mut Value, native: Value) -> Result<bool> {
    if journal["expectedIdentity"].is_null() {
        ensure!(
            native.is_null()
                && (journal["recovery"].is_null() || journal["recovery"]["adoptedCurrent"] == true),
            "native credential item differs from verified fresh signed-out state"
        );
        journal["nativeAbsenceVerified"] = json!(true);
        journal["remoteRevocation"] = json!("not_required");
        journal["protectedStoreRemoved"] = json!(true);
        journal["revocationResult"] = json!({"remoteRevocation":"not_required","identity":null,"protectedStoreRemoved":true,"nativeAbsenceVerified":true});
        return Ok(true);
    }
    ensure!(
        native["installationId"] == journal["expectedIdentity"]["installationId"],
        "native uninstall identity differs from trusted baseline"
    );
    ensure!(
        journal["expectedIdentity"]["deviceId"].is_null() || native == journal["expectedIdentity"],
        "native uninstall device identity changed"
    );
    journal["expectedIdentity"] = native;
    Ok(false)
}

fn validated_current_identity(journal: &Value) -> Result<Value> {
    let identity = &journal["expectedIdentity"];
    if identity.is_null() {
        return Ok(Value::Null);
    }
    Uuid::parse_str(
        identity["installationId"]
            .as_str()
            .context("current uninstall identity missing")?,
    )?;
    ensure!(
        identity.as_object().is_some_and(|v| v.len() == 2) && identity["deviceId"].is_null(),
        "current uninstall identity invalid"
    );
    Ok(identity.clone())
}

fn prior_identity(paths: &lifecycle::Paths) -> Result<Value> {
    let operation: lifecycle::Operation =
        state::read_json(&paths.state_dir.join("lifecycle-operation.json"))?;
    let operation = operation
        .uninstall_fence
        .as_ref()
        .and_then(|f| f.original_operation.as_deref())
        .unwrap_or(&operation);
    ensure!(
        lifecycle::operation_is_terminal(operation)?,
        "uninstall prior operation is unresolved"
    );
    let installation = match operation.auth_baseline.as_ref() {
        Some(lifecycle::AuthBaseline::Authenticated {
            installation_id, ..
        }) => *installation_id,
        Some(lifecycle::AuthBaseline::SignedOut {
            installation_id: Some(id),
        }) => *id,
        _ => bail!(
            "old uninstall has no trusted authentication baseline; supported recovery cannot derive credential ownership"
        ),
    };
    Ok(json!({"installationId":installation,"deviceId":null}))
}
fn reject_unresolved_work(paths: &lifecycle::Paths) -> Result<()> {
    reject_unresolved_work_evidence(paths).map_err(|error| error.context(ManagedWorkBlocked))
}
fn reject_unresolved_work_evidence(paths: &lifecycle::Paths) -> Result<()> {
    let root = paths.state_dir.join("jobs");
    if !root.try_exists()? {
        return Ok(());
    }
    ensure!(
        fs::symlink_metadata(&root)?.is_dir()
            && !fs::symlink_metadata(&root)?.file_type().is_symlink(),
        "unsafe work evidence"
    );
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        if entry
            .file_name()
            .to_str()
            .is_none_or(|name| Uuid::parse_str(name).is_err())
        {
            continue;
        }
        let dir = entry.path();
        let meta = fs::symlink_metadata(&dir)?;
        ensure!(
            meta.is_dir() && !meta.file_type().is_symlink(),
            "unresolved uninstall work evidence"
        );
        let journal: Value = serde_json::from_slice(&regular_bytes(&dir.join("journal.json"))?)?;
        ensure!(
            journal["phase"] == "acknowledged",
            "unresolved uninstall work evidence; preserve run journals and reconcile delivery first"
        );
    }
    Ok(())
}

fn qualify_before_effects(paths: &lifecycle::Paths) -> Result<()> {
    reject_unresolved_work(paths)?;
    uninstall_state::inventory_resolved_state(&paths.state_dir)
        .map_err(|error| error.context(ManagedWorkBlocked))?;
    Ok(())
}

fn singleton(paths: &lifecycle::Paths, synthetic: bool) -> Result<File> {
    let path = paths.state_dir.join("daemon.lock");
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(synthetic)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)?;
    let meta = file.metadata()?;
    ensure!(
        meta.is_file()
            && meta.uid() == unsafe { libc::geteuid() }
            && meta.permissions().mode() & 0o077 == 0,
        "unsafe daemon singleton"
    );
    file.try_lock_exclusive()
        .context("daemon singleton is still owned")?;
    let fresh = fs::symlink_metadata(&path)?;
    ensure!(
        meta.dev() == fresh.dev() && meta.ino() == fresh.ino(),
        "daemon singleton changed"
    );
    Ok(file)
}
async fn label_observation(paths: &lifecycle::Paths) -> Result<Option<i32>> {
    let uid = unsafe { libc::geteuid() };
    let output = tokio::time::timeout(
        std::time::Duration::from_secs(4),
        tokio::process::Command::new("/bin/launchctl")
            .arg("print")
            .arg(format!("gui/{uid}/app.loomex.runner"))
            .env("LC_ALL", "C")
            .stdin(Stdio::null())
            .kill_on_drop(true)
            .output(),
    )
    .await
    .context("uninstall service observation timed out")??;
    ensure!(
        output.stdout.len() + output.stderr.len() < 1024 * 1024,
        "uninstall service observation overflow"
    );
    let missing =
        format!("Could not find service \"app.loomex.runner\" in domain for user gui: {uid}");
    let err = std::str::from_utf8(&output.stderr)?;
    if output.status.code() == Some(113)
        && output.stdout.is_empty()
        && (err.lines().collect::<Vec<_>>() == [missing.as_str()]
            || err.lines().collect::<Vec<_>>() == ["Bad request.", missing.as_str()])
    {
        return Ok(None);
    }
    let out = std::str::from_utf8(&output.stdout)?;
    ensure!(
        output.status.success()
            && err.is_empty()
            && out.starts_with(&format!("gui/{uid}/app.loomex.runner = {{\n"))
            && out.ends_with("}\n"),
        "uninstall service observation unavailable"
    );
    let programs: Vec<_> = out
        .lines()
        .filter_map(|s| s.strip_prefix("\tprogram = "))
        .collect();
    let receipt_target: Value = state::read_json(&paths.state_dir.join("install-receipt.json"))?;
    let target = PathBuf::from(
        receipt_target["versionPath"]
            .as_str()
            .context("uninstall target missing")?,
    )
    .join("bin/loomex-runner");
    ensure!(
        programs.len() == 1
            && (Path::new(programs[0]) == target
                || Path::new(programs[0]) == paths.install_base.join("current/bin/loomex-runner")),
        "uninstall service identity mismatch"
    );
    let pids: Vec<_> = out
        .lines()
        .filter_map(|s| s.strip_prefix("\tpid = "))
        .collect();
    ensure!(pids.len() == 1, "uninstall service process unavailable");
    Ok(Some(
        pids[0]
            .parse::<i32>()
            .ok()
            .filter(|p| *p > 0)
            .context("uninstall service process unavailable")?,
    ))
}
fn verify_recorded_process_exit(journal: &Value) -> Result<()> {
    if let Some(pid) = journal["stopEvidence"]["pid"].as_i64() {
        let pid = i32::try_from(pid)?;
        ensure!(pid > 0, "invalid uninstall process identity");
        let result = unsafe { libc::kill(pid, 0) };
        ensure!(
            result == -1 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH),
            "uninstall recorded runner process is not confirmed exited"
        );
    }
    Ok(())
}

async fn verify_stopped(
    paths: &lifecycle::Paths,
    journal: &Value,
    synthetic: bool,
) -> Result<File> {
    if !synthetic {
        ensure!(
            label_observation(paths).await?.is_none(),
            "uninstall runner service remains loaded"
        );
        verify_recorded_process_exit(journal)?;
    }
    let file = singleton(paths, synthetic)?;
    if journal["cleanup"]["stateDeletingStarted"] != true {
        reject_unresolved_work(paths)?;
    }
    if !synthetic {
        let targets = journal["paths"]
            .as_array()
            .context("missing uninstall paths")?
            .iter()
            .map(|v| PathBuf::from(v.as_str().unwrap()))
            .collect::<Vec<_>>();
        lifecycle::prune_in_use(&targets).await?;
    }
    Ok(file)
}

async fn invoke_maintenance(
    paths: &lifecycle::Paths,
    journal: &Value,
    guard: &File,
    identity_only: bool,
    delete_credential: bool,
    args: &Arguments,
) -> Result<Value> {
    let binary = PathBuf::from(
        journal["maintenanceBinary"]
            .as_str()
            .context("verified maintenance daemon is missing")?,
    );
    ensure!(
        digest_file(&binary)? == journal["maintenanceSha256"],
        "maintenance daemon identity changed"
    );
    let inherited = guard.try_clone()?;
    let fd = inherited.as_raw_fd();
    let context_path = paths.state_dir.join(format!(
        "uninstall-maintenance-{}.json",
        journal["operationId"].as_str().unwrap()
    ));
    let context = json!({"schema":"app.loomex.runner.credential-maintenance/v1","operationId":journal["operationId"],"stateDir":paths.state_dir,"installBase":paths.install_base,"launchAgentsDir":paths.launch_agents_dir,"journalSha256":digest_file(&paths.state_dir.join("bootstrap-uninstall.json"))?,"receiptSha256":journal["receiptSha256"],"expectedIdentity":journal["expectedIdentity"],"apiOrigin":journal["receipt"]["developmentApiOrigin"],"singletonFd":fd,"deleteCredential":delete_credential});
    state::write_json(&context_path, &context)?;
    let mut child = tokio::process::Command::new(&binary);
    child
        .arg(if identity_only {
            "--maintenance-identity"
        } else {
            "--maintenance-logout"
        })
        .arg(&context_path)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(false);
    // The descriptor shares the parent's locked open file description. Both
    // owners retain it until native work and payload cleanup have finished.
    unsafe {
        child.pre_exec(move || {
            let flags = libc::fcntl(fd, libc::F_GETFD);
            if flags < 0 || libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut process = child.spawn()?;
    dispatch_activation(args, true);
    let output = observe_maintenance(&mut process, std::time::Duration::from_secs(35)).await?;
    if !output.status.success() {
        return Err(maintenance_failure(&output.stderr));
    }
    let value =
        serde_json::from_slice(&output.stdout).context("maintenance daemon result invalid")?;
    remove_regular(&context_path)?;
    Ok(value)
}

async fn observe_maintenance(
    process: &mut tokio::process::Child,
    budget: std::time::Duration,
) -> Result<std::process::Output> {
    let stdout = process
        .stdout
        .take()
        .context("maintenance output unavailable")?;
    let stderr = process
        .stderr
        .take()
        .context("maintenance diagnostics unavailable")?;
    let observation = async {
        let (stdout, stderr, status) =
            tokio::try_join!(bounded_pipe(stdout), bounded_pipe(stderr), process.wait())?;
        Ok::<_, anyhow::Error>(std::process::Output {
            status,
            stdout,
            stderr,
        })
    };
    // An observation timeout never kills credential IO. The inherited lock
    // remains owned by the child; a retry must wait for actual native exit.
    tokio::time::timeout(budget,observation).await.context("maintenance observation timed out; child retains singleton ownership; resume the same uninstall after it finishes")?
}

async fn bounded_pipe<R: tokio::io::AsyncRead + Unpin>(pipe: R) -> std::io::Result<Vec<u8>> {
    use tokio::io::AsyncReadExt;
    let mut bytes = Vec::new();
    pipe.take(65_537).read_to_end(&mut bytes).await?;
    if bytes.len() > 65_536 {
        return Err(std::io::Error::other("maintenance output limit exceeded"));
    }
    Ok(bytes)
}

fn maintenance_failure(stderr: &[u8]) -> anyhow::Error {
    let envelope: Value = serde_json::from_slice(stderr).unwrap_or(Value::Null);
    let no_details = Value::Null;
    // The daemon's public error encoder places cleanup facts under data.
    // Flat records remain readable for the older bounded diagnostic contract;
    // malformed data never falls back to an unrelated top-level detail.
    let value = match envelope.get("data") {
        Some(value) if value.is_object() => value,
        Some(_) => &no_details,
        None => &envelope,
    };
    let code = envelope["code"]
        .as_str()
        .filter(|s| {
            matches!(
                *s,
                "STORE_ACCESS_REQUIRED"
                    | "STORE_ACCESS_DENIED"
                    | "STORE_OPERATION_PENDING"
                    | "STORE_INVALID"
                    | "STORE_OWNER_BUSY"
                    | "STORE_UNAVAILABLE"
                    | "AUTH_REQUIRED"
                    | "AUTH_EXPIRED"
                    | "AUTH_IDENTITY_CHANGED"
                    | "AUTH_RECONCILIATION_REQUIRED"
                    | "AUTH_RECOVERY_PENDING"
                    | "AUTH_LOGOUT_FAILED"
                    | "INVALID_API_ORIGIN"
                    | "DAEMON_ALREADY_RUNNING"
            )
        })
        .unwrap_or("AUTH_LOGOUT_FAILED");
    let stage = value["failureStage"]
        .as_str()
        .filter(|s| {
            matches!(
                *s,
                "identity_probe"
                    | "credential_owner"
                    | "operation_admission"
                    | "protected_store_read"
                    | "logout_intent"
                    | "remote_revocation"
                    | "identity_verification"
                    | "revocation_evidence"
                    | "protected_store_clear"
                    | "protected_store_delete"
                    | "authority_reconciliation"
                    | "credential_store"
            )
        })
        .unwrap_or("maintenance_daemon");
    let category = value["failureCategory"]
        .as_str()
        .filter(|s| {
            matches!(
                *s,
                "access_required"
                    | "access_denied"
                    | "native_operation_pending"
                    | "invalid_store"
                    | "owner_busy"
                    | "identity_mismatch"
                    | "unresolved_authority"
                    | "operation_busy"
                    | "remote_unconfirmed"
                    | "native_os_error"
                    | "native_io_timeout"
                    | "native_worker_failed"
                    | "serialization_timeout"
                    | "unavailable"
            )
        })
        .unwrap_or("unavailable");
    let mut projected = json!({"code":code,"failureStage":stage,"failureCategory":category,"nativeOsStatus":value["nativeOsStatus"].as_i64().and_then(|n| i32::try_from(n).ok())});
    if let Some(status) = value["httpStatus"]
        .as_u64()
        .filter(|status| (100..=599).contains(status))
    {
        projected["httpStatus"] = json!(status);
    }
    if let Some(correlation) = value["correlationId"]
        .as_str()
        .and_then(|value| Uuid::parse_str(value).ok())
    {
        projected["correlationId"] = json!(correlation.to_string());
    }
    if let Some(remote) = value["remoteCode"].as_str().filter(|code| {
        !code.is_empty()
            && code.len() <= 120
            && code
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
    }) {
        projected["remoteCode"] = json!(remote);
    }
    if let Some(outcome) = envelope["outcome"]
        .as_str()
        .filter(|outcome| matches!(*outcome, "not_dispatched" | "rejected" | "unknown"))
    {
        projected["outcome"] = json!(outcome);
    }
    if let Some(recovery) = envelope["recovery"].as_str().filter(|recovery| {
        matches!(
            *recovery,
            "correct_input"
                | "explicit_scope_upgrade"
                | "prepare_again"
                | "read_run_status"
                | "reconcile_outcome"
                | "refresh_authority"
                | "refresh_context"
                | "retry_exact_operation"
                | "select_supported_provider"
                | "unavailable"
        )
    }) {
        projected["recovery"] = json!(recovery);
    }
    if let Some(remote) = value["remoteRevocation"].as_str().filter(|remote| {
        matches!(
            *remote,
            "not_dispatched" | "pending" | "confirmed" | "not_required" | "unverified"
        )
    }) {
        projected["remoteRevocation"] = json!(remote);
    }
    if let Some(removed) = value["protectedStoreRemoved"].as_bool() {
        projected["protectedStoreRemoved"] = json!(removed);
    }
    let error = anyhow::anyhow!("{projected}");
    if matches!(
        envelope["outcome"].as_str(),
        Some("not_dispatched" | "rejected")
    ) {
        // Context keeps the public JSON display intact while retaining a typed
        // authoritative refusal marker for the activation outcome encoder.
        return Err::<(), _>(DefinitiveActivationBlock)
            .context(error)
            .unwrap_err();
    }
    error
}

fn immutable_copy(path: &Path, bytes: &[u8]) -> Result<()> {
    if fs::symlink_metadata(path).is_ok() {
        ensure!(
            regular_bytes(path)? == bytes,
            "immutable uninstall recovery evidence changed"
        );
        return Ok(());
    }
    let parent = path.parent().context("unsafe immutable evidence path")?;
    let temporary = parent.join(format!(
        ".uninstall-immutable-publication-{}",
        Uuid::new_v4()
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    // The native lifecycle owner serializes publication. Only a complete synced
    // inode can become an immutable context or evidence record.
    ensure!(
        matches!(fs::symlink_metadata(path),Err(error) if error.kind()==std::io::ErrorKind::NotFound),
        "immutable uninstall recovery evidence changed"
    );
    fs::rename(&temporary, path)?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

fn checkpoint_idle_stop_intent(
    paths: &lifecycle::Paths,
    journal: &mut Value,
    synthetic: bool,
) -> Result<()> {
    if journal["phase"] != "idle_verified" {
        return Ok(());
    }
    if !synthetic {
        ensure!(
            journal["stopEvidence"]["pid"]
                .as_i64()
                .and_then(|pid| i32::try_from(pid).ok())
                .is_some_and(|pid| pid > 0),
            "saved uninstall idle proof has no process identity"
        );
        ensure!(
            digest_file(&paths.launch_agents_dir.join("app.loomex.runner.plist"))?
                == journal["stopEvidence"]["launchAgentSha256"],
            "saved uninstall idle proof service changed"
        );
    }
    journal["phase"] = json!("stop_intent");
    journal["stopEvidence"]["request"] = json!("prepared");
    save(paths, journal)?;
    fault("AFTER_STOP_INTENT")?;
    Ok(())
}

async fn require_initial_admission<F>(phase: &str, admission: F) -> Result<()>
where
    F: std::future::Future<Output = Result<()>>,
{
    if phase == "prepared" {
        admission.await?;
    }
    Ok(())
}

pub(super) async fn run(args: Arguments, recover: bool) -> Result<()> {
    let paths = paths(&args)?;
    let _lifecycle = lifecycle::LifecycleLock::acquire(&paths)?;
    let terminal_path = paths.state_dir.join("bootstrap-uninstall-terminal.json");
    if terminal_path.exists() && !paths.state_dir.join("bootstrap-uninstall.json").exists() {
        return finish_terminal(&paths, &args, recover).await;
    }
    lifecycle::require_terminal_before_uninstall(&paths)?;
    let journal_path = paths.state_dir.join("bootstrap-uninstall.json");
    let synthetic = std::env::var_os("LOOMEX_INSTALL_TEST_MODE").is_some();
    let mut journal: Value;
    if journal_path.exists() {
        journal = serde_json::from_slice(&regular_bytes(&journal_path)?)?;
        if recover && journal["schema"] == SCHEMA && journal["recovery"].is_null() {
            if journal["phase"] != "prepared" {
                return Err(OriginalUninstallOwnerRequired.into());
            }
            ensure!(
                args.expected_old_journal_sha256.as_deref()
                    == Some(digest_file(&journal_path)?.as_str()),
                "reviewed current uninstall journal digest mismatch"
            );
            validate_journal(&paths, &journal)?;
            select_activation(
                &args,
                Uuid::parse_str(journal["operationId"].as_str().unwrap())?,
            );
        }
        if journal["schema"] == OLD_SCHEMA
            || (recover && journal["schema"] == SCHEMA && journal["recovery"].is_null())
        {
            ensure!(
                recover,
                "old uninstall requires explicit recover-uninstall RELEASE --expected-old-journal-sha256 SHA256"
            );
            journal = recover_old(&paths, &args, journal).await?;
        } else {
            validate_journal(&paths, &journal)?;
        }
    } else {
        ensure!(!recover, "old uninstall journal is unavailable");
        let receipt_path = paths.state_dir.join("install-receipt.json");
        let receipt: Value = serde_json::from_slice(&regular_bytes(&receipt_path)?)?;
        let owned: Value = serde_json::from_slice(&regular_bytes(
            &paths.state_dir.join("owned-versions.json"),
        )?)?;
        validate_owned_installation(&paths, &receipt, &owned, false)?;
        qualify_before_effects(&paths)?;
        let target = PathBuf::from(
            receipt["versionPath"]
                .as_str()
                .context("installation target missing")?,
        );
        let bootstrap = target.join("bin/loomex-lifecycle-bootstrap");
        ensure!(
            digest_file(&bootstrap)? == receipt["bootstrapSha256"],
            "installed bootstrap identity mismatch"
        );
        let helper = paths.state_dir.join("bootstrap-uninstall-helper");
        immutable_copy(&helper, &regular_bytes(&bootstrap)?)?;
        fs::set_permissions(&helper, fs::Permissions::from_mode(0o700))?;
        let identity = if synthetic {
            Value::Null
        } else {
            let response = control::client(&paths.state_dir, "auth.status", json!({})).await?;
            ensure!(
                response.get("error").is_none(),
                "uninstall auth status unavailable"
            );
            public_identity(&response["result"])?
        };
        journal = json!({"schema":SCHEMA,"phase":"prepared","operationId":Uuid::new_v4(),"drainKey":Uuid::new_v4(),"receipt":receipt,"receiptSha256":state::json_digest(&receipt),"receiptFileSha256":digest_file(&receipt_path)?,"paths":owned["paths"],"inventories":owned["inventories"],"helper":helper,"helperSha256":digest_file(&bootstrap)?,"expectedIdentity":identity,"maintenanceBinary":target.join("bin/loomex-runner"),"maintenanceSha256":digest_file(&target.join("bin/loomex-runner"))?,"cleanup":{"moved":[],"deletingStarted":[]}});
        journal["fenceJournalSha256"] = json!(state::json_digest(&journal));
        save(&paths, &journal)?;
        select_activation(
            &args,
            Uuid::parse_str(journal["operationId"].as_str().unwrap())?,
        );
        fault("AFTER_PREPARED")?;
    }
    validate_journal(&paths, &journal)?;
    select_activation(
        &args,
        Uuid::parse_str(journal["operationId"].as_str().unwrap())?,
    );
    if journal["stopEvidence"]["request"] == "unconfirmed" {
        dispatch_activation(&args, true);
    }
    if !journal["recovery"].is_null() {
        ensure!(
            recover
                && args.expected_old_journal_sha256.as_deref()
                    == journal["recovery"]["oldJournalSha256"].as_str(),
            "uninstall recovery requires the same reviewed old journal digest"
        );
        let release = fs::canonicalize(
            args.release
                .as_ref()
                .context("uninstall recovery release required")?,
        )?;
        let manifest = read_manifest(&release)?;
        bootstrap_preflight::verify_artifact(&release, &manifest, &args).await?;
        ensure!(
            release.to_string_lossy().as_ref()
                == journal["recovery"]["releasePath"].as_str().unwrap_or("")
                && digest_file(&release.join("manifest.json"))?
                    == journal["recovery"]["releaseManifestSha256"]
                && digest_file(&std::env::current_exe()?)? == manifest["bootstrap"]["sha256"],
            "uninstall recovery release changed"
        );
        let original = PathBuf::from(
            journal["recovery"]["originalJournal"]
                .as_str()
                .context("original uninstall evidence missing")?,
        );
        ensure!(
            original
                == paths.state_dir.join(format!(
                    "bootstrap-uninstall-original-{}.json",
                    journal["recovery"]["oldJournalSha256"].as_str().unwrap()
                ))
                && digest_file(&original)? == journal["recovery"]["oldJournalSha256"],
            "original uninstall evidence changed"
        );
        validate_adopted_replacement(&paths, &args, &journal)?;
        let intent = PathBuf::from(
            journal["recovery"]["releaseIntent"]
                .as_str()
                .context("recovery release intent missing")?,
        );
        ensure!(
            recovery_intent_path_matches(&paths, &journal, &intent)
                && digest_file(&intent)? == journal["recovery"]["releaseIntentSha256"],
            "uninstall recovery release intent changed"
        );
        if !matches!(journal["phase"].as_str(), Some("cleanup" | "terminal")) {
            inventory(
                Path::new(journal["recovery"]["payloadPath"].as_str().unwrap()),
                manifest["payload"]["files"]
                    .as_array()
                    .context("recovery inventory missing")?,
            )?;
        }
    }
    if matches!(
        journal["phase"].as_str(),
        Some("prepared" | "idle_verified")
    ) || (journal["phase"] == "stop_intent" && journal["stopEvidence"]["request"] == "prepared")
    {
        qualify_before_effects(&paths)?;
    }
    // A fresh helper outside the payload must own cleanup; deleting a running
    // installed bootstrap would invalidate the in-use proof and retry route.
    if journal["recovery"].is_null() && !synthetic {
        let helper = validate_helper(&paths, &journal)?;
        if fs::canonicalize(std::env::current_exe()?)? != fs::canonicalize(&helper)? {
            let error = std::process::Command::new(helper)
                .args(std::env::args_os().skip(1))
                .exec();
            return Err(error.into());
        }
    }
    let id = Uuid::parse_str(journal["operationId"].as_str().unwrap())?;
    lifecycle::begin_uninstall_fence_locked(
        &paths,
        id,
        journal["fenceJournalSha256"].as_str().unwrap(),
    )?;
    let mut stopped_guard = None;
    if journal["phase"] == "prepared" && !synthetic && label_observation(&paths).await?.is_none() {
        // This is fresh absence admission, never an invented idle/drain proof.
        // The receipt, owned payload and native identity remain bound while the
        // singleton excludes both a daemon and another maintenance process.
        let guard = verify_stopped(&paths, &journal, false).await?;
        qualify_before_effects(&paths)?;
        let agent_sha = digest_file(&paths.launch_agents_dir.join("app.loomex.runner.plist"))?;
        let native = invoke_maintenance(&paths, &journal, &guard, true, false, &args).await?;
        dispatch_activation(&args, false);
        fault("BEFORE_PREPARED_STOPPED")?;
        checkpoint_prepared_stopped(&paths, &mut journal, native, agent_sha)?;
        fault("AFTER_PREPARED_STOPPED")?;
        stopped_guard = Some(guard);
    }
    let admission_phase = journal["phase"].as_str().unwrap().to_owned();
    require_initial_admission(&admission_phase,async {
        qualify_before_effects(&paths)?;
        if !synthetic {
            let marker = paths.state_dir.join("drain.json");
            if marker.exists() {
                let existing: Value = serde_json::from_slice(&regular_bytes(&marker)?)?;
                ensure!(
                    existing["idempotencyKey"] == journal["drainKey"],
                    "uninstall drain identity mismatch"
                );
            } else {
                dispatch_activation(&args,true);
                let result = control::client(
                    &paths.state_dir,
                    "daemon.drain",
                    json!({"idempotencyKey":journal["drainKey"]}),
                )
                .await?;
                dispatch_activation(&args,false);
                ensure!(
                    result.get("error").is_none() && result["result"]["draining"] == true,
                    "uninstall drain rejected"
                );
            }
            let status = control::client(&paths.state_dir, "status.get", json!({})).await?;
            if status.get("error").is_none() && status["result"]["activeJobs"].as_u64().is_some_and(|v| v > 0) {
                return Err(PendingActivation.into());
            }
            ensure!(
                status.get("error").is_none()
                    && status["result"]["activeJobs"] == 0
                    && status["result"]["draining"] == true
                    && status["result"]["version"] == journal["receipt"]["version"],
                "uninstall deferred while runner jobs remain or identity is unconfirmed"
            );
            let fresh_auth = control::client(&paths.state_dir, "auth.status", json!({})).await?;
            ensure!(
                fresh_auth.get("error").is_none()
                    && public_identity(&fresh_auth["result"])?["installationId"]
                        == journal["expectedIdentity"]["installationId"],
                "uninstall authentication identity changed"
            );
            journal["stopEvidence"] = json!({"pid":label_observation(&paths).await?.context("runner service disappeared before stop intent")?,"launchAgentSha256":digest_file(&paths.launch_agents_dir.join("app.loomex.runner.plist"))?});
        }
        journal["phase"] = json!("idle_verified");
        save(&paths, &journal)?;
        fault("AFTER_IDLE_VERIFIED")?;
        Ok(())
    }).await?;
    checkpoint_idle_stop_intent(&paths, &mut journal, synthetic)?;
    if journal["phase"] == "stop_intent" && journal["stopEvidence"]["request"] == "prepared" {
        let mut dispatch = !synthetic;
        if !synthetic {
            match label_observation(&paths).await? {
                None => dispatch = false,
                Some(pid) => {
                    ensure!(
                        Some(i64::from(pid)) == journal["stopEvidence"]["pid"].as_i64(),
                        "uninstall prepared stop service changed"
                    );
                    let marker: Value = serde_json::from_slice(&regular_bytes(
                        &paths.state_dir.join("drain.json"),
                    )?)?;
                    ensure!(
                        marker["idempotencyKey"] == journal["drainKey"]
                            && digest_file(
                                &paths.launch_agents_dir.join("app.loomex.runner.plist")
                            )? == journal["stopEvidence"]["launchAgentSha256"],
                        "uninstall prepared stop binding changed"
                    );
                    let fresh = control::client(&paths.state_dir, "status.get", json!({})).await?;
                    ensure!(
                        fresh.get("error").is_none()
                            && fresh["result"]["activeJobs"] == 0
                            && fresh["result"]["draining"] == true
                            && fresh["result"]["version"] == journal["receipt"]["version"],
                        "uninstall prepared stop requires fresh idle proof"
                    );
                    let auth = control::client(&paths.state_dir, "auth.status", json!({})).await?;
                    ensure!(
                        auth.get("error").is_none()
                            && public_identity(&auth["result"])?["installationId"]
                                == journal["expectedIdentity"]["installationId"],
                        "uninstall prepared stop authentication changed"
                    );
                }
            }
        }
        // Persist possible dispatch before spawning. Only a definitive spawn
        // refusal restores prepared; an uncertain request is observation-only.
        journal["stopEvidence"]["request"] = json!("unconfirmed");
        save(&paths, &journal)?;
        dispatch_activation(&args, true);
        if dispatch {
            let uid = unsafe { libc::geteuid() };
            let mut command = tokio::process::Command::new("/bin/launchctl");
            command
                .arg("bootout")
                .arg(format!("gui/{uid}/app.loomex.runner"))
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .kill_on_drop(true);
            let mut child = match command.spawn() {
                Ok(child) => child,
                Err(error) => {
                    journal["stopEvidence"]["request"] = json!("prepared");
                    save(&paths, &journal)?;
                    dispatch_activation(&args, false);
                    return Err(error.into());
                }
            };
            tokio::time::timeout(std::time::Duration::from_secs(8), child.wait())
                .await
                .context("uninstall stop request unconfirmed; resume observation")??;
        }
        fault("AFTER_STOP_REQUEST")?;
    }
    // Stopped retries and uncertain stop requests observe fresh OS/singleton
    // facts without contacting the socket or repeating an uncertain bootout.
    let guard = match stopped_guard {
        Some(guard) => guard,
        None => verify_stopped(&paths, &journal, synthetic).await?,
    };
    dispatch_activation(&args, false);
    if journal["phase"] == "stop_intent" {
        journal["phase"] = json!("stopped");
        save(&paths, &journal)?;
        fault("AFTER_STOPPED")?;
    }
    if journal["phase"] == "stopped" {
        if journal["stateEntries"].is_null() {
            journal["stateEntries"] = capture_state_entries(&paths)?;
            save(&paths, &journal)?;
        }
        if !synthetic {
            let native = invoke_maintenance(&paths, &journal, &guard, true, false, &args).await?;
            dispatch_activation(&args, false);
            let absent = record_native_identity(&mut journal, native)?;
            save(&paths, &journal)?;
            if !absent {
                let result =
                    invoke_maintenance(&paths, &journal, &guard, false, false, &args).await?;
                dispatch_activation(&args, false);
                ensure!(
                    result["identity"]["installationId"]
                        == journal["expectedIdentity"]["installationId"]
                        && (journal["expectedIdentity"]["deviceId"].is_null()
                            || result["identity"]["deviceId"]
                                == journal["expectedIdentity"]["deviceId"]),
                    "uninstall revocation identity changed"
                );
                ensure!(
                    result["remoteRevocation"] == "confirmed"
                        || (result["remoteRevocation"] == "not_required"
                            && result["identity"]["deviceId"].is_null()),
                    "uninstall credential revocation remains unverified"
                );
                journal["expectedIdentity"] = result["identity"].clone();
                journal["remoteRevocation"] = result["remoteRevocation"].clone();
                journal["revocationResult"] = result;
            }
        }
        journal["phase"] = json!("revoked");
        save(&paths, &journal)?;
        fault("AFTER_REVOKED")?;
    }
    if journal["phase"] == "revoked" && journal["protectedStoreRemoved"] != true {
        if !synthetic {
            let result = invoke_maintenance(&paths, &journal, &guard, false, true, &args).await?;
            dispatch_activation(&args, false);
            ensure!(
                result["remoteRevocation"] == journal["remoteRevocation"]
                    && result["protectedStoreRemoved"] == true,
                "uninstall native item removal remains pending"
            );
        }
        journal["protectedStoreRemoved"] = json!(true);
        save(&paths, &journal)?;
        fault("AFTER_NATIVE_REMOVAL")?;
    }
    cleanup(&paths, &mut journal, &guard, synthetic).await
}

struct RecoveryScratch(PathBuf);
impl Drop for RecoveryScratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn valid_sha(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}
fn recovery_stage_path_matches(paths: &lifecycle::Paths, journal: &Value, stage: &Path) -> bool {
    let Some(old) = journal["recovery"]["oldJournalSha256"]
        .as_str()
        .filter(|v| valid_sha(v))
    else {
        return false;
    };
    let Some(manifest) = journal["recovery"]["releaseManifestSha256"]
        .as_str()
        .filter(|v| valid_sha(v))
    else {
        return false;
    };
    stage == paths.state_dir.join(format!("uninstall-recovery-{old}"))
        || stage
            == paths
                .state_dir
                .join(format!("uninstall-recovery-{old}-{manifest}"))
}
fn recovery_intent_path_matches(paths: &lifecycle::Paths, journal: &Value, intent: &Path) -> bool {
    let Some(old) = journal["recovery"]["oldJournalSha256"]
        .as_str()
        .filter(|v| valid_sha(v))
    else {
        return false;
    };
    let Some(manifest) = journal["recovery"]["releaseManifestSha256"]
        .as_str()
        .filter(|v| valid_sha(v))
    else {
        return false;
    };
    intent
        == paths
            .state_dir
            .join(format!("bootstrap-uninstall-recovery-release-{old}.json"))
        || intent
            == paths.state_dir.join(format!(
                "bootstrap-uninstall-recovery-replacement-{old}-{manifest}.json"
            ))
}
fn validate_replacement(
    paths: &lifecycle::Paths,
    args: &Arguments,
    old: &Value,
    old_digest: &str,
    id: Uuid,
    intent: &Path,
) -> Result<()> {
    ensure!(
        old["schema"] == OLD_SCHEMA
            && old["phase"] == "prepared"
            && digest_file(&paths.state_dir.join("bootstrap-uninstall.json"))? == old_digest,
        "candidate replacement requires unchanged historical prepared journal"
    );
    ensure!(
        args.replace_pre_adoption_candidate
            && args.expected_recovery_intent_sha256.as_deref()
                == Some(digest_file(intent)?.as_str()),
        "reviewed recovery intent digest mismatch"
    );
    let operation: lifecycle::Operation =
        state::read_json(&paths.state_dir.join("lifecycle-operation.json"))?;
    ensure!(
        operation.id == id
            && operation
                .uninstall_fence
                .as_ref()
                .is_some_and(|f| f.journal_sha256 == old_digest),
        "candidate replacement fence changed"
    );
    // A retained request can mean a child is still doing native IO. Neither a
    // missing socket nor a v1 journal proves that such work never dispatched.
    ensure!(
        !paths
            .state_dir
            .join(format!("uninstall-maintenance-{id}.json"))
            .try_exists()?,
        "candidate replacement maintenance history is uncertain"
    );
    let previous: Value = serde_json::from_slice(&regular_bytes(intent)?)?;
    ensure!(
        previous["schema"] == "app.loomex.runner.uninstall-recovery-release/v1"
            && previous["operationId"] == id.to_string()
            && previous["oldJournalSha256"] == old_digest
            && previous["stage"]
                == paths
                    .state_dir
                    .join(format!("uninstall-recovery-{old_digest}"))
                    .to_string_lossy()
                    .as_ref()
            && previous["manifestSha256"].as_str().is_some_and(valid_sha)
            && previous["releasePath"]
                .as_str()
                .is_some_and(|p| Path::new(p).is_absolute()),
        "candidate replacement original intent invalid"
    );
    qualify_before_effects(paths)?;
    Ok(())
}

fn recovery_release_selection(
    paths: &lifecycle::Paths,
    args: &Arguments,
    id: Uuid,
    old_digest: &str,
    manifest_sha: &str,
    release: &Path,
) -> (PathBuf, Value) {
    let replacing = args.replace_pre_adoption_candidate;
    let stage = paths.state_dir.join(if replacing {
        format!("uninstall-recovery-{old_digest}-{manifest_sha}")
    } else {
        format!("uninstall-recovery-{old_digest}")
    });
    let intent = paths.state_dir.join(if replacing {
        format!("bootstrap-uninstall-recovery-replacement-{old_digest}-{manifest_sha}.json")
    } else {
        format!("bootstrap-uninstall-recovery-release-{old_digest}.json")
    });
    let mut value = json!({"schema":"app.loomex.runner.uninstall-recovery-release/v1","operationId":id,"oldJournalSha256":old_digest,"releasePath":release,"manifestSha256":manifest_sha,"stage":stage});
    if replacing {
        value["supersededIntent"] = json!(paths.state_dir.join(format!(
            "bootstrap-uninstall-recovery-release-{old_digest}.json"
        )));
        value["supersededIntentSha256"] = json!(args.expected_recovery_intent_sha256);
    }
    (intent, value)
}
fn validate_retained_selection(intent: &Path, expected: &Value) -> Result<()> {
    if intent.try_exists()? {
        ensure!(
            regular_bytes(intent)? == serde_json::to_vec(expected)?,
            "retained recovery candidate binding differs; explicit reviewed replacement is required"
        );
    }
    Ok(())
}

fn validate_adopted_replacement(
    paths: &lifecycle::Paths,
    args: &Arguments,
    journal: &Value,
) -> Result<()> {
    if !args.replace_pre_adoption_candidate {
        return Ok(());
    }
    let old = journal["recovery"]["oldJournalSha256"]
        .as_str()
        .context("replacement historical binding missing")?;
    let original = paths
        .state_dir
        .join(format!("bootstrap-uninstall-recovery-release-{old}.json"));
    ensure!(
        args.expected_recovery_intent_sha256.as_deref() == Some(digest_file(&original)?.as_str()),
        "replacement original intent digest changed"
    );
    let selected = PathBuf::from(
        journal["recovery"]["releaseIntent"]
            .as_str()
            .context("replacement selected intent missing")?,
    );
    ensure!(
        selected != original && recovery_intent_path_matches(paths, journal, &selected),
        "replacement was not adopted by this operation"
    );
    let value: Value = serde_json::from_slice(&regular_bytes(&selected)?)?;
    ensure!(
        value["supersededIntent"].as_str() == Some(original.to_string_lossy().as_ref())
            && value["supersededIntentSha256"].as_str()
                == args.expected_recovery_intent_sha256.as_deref()
            && value["operationId"] == journal["operationId"],
        "replacement selection evidence changed"
    );
    Ok(())
}

pub(super) fn recovery_ownership(paths: &lifecycle::Paths) -> Value {
    let inspect = || -> Result<Value> {
        let snapshot = lifecycle::status(paths).unwrap_or_else(|_| json!({"ownershipValid":false}));
        let ownership_valid = snapshot["ownershipValid"] == true;
        let operation_id = snapshot["operation"]["id"]
            .as_str()
            .and_then(|v| Uuid::parse_str(v).ok())
            .map(|v| v.to_string());
        for name in [
            "bootstrap-uninstall.json",
            "bootstrap-uninstall-terminal.json",
        ] {
            let path = paths.state_dir.join(name);
            if !path.try_exists()? {
                continue;
            }
            let journal: Value = serde_json::from_slice(&regular_bytes(&path)?)?;
            let old = journal["schema"] == OLD_SCHEMA;
            let digest = digest_file(&path)?;
            let intent = paths.state_dir.join(format!(
                "bootstrap-uninstall-recovery-release-{digest}.json"
            ));
            let intent_digest = if old && intent.try_exists()? {
                Some(digest_file(&intent)?)
            } else {
                None
            };
            let phase = journal["phase"]
                .as_str()
                .filter(|v| {
                    matches!(
                        *v,
                        "prepared"
                            | "idle_verified"
                            | "stop_intent"
                            | "stopped"
                            | "revoked"
                            | "cleanup"
                            | "terminal"
                    )
                })
                .unwrap_or("unknown");
            let original_owner =
                journal["schema"] == SCHEMA && journal["recovery"].is_null() && phase != "prepared";
            let prepared_current =
                journal["schema"] == SCHEMA && journal["recovery"].is_null() && phase == "prepared";
            return Ok(
                json!({"status":if ownership_valid {"pending"} else {"blocked"},"owner":"bootstrap_uninstall","operationId":journal["operationId"].as_str().and_then(|v| Uuid::parse_str(v).ok()).map(|v| v.to_string()).or(operation_id),
                "phase":phase,"journalSha256":digest,"recoveryIntentSha256":intent_digest,
                "nextAction":if !ownership_valid {"inspect_protected_ownership"} else if original_owner {"resume_original_uninstall_owner"} else if old || prepared_current {"recover_uninstall"} else {"resume_bootstrap_uninstall"},
                "reasonCode":if !ownership_valid {"OWNERSHIP_UNCONFIRMED"} else if old {"HISTORICAL_UNINSTALL_PENDING"} else {"UNINSTALL_PENDING"}}),
            );
        }
        ensure!(ownership_valid, "invalid lifecycle ownership");
        let record = snapshot["ownership"]
            .as_array()
            .and_then(|v| v.iter().find(|v| v["pending"] == true));
        Ok(match record {
            Some(record) => {
                json!({"status":"pending","owner":record["owner"],"operationId":operation_id,"phase":record["phase"],"journalSha256":record["sha256"],"nextAction":snapshot["nextAction"],"reasonCode":"LIFECYCLE_OPERATION_PENDING"})
            }
            None => {
                json!({"status":"none","operationId":null,"phase":null,"journalSha256":null,"nextAction":"none","reasonCode":"NO_PENDING_RECOVERY"})
            }
        })
    };
    inspect().unwrap_or_else(|_| json!({"status":"blocked","operationId":null,"phase":null,"journalSha256":null,"nextAction":"inspect_protected_ownership","reasonCode":"OWNERSHIP_UNCONFIRMED"}))
}

// Read-only candidate/historical binding admission. A successful preflight is
// never native authorization; the mutator repeats every check under its lock.
pub(super) async fn recovery_preflight(
    paths: &lifecycle::Paths,
    args: &Arguments,
    release: &Path,
    manifest: &Value,
    payload: &Path,
) -> Result<bool> {
    let journal_path = paths.state_dir.join("bootstrap-uninstall.json");
    let terminal_path = paths.state_dir.join("bootstrap-uninstall-terminal.json");
    let path = if journal_path.try_exists()? {
        journal_path
    } else if terminal_path.try_exists()? {
        terminal_path
    } else {
        return Ok(false);
    };
    let journal: Value = serde_json::from_slice(&regular_bytes(&path)?)?;
    let expected_path = args.expected_release_path.as_deref().unwrap_or(release);
    ensure!(
        expected_path.is_absolute(),
        "recovery release path must be absolute"
    );
    let release_sha = digest_file(&release.join("manifest.json"))?;
    ensure!(
        digest_file(&std::env::current_exe()?)? == manifest["bootstrap"]["sha256"],
        "recovery requires release-bound bootstrap"
    );
    if journal["schema"] == OLD_SCHEMA
        || (journal["schema"] == SCHEMA && journal["recovery"].is_null())
    {
        let current_v2 = journal["schema"] == SCHEMA;
        if current_v2 && journal["phase"] != "prepared" {
            return Err(OriginalUninstallOwnerRequired.into());
        }
        let digest = digest_file(&path)?;
        ensure!(
            args.expected_old_journal_sha256.as_deref() == Some(digest.as_str())
                && journal["phase"] == "prepared",
            "historical recovery journal binding mismatch"
        );
        lifecycle::require_terminal_before_uninstall(paths)?;
        validate_owned_installation(paths, &journal["receipt"], &journal_owned(&journal), false)?;
        validate_helper(paths, &journal)?;
        ensure!(
            serde_json::from_slice::<Value>(&regular_bytes(
                &paths.state_dir.join("install-receipt.json")
            )?)? == journal["receipt"],
            "old uninstall receipt changed"
        );
        if current_v2 {
            validate_journal(paths, &journal)?;
            validated_current_identity(&journal)?;
        } else {
            prior_identity(paths)?;
        }
        qualify_before_effects(paths)?;
        let intent = paths.state_dir.join(format!(
            "bootstrap-uninstall-recovery-release-{digest}.json"
        ));
        if args.replace_pre_adoption_candidate {
            let operation: lifecycle::Operation =
                state::read_json(&paths.state_dir.join("lifecycle-operation.json"))?;
            validate_replacement(paths, args, &journal, &digest, operation.id, &intent)?;
        }
        let operation: Option<lifecycle::Operation> = if paths
            .state_dir
            .join("lifecycle-operation.json")
            .try_exists()?
        {
            Some(state::read_json(
                &paths.state_dir.join("lifecycle-operation.json"),
            )?)
        } else {
            None
        };
        let selected_id = if current_v2 {
            Uuid::parse_str(
                journal["operationId"]
                    .as_str()
                    .context("current uninstall operation missing")?,
            )?
        } else {
            operation
                .as_ref()
                .filter(|op| op.uninstall_fence.is_some())
                .map(|op| op.id)
                .unwrap_or(Uuid::nil())
        };
        ensure!(
            !paths
                .state_dir
                .join(format!("uninstall-maintenance-{selected_id}.json"))
                .try_exists()?,
            "prepared adoption maintenance history is uncertain"
        );
        let (selected_intent, expected) = recovery_release_selection(
            paths,
            args,
            selected_id,
            &digest,
            &release_sha,
            expected_path,
        );
        validate_retained_selection(&selected_intent, &expected)?;
        validate_recovery_candidate(args, &journal, manifest, payload).await?;
    } else {
        validate_adopted_replacement(paths, args, &journal)?;
        if journal["phase"] != "terminal" {
            validate_journal(paths, &journal)?;
        }
        ensure!(
            journal["schema"] == SCHEMA
                && args.expected_old_journal_sha256.as_deref()
                    == journal["recovery"]["oldJournalSha256"].as_str()
                && journal["recovery"]["releasePath"].as_str()
                    == Some(expected_path.to_string_lossy().as_ref())
                && journal["recovery"]["releaseManifestSha256"] == release_sha,
            "recovery candidate historical binding mismatch"
        );
        let original = paths.state_dir.join(format!(
            "bootstrap-uninstall-original-{}.json",
            args.expected_old_journal_sha256.as_deref().unwrap_or("")
        ));
        ensure!(
            digest_file(&original)?.as_str()
                == args.expected_old_journal_sha256.as_deref().unwrap_or(""),
            "historical recovery evidence changed"
        );
        let intent = PathBuf::from(
            journal["recovery"]["releaseIntent"]
                .as_str()
                .context("recovery intent missing")?,
        );
        ensure!(
            recovery_intent_path_matches(paths, &journal, &intent)
                && digest_file(&intent)? == journal["recovery"]["releaseIntentSha256"],
            "recovery intent changed"
        );
    }
    Ok(true)
}

async fn validate_recovery_candidate(
    args: &Arguments,
    old: &Value,
    manifest: &Value,
    payload: &Path,
) -> Result<SigningTransition> {
    let version = manifest["version"]
        .as_str()
        .context("recovery version missing")?;
    let numeric = |v: &str| -> Result<Vec<u64>> {
        let parts = v
            .split('.')
            .map(|s| s.parse::<u64>().context("invalid recovery version"))
            .collect::<Result<Vec<_>>>()?;
        ensure!(parts.len() == 3, "invalid recovery version");
        Ok(parts)
    };
    ensure!(
        numeric(version)?
            >= numeric(
                old["receipt"]["version"]
                    .as_str()
                    .context("old version missing")?
            )?,
        "uninstall recovery release downgrade refused"
    );
    let project: Value =
        serde_json::from_slice(&regular_bytes(&payload.join("metadata/project.json"))?)?;
    ensure!(
        project["project"] == "loomex-runner"
            && project["version"] == version
            && project["platform"] == "darwin-arm64",
        "recovery project metadata mismatch"
    );
    if args.preview_api_origin.is_some() {
        validate_preview_identity(
            manifest,
            option_env!("LOOMEX_PREVIEW_SOURCE_REVISION"),
            env!("CARGO_PKG_VERSION"),
        )?;
    }
    let candidate = payload.join("bin/loomex-runner");
    let previous = PathBuf::from(
        old["receipt"]["versionPath"]
            .as_str()
            .context("old target missing")?,
    )
    .join("bin/loomex-runner");
    let candidate_requirement = if manifest["developmentOnly"] == true {
        bootstrap_preflight::development_signing(payload)?
    } else {
        for name in ["loomex", "loomex-lifecycle-bootstrap"] {
            signing_requirement(&payload.join("bin").join(name))?;
        }
        signing_requirement(&candidate)?
    };
    if manifest["developmentOnly"] == true {
        let candidate_origin =
            development_origin(payload, manifest, args, option_env!("LOOMEX_API_ORIGIN"))?;
        ensure!(
            candidate_origin.as_deref() == old["receipt"]["developmentApiOrigin"].as_str(),
            "recovery origin differs from owned receipt"
        );
    } else {
        ensure!(
            old["receipt"]["developmentApiOrigin"].is_null(),
            "production recovery origin mismatch"
        );
    }
    let previous_requirement = signing_requirement(&previous)?;
    let transition = if args.work_action.is_some() {
        work_signing_transition(
            previous_requirement.as_deref(),
            candidate_requirement.as_deref(),
            digest_file(&previous)? == digest_file(&candidate)?,
            args.authorize_keychain_transition,
        )?
    } else {
        signing_transition(
            previous_requirement.as_deref(),
            candidate_requirement.as_deref(),
            digest_file(&previous)? == digest_file(&candidate)?,
            args.authorize_keychain_transition,
        )?
    };
    // Both inspections are non-authorizing. Foreground native authorization
    // runs only after the mutator has adopted the qualified candidate binding.
    Ok(transition)
}

fn checkpoint_prepared_stopped(
    paths: &lifecycle::Paths,
    journal: &mut Value,
    native: Value,
    agent_sha: String,
) -> Result<()> {
    ensure!(
        journal["phase"] == "prepared",
        "stopped admission requires prepared journal"
    );
    qualify_before_effects(paths)?;
    record_native_identity(journal, native)?;
    journal["phase"] = json!("stopped");
    journal["stopEvidence"] = json!({"launchAgentSha256":agent_sha,"admission":"service_absence_verified","request":"not_dispatched"});
    save(paths, journal)
}

// Candidate qualification belongs before any durable binding. Keeping this
// boundary explicit also makes failure ordering testable without native IO.
async fn adopt_recovery_binding<F>(
    paths: &lifecycle::Paths,
    id: Uuid,
    old_digest: &str,
    intent: &Path,
    release_intent: &Value,
    qualification: F,
) -> Result<()>
where
    F: std::future::Future<Output = Result<()>>,
{
    qualification.await?;
    lifecycle::begin_uninstall_fence_locked(paths, id, old_digest)?;
    immutable_copy(intent, &serde_json::to_vec(release_intent)?)?;
    Ok(())
}

async fn recover_old(paths: &lifecycle::Paths, args: &Arguments, old: Value) -> Result<Value> {
    let old_path = paths.state_dir.join("bootstrap-uninstall.json");
    let bytes = regular_bytes(&old_path)?;
    let old_digest = state::digest(&bytes);
    ensure!(
        serde_json::from_slice::<Value>(&bytes)? == old,
        "historical uninstall journal changed"
    );
    ensure!(
        args.expected_old_journal_sha256.as_deref() == Some(old_digest.as_str()),
        "reviewed old uninstall journal digest mismatch"
    );
    ensure!(
        (old["schema"] == OLD_SCHEMA || (old["schema"] == SCHEMA && old["recovery"].is_null()))
            && matches!(old["phase"].as_str(), Some("prepared" | "revoked")),
        "unsupported old uninstall state"
    );
    // A v1 revoked record has no binding proving remote revocation. Never
    // reinterpret it as a successful modern credential cleanup checkpoint.
    ensure!(
        old["phase"] == "prepared",
        "old revoked journal lacks bound native cleanup proof; recovery requires explicit external resolution"
    );
    validate_owned_installation(paths, &old["receipt"], &journal_owned(&old), false)?;
    validate_helper(paths, &old)?;
    let receipt_path = paths.state_dir.join("install-receipt.json");
    ensure!(
        serde_json::from_slice::<Value>(&regular_bytes(&receipt_path)?)? == old["receipt"],
        "old uninstall receipt changed"
    );
    qualify_before_effects(paths)?;
    let current_v2 = old["schema"] == SCHEMA;
    if current_v2 {
        validate_journal(paths, &old)?;
    }
    let identity = if current_v2 {
        validated_current_identity(&old)?
    } else {
        prior_identity(paths)?
    };
    let release = fs::canonicalize(args.release.as_ref().context("recovery release required")?)?;
    let manifest = read_manifest(&release)?;
    bootstrap_preflight::verify_artifact(&release, &manifest, args).await?;
    ensure!(
        digest_file(&std::env::current_exe()?)? == manifest["bootstrap"]["sha256"],
        "recovery must run the release-bound bootstrap"
    );
    let version = manifest["version"].as_str().unwrap();
    let old_version = old["receipt"]["version"]
        .as_str()
        .context("old receipt version missing")?;
    let numeric = |v: &str| -> Result<Vec<u64>> {
        v.split('.')
            .map(|s| s.parse::<u64>().context("invalid recovery version"))
            .collect()
    };
    ensure!(
        numeric(version)?.len() == 3 && numeric(version)? >= numeric(old_version)?,
        "uninstall recovery release downgrade refused"
    );
    let operation: Option<lifecycle::Operation> =
        if paths.state_dir.join("lifecycle-operation.json").exists() {
            Some(state::read_json(
                &paths.state_dir.join("lifecycle-operation.json"),
            )?)
        } else {
            None
        };
    let id = if current_v2 {
        Uuid::parse_str(
            old["operationId"]
                .as_str()
                .context("current uninstall operation missing")?,
        )?
    } else {
        operation
            .as_ref()
            .filter(|op| op.uninstall_fence.is_some())
            .map(|op| op.id)
            .unwrap_or_else(Uuid::new_v4)
    };
    select_activation(args, id);
    let fence_digest = if current_v2 {
        old["fenceJournalSha256"]
            .as_str()
            .context("current uninstall fence missing")?
            .to_owned()
    } else {
        old_digest.clone()
    };
    ensure!(
        !paths
            .state_dir
            .join(format!("uninstall-maintenance-{id}.json"))
            .try_exists()?,
        "prepared adoption maintenance history is uncertain"
    );
    // Validate in disposable scratch, including every package binding and the
    // installed-to-candidate signer transition, before publishing any intent.
    let scratch = RecoveryScratch(
        std::env::temp_dir().join(format!("loomex-uninstall-qualification-{}", Uuid::new_v4())),
    );
    let original_intent = paths.state_dir.join(format!(
        "bootstrap-uninstall-recovery-release-{old_digest}.json"
    ));
    let manifest_sha = digest_file(&release.join("manifest.json"))?;
    work::require_recovery_binding(paths, &old_digest, &release, &manifest)?;
    let replacement = args.replace_pre_adoption_candidate;
    let (intent, release_intent) =
        recovery_release_selection(paths, args, id, &old_digest, &manifest_sha, &release);
    let stage = PathBuf::from(release_intent["stage"].as_str().unwrap());
    validate_retained_selection(&intent, &release_intent)?;
    if replacement {
        validate_replacement(paths, args, &old, &old_digest, id, &original_intent)?;
    }
    adopt_recovery_binding(paths, id, &fence_digest, &intent, &release_intent, async {
        let payload =
            bootstrap_preflight::extract_artifact(&release, &manifest, &scratch.0).await?;
        bootstrap_preflight::verify_envelope(&release, &payload, &manifest)?;
        validate_recovery_candidate(args, &old, &manifest, &payload).await?;
        ensure!(
            digest_file(&old_path)? == old_digest,
            "historical uninstall journal changed during qualification"
        );
        if replacement {
            validate_replacement(paths, args, &old, &old_digest, id, &original_intent)?;
        }
        Ok(())
    })
    .await?;
    if stage.exists() {
        inventory(
            &stage,
            manifest["payload"]["files"]
                .as_array()
                .context("release inventory missing")?,
        )?;
    } else {
        // Scratch may be on a different filesystem: copy into a private owned
        // stage, reverify, then publish with one same-filesystem rename.
        let publishing = RecoveryScratch(paths.state_dir.join(format!(
            ".uninstall-recovery-stage-{}-{}",
            id,
            Uuid::new_v4()
        )));
        bootstrap_preflight::extract_artifact(&release, &manifest, &publishing.0).await?;
        fs::rename(&publishing.0, &stage)?;
        File::open(&paths.state_dir)?.sync_all()?;
    }
    let candidate = stage.join("bin/loomex-runner");
    if args.authorize_keychain_transition {
        credential_probe(&candidate, true).await?;
    }
    // Preserve the original journal bytes and helper unchanged. The private
    // lifecycle fence is durable before the old journal is superseded.
    let original = paths
        .state_dir
        .join(format!("bootstrap-uninstall-original-{old_digest}.json"));
    immutable_copy(&original, &bytes)?;
    let drain = paths.state_dir.join("drain.json");
    let drain_key = if current_v2 {
        Uuid::parse_str(
            old["drainKey"]
                .as_str()
                .context("current uninstall drain missing")?,
        )?
    } else if drain.exists() {
        let marker: Value = serde_json::from_slice(&regular_bytes(&drain)?)?;
        Uuid::parse_str(
            marker["idempotencyKey"]
                .as_str()
                .context("old uninstall drain ownership unconfirmed")?,
        )?
    } else {
        Uuid::new_v4()
    };
    let mut value = old;
    value["schema"] = json!(SCHEMA);
    value["phase"] = json!("prepared");
    value["operationId"] = json!(id);
    value["drainKey"] = json!(drain_key);
    value["fenceJournalSha256"] = json!(fence_digest);
    value["expectedIdentity"] = identity;
    value["receiptSha256"] = json!(state::json_digest(&value["receipt"]));
    value["receiptFileSha256"] = json!(digest_file(&receipt_path)?);
    value["maintenanceBinary"] = json!(candidate);
    value["maintenanceSha256"] = json!(digest_file(&candidate)?);
    value["cleanup"] = json!({"moved":[],"deletingStarted":[]});
    value["recovery"] = json!({"adoptedCurrent":current_v2,"originalJournal":original,"oldJournalSha256":old_digest,"releasePath":release,"releaseManifestSha256":digest_file(&release.join("manifest.json"))?,"payloadPath":stage,"files":manifest["payload"]["files"],"releaseIntent":intent,"releaseIntentSha256":digest_file(&intent)?});
    value["stopEvidence"] = json!({"launchAgentSha256":digest_file(&paths.launch_agents_dir.join("app.loomex.runner.plist"))?});
    if !current_v2 && label_observation(paths).await?.is_none() {
        value["phase"] = json!("stop_intent");
        value["recovery"]["adoptedStopped"] = json!(true);
    }
    save(paths, &value)?;
    fault("AFTER_RECOVERY_ADOPTION")?;
    Ok(value)
}

async fn cleanup(
    paths: &lifecycle::Paths,
    journal: &mut Value,
    _guard: &File,
    synthetic: bool,
) -> Result<()> {
    ensure!(
        matches!(journal["phase"].as_str(), Some("revoked" | "cleanup")),
        "uninstall cannot clean files before bound revocation"
    );
    if journal["cleanup"]["stateDeletingStarted"] != true {
        reject_unresolved_work(paths)?;
    }
    ensure!(
        synthetic || (revocation_satisfied(journal) && journal["protectedStoreRemoved"] == true),
        "uninstall bound credential cleanup is incomplete"
    );
    work::cleanup_resources(paths, journal)?;
    journal["phase"] = json!("cleanup");
    save(paths, journal)?;
    let owned = journal_owned(journal);
    let quarantine = paths.install_base.join("versions").join(format!(
        ".uninstall-{}",
        journal["operationId"].as_str().unwrap()
    ));
    if quarantine.exists() {
        ensure!(
            fs::symlink_metadata(&quarantine)?.is_dir()
                && !fs::symlink_metadata(&quarantine)?.file_type().is_symlink(),
            "unsafe uninstall quarantine"
        );
    } else {
        fs::create_dir(&quarantine)?;
        File::open(quarantine.parent().unwrap())?.sync_all()?;
    }
    for target in journal["paths"].as_array().unwrap().clone() {
        let source = PathBuf::from(target.as_str().unwrap());
        let destination = quarantine.join(source.file_name().unwrap());
        let expected = expected_files(&owned, &source)?;
        let moved = journal["cleanup"]["moved"]
            .as_array()
            .unwrap()
            .contains(&target);
        if source.exists() {
            ensure!(
                !moved && !destination.exists(),
                "ambiguous uninstall quarantine ownership"
            );
            lifecycle::prune_quarantine_inventory(&source, expected, false)?;
            if !synthetic {
                lifecycle::prune_in_use(&[source.clone()]).await?;
            }
            fs::rename(&source, &destination)?;
            File::open(source.parent().unwrap())?.sync_all()?;
            File::open(&quarantine)?.sync_all()?;
        } else {
            ensure!(
                moved || destination.exists(),
                "uninstall payload disappeared before quarantine checkpoint"
            );
        }
        if !moved {
            journal["cleanup"]["moved"]
                .as_array_mut()
                .unwrap()
                .push(target.clone());
            save(paths, journal)?;
        }
        if destination.exists() {
            let started = journal["cleanup"]["deletingStarted"]
                .as_array()
                .unwrap()
                .contains(&target);
            lifecycle::prune_quarantine_inventory(&destination, expected, started)?;
            if !started {
                journal["cleanup"]["deletingStarted"]
                    .as_array_mut()
                    .unwrap()
                    .push(target.clone());
                save(paths, journal)?;
            }
            if !synthetic {
                lifecycle::prune_in_use(&[destination.clone()]).await?;
            }
            lifecycle::prune_remove_quarantine_exact(&destination, expected)?;
            File::open(&quarantine)?.sync_all()?;
        }
    }
    if quarantine.exists() {
        fs::remove_dir(&quarantine)?;
    }
    fault("AFTER_PAYLOAD")?;
    if !journal["recovery"].is_null() {
        let stage = PathBuf::from(
            journal["recovery"]["payloadPath"]
                .as_str()
                .context("recovery payload missing")?,
        );
        ensure!(
            recovery_stage_path_matches(paths, journal, &stage),
            "unsafe recovery payload path"
        );
        if stage.exists() {
            let files = journal["recovery"]["files"]
                .as_array()
                .context("recovery inventory missing")?
                .clone();
            lifecycle::prune_quarantine_inventory(
                &stage,
                &files,
                journal["recovery"]["deletingStarted"] == true,
            )?;
            journal["recovery"]["deletingStarted"] = json!(true);
            save(paths, journal)?;
            lifecycle::prune_remove_quarantine_exact(&stage, &files)?;
        }
    }
    let agent = paths.launch_agents_dir.join("app.loomex.runner.plist");
    if agent.exists() {
        if !synthetic {
            ensure!(
                digest_file(&agent)? == journal["stopEvidence"]["launchAgentSha256"],
                "uninstall LaunchAgent changed"
            );
        }
        remove_regular(&agent)?;
    }
    lifecycle::remove_operation_resources_after_uninstall(paths)?;
    remove_state_entries(paths, journal)?;
    let socket = paths.state_dir.join("control.sock");
    if let Ok(meta) = fs::symlink_metadata(&socket) {
        ensure!(
            meta.file_type().is_socket() && meta.uid() == unsafe { libc::geteuid() },
            "unsafe uninstall socket"
        );
        fs::remove_file(&socket)?;
    }
    // daemon.lock is stable exclusion metadata. Retain its inode even after
    // cleanup; unlinking a locked pathname would allow a new cooperative owner.
    let current = paths.install_base.join("current");
    if current.is_symlink() {
        let link = fs::read_link(&current)?;
        let resolved = if link.is_absolute() {
            link
        } else {
            paths.install_base.join(link)
        };
        ensure!(
            resolved == PathBuf::from(journal["receipt"]["versionPath"].as_str().unwrap()),
            "uninstall current pointer changed"
        );
        fs::remove_file(&current)?;
    } else {
        ensure!(!current.exists(), "unsafe uninstall current pointer");
    }
    validate_helper(paths, journal)?;
    for name in ["install-receipt.json", "owned-versions.json"] {
        let path = paths.state_dir.join(name);
        if path.exists() {
            remove_regular(&path)?;
        }
    }
    fault("AFTER_RECEIPT_REMOVAL")?;
    let marker = paths.state_dir.join("bootstrap-uninstall-terminal.json");
    journal["phase"] = json!("terminal");
    state::write_json(&marker, journal)?;
    remove_regular(&paths.state_dir.join("bootstrap-uninstall.json"))?;
    fault("AFTER_JOURNAL_REMOVAL")?;
    remove_regular(&paths.state_dir.join("bootstrap-uninstall-helper"))?;
    fault("AFTER_HELPER_UNLINK")?;
    remove_terminal_fence(paths, journal)?;
    remove_regular(&marker)?;
    if !json_output_requested() {
        println!(
            "Removed inventoried runner files and resolved state. Stable lock metadata and unowned files were preserved."
        );
    }
    Ok(())
}

async fn finish_terminal(paths: &lifecycle::Paths, args: &Arguments, recover: bool) -> Result<()> {
    let marker = paths.state_dir.join("bootstrap-uninstall-terminal.json");
    let terminal: Value = serde_json::from_slice(&regular_bytes(&marker)?)?;
    if recover && terminal["recovery"].is_null() {
        return Err(OriginalUninstallOwnerRequired.into());
    }
    ensure!(
        terminal["schema"] == SCHEMA
            && terminal["phase"] == "terminal"
            && terminal["protectedStoreRemoved"] == true,
        "uninstall terminal marker invalid"
    );
    ensure!(
        !paths.state_dir.join("install-receipt.json").exists()
            && !paths.install_base.join("current").exists()
            && !paths.state_dir.join("owned-versions.json").exists(),
        "terminal uninstall namespace changed"
    );
    Uuid::parse_str(
        terminal["operationId"]
            .as_str()
            .context("terminal operation missing")?,
    )?;
    if !terminal["recovery"].is_null() {
        ensure!(
            recover
                && args.expected_old_journal_sha256.as_deref()
                    == terminal["recovery"]["oldJournalSha256"].as_str(),
            "terminal recovery requires reviewed release and old journal digest"
        );
        let release = fs::canonicalize(
            args.release
                .as_ref()
                .context("terminal recovery release missing")?,
        )?;
        let manifest = read_manifest(&release)?;
        bootstrap_preflight::verify_artifact(&release, &manifest, args).await?;
        ensure!(
            digest_file(&std::env::current_exe()?)? == manifest["bootstrap"]["sha256"]
                && digest_file(&release.join("manifest.json"))?
                    == terminal["recovery"]["releaseManifestSha256"],
            "terminal recovery release changed"
        );
    }
    validate_adopted_replacement(paths, args, &terminal)?;
    select_activation(
        args,
        Uuid::parse_str(terminal["operationId"].as_str().unwrap())?,
    );
    let synthetic = std::env::var_os("LOOMEX_INSTALL_TEST_MODE").is_some();
    let _guard = verify_stopped(paths, &terminal, synthetic).await?;
    let helper = paths.state_dir.join("bootstrap-uninstall-helper");
    if helper.exists() {
        validate_helper(paths, &terminal)?;
        remove_regular(&helper)?;
    }
    remove_terminal_fence(paths, &terminal)?;
    remove_regular(&marker)?;
    if !args.json {
        println!("Loomex runner is already uninstalled.");
    }
    Ok(())
}

fn revocation_satisfied(journal: &Value) -> bool {
    journal["remoteRevocation"] == "confirmed"
        || (journal["remoteRevocation"] == "not_required"
            && (!journal["expectedIdentity"].is_null() || journal["nativeAbsenceVerified"] == true)
            && journal["expectedIdentity"]["deviceId"].is_null()
            && journal["revocationResult"]["remoteRevocation"] == "not_required"
            && journal["revocationResult"]["identity"] == journal["expectedIdentity"])
}

fn remove_terminal_fence(paths: &lifecycle::Paths, journal: &Value) -> Result<()> {
    lifecycle::require_operation_retirement_reader_state(&paths.state_dir)?;
    let path = paths.state_dir.join("lifecycle-operation.json");
    if path.exists() {
        let operation_bytes = regular_bytes(&path)?;
        let operation: lifecycle::Operation = serde_json::from_slice(&operation_bytes)?;
        let id = Uuid::parse_str(
            journal["operationId"]
                .as_str()
                .context("terminal uninstall identity missing")?,
        )?;
        if lifecycle::retained_retirement_terminal(&operation, id)? {
            return Ok(());
        }
        ensure!(
            operation.id.to_string() == journal["operationId"]
                && operation
                    .uninstall_fence
                    .as_ref()
                    .is_some_and(|f| Some(f.journal_sha256.as_str())
                        == journal["fenceJournalSha256"].as_str()),
            "terminal uninstall fence changed"
        );
        if lifecycle::operation_retirement_evidence_present(paths)? {
            let root = paths
                .state_dir
                .join("recovery-evidence")
                .join(id.to_string());
            state::private_dir(&root)?;
            immutable_copy(
                &root.join("terminal-lifecycle-owner.json"),
                &operation_bytes,
            )?;
            let terminal_path = paths.state_dir.join("bootstrap-uninstall.json");
            let terminal_bytes = if terminal_path.try_exists()? {
                regular_bytes(&terminal_path)?
            } else {
                serde_json::to_vec(journal)?
            };
            immutable_copy(
                &root.join("terminal-bootstrap-uninstall.json"),
                &terminal_bytes,
            )?;
            ensure!(
                lifecycle::complete_uninstall_retirement_fence(paths, id)?,
                "operation retirement evidence changed"
            );
        } else {
            remove_regular(&path)?;
        }
    }
    Ok(())
}

fn capture_state_entries(paths: &lifecycle::Paths) -> Result<Value> {
    let mut candidates = uninstall_state::inventory_resolved_state(&paths.state_dir)?
        .into_iter()
        .collect::<std::collections::BTreeSet<_>>();
    for name in ["state.json", "drain.json", "pending-update.json"] {
        let path = paths.state_dir.join(name);
        if fs::symlink_metadata(&path).is_ok() {
            candidates.insert(path);
        }
    }
    let mut entries = Vec::new();
    for path in candidates {
        let relative = path.strip_prefix(&paths.state_dir)?;
        ensure!(
            !relative.as_os_str().is_empty()
                && relative
                    .components()
                    .all(|part| matches!(part, std::path::Component::Normal(_))),
            "unsafe uninstall state path"
        );
        ensure!(
            owned_state_namespace(relative),
            "unowned uninstall state path"
        );
        let meta = fs::symlink_metadata(&path)?;
        ensure!(
            meta.uid() == unsafe { libc::geteuid() } && !meta.file_type().is_symlink(),
            "unsafe uninstall state entry"
        );
        if meta.is_file() {
            ensure!(meta.nlink() == 1, "unsafe uninstall state hardlink");
            entries.push(json!({"path":relative,"kind":"file","sha256":digest_file(&path)?,"size":meta.len(),"mode":meta.mode() & 0o777}));
        } else {
            ensure!(meta.is_dir(), "unsafe uninstall state entry");
            entries.push(json!({"path":relative,"kind":"directory"}));
        }
    }
    Ok(Value::Array(entries))
}

fn owned_state_namespace(relative: &Path) -> bool {
    let parts = relative
        .iter()
        .map(|s| s.to_str())
        .collect::<Option<Vec<_>>>();
    let Some(parts) = parts else {
        return false;
    };
    match parts.as_slice() {
        [name] => matches!(
            *name,
            "state.json"
                | "drain.json"
                | "pending-update.json"
                | "jobs"
                | "operations"
                | "workflow-patches"
                | "responses"
                | "presentation.sqlite3"
                | "presentation.sqlite3-wal"
                | "presentation.sqlite3-shm"
                | "follow.sqlite3"
                | "follow.sqlite3-wal"
                | "follow.sqlite3-shm"
                | "recovery.sqlite3"
                | "recovery.sqlite3-wal"
                | "recovery.sqlite3-shm"
        ),
        ["jobs", id] => Uuid::parse_str(id).is_ok(),
        ["jobs", id, name] => {
            Uuid::parse_str(id).is_ok()
                && matches!(
                    *name,
                    "journal.json"
                        | "stdout"
                        | "stderr"
                        | "target-status.json"
                        | "provider-schema.json"
                        | "http-response-body"
                )
        }
        ["operations", name] => name.strip_suffix(".json").is_some_and(|key| {
            Uuid::parse_str(key).is_ok()
                || (key.len() == 64 && key.bytes().all(|b| b.is_ascii_hexdigit()))
        }),
        ["workflow-patches", name] => name
            .strip_suffix(".json")
            .is_some_and(|key| key.len() == 64 && key.bytes().all(|byte| byte.is_ascii_hexdigit())),
        ["responses", name] => name
            .strip_suffix(".meta.json")
            .or_else(|| name.strip_suffix(".sha256"))
            .or_else(|| name.strip_suffix(".json"))
            .is_some_and(|id| Uuid::parse_str(id).is_ok()),
        _ => false,
    }
}

fn remove_state_entries(paths: &lifecycle::Paths, journal: &mut Value) -> Result<()> {
    let entries = journal["stateEntries"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let mut expected = std::collections::BTreeSet::new();
    let mut files = Vec::new();
    let mut dirs = Vec::new();
    let started = journal["cleanup"]["stateDeletingStarted"] == true;
    for entry in &entries {
        let relative = PathBuf::from(
            entry["path"]
                .as_str()
                .context("uninstall state path missing")?,
        );
        ensure!(
            !relative.as_os_str().is_empty()
                && relative
                    .components()
                    .all(|part| matches!(part, std::path::Component::Normal(_)))
                && expected.insert(relative.clone()),
            "invalid uninstall state inventory"
        );
        ensure!(
            owned_state_namespace(&relative),
            "unowned uninstall state path"
        );
        let path = paths.state_dir.join(&relative);
        match fs::symlink_metadata(&path) {
            Ok(meta) => {
                ensure!(
                    meta.uid() == unsafe { libc::geteuid() } && !meta.file_type().is_symlink(),
                    "unsafe uninstall state entry"
                );
                if entry["kind"] == "file" {
                    ensure!(
                        meta.is_file()
                            && meta.nlink() == 1
                            && entry["size"].as_u64() == Some(meta.len())
                            && entry["mode"].as_u64() == Some(u64::from(meta.mode() & 0o777))
                            && digest_file(&path)? == entry["sha256"],
                        "uninstall state entry changed"
                    );
                    files.push(relative);
                } else {
                    ensure!(
                        entry["kind"] == "directory" && meta.is_dir(),
                        "unsafe uninstall state directory"
                    );
                    dirs.push(relative);
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound && started => (),
            Err(error) => return Err(error.into()),
        }
    }
    // Validate the whole remaining subset before deleting even one entry.
    for relative in &dirs {
        for child in fs::read_dir(paths.state_dir.join(relative))? {
            let child = child?.path();
            ensure!(
                expected.contains(child.strip_prefix(&paths.state_dir)?),
                "unowned entry appeared in uninstall state directory"
            );
        }
    }
    journal["cleanup"]["stateDeletingStarted"] = json!(true);
    save(paths, journal)?;
    for relative in files {
        let path = paths.state_dir.join(relative);
        fs::remove_file(&path)?;
        File::open(path.parent().unwrap())?.sync_all()?;
        fault("DURING_STATE_DELETE")?;
    }
    dirs.sort_by_key(|p| std::cmp::Reverse(p.components().count()));
    for relative in dirs {
        let path = paths.state_dir.join(relative);
        fs::remove_dir(&path)?;
        File::open(path.parent().unwrap())?.sync_all()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    pub(super) struct Fixture {
        _root: tempfile::TempDir,
        pub(super) paths: lifecycle::Paths,
        pub(super) journal: Value,
        target: PathBuf,
        quarantine: PathBuf,
    }
    fn fixture() -> Fixture {
        let root = tempfile::tempdir().unwrap();
        let base = fs::canonicalize(root.path()).unwrap();
        let paths = lifecycle::Paths {
            install_base: base.join("install"),
            state_dir: base.join("state"),
            launch_agents_dir: base.join("agents"),
        };
        fs::create_dir_all(paths.install_base.join("versions")).unwrap();
        fs::create_dir_all(&paths.state_dir).unwrap();
        fs::create_dir_all(&paths.launch_agents_dir).unwrap();
        let target = paths.install_base.join("versions/1.2.3");
        let id = Uuid::new_v4();
        let quarantine = paths
            .install_base
            .join("versions")
            .join(format!(".uninstall-{id}"))
            .join("1.2.3");
        fs::create_dir_all(quarantine.join("bin")).unwrap();
        fs::write(quarantine.join("bin/remaining"), b"owned").unwrap();
        fs::set_permissions(
            quarantine.join("bin/remaining"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        let files = json!([{"path":"bin/deleted","size":7,"mode":384,"sha256":state::digest(b"deleted")},{"path":"bin/remaining","size":5,"mode":384,"sha256":state::digest(b"owned")}]);
        let receipt = json!({"schema":"app.loomex.runner.install-receipt/v2","version":"1.2.3","versionPath":target,"launchAgent":paths.launch_agents_dir.join("app.loomex.runner.plist"),"bootstrapSha256":state::digest(b"fixture helper")});
        let owned = json!({"schema":"app.loomex.runner.owned-versions/v1","paths":[target],"inventories":[{"path":target,"files":files}]});
        state::write_json(&paths.state_dir.join("install-receipt.json"), &receipt).unwrap();
        state::write_json(&paths.state_dir.join("owned-versions.json"), &owned).unwrap();
        let helper = paths.state_dir.join("bootstrap-uninstall-helper");
        fs::write(&helper, b"fixture helper").unwrap();
        std::os::unix::fs::symlink(&target, paths.install_base.join("current")).unwrap();
        let journal = json!({"schema":SCHEMA,"phase":"cleanup","operationId":id,"drainKey":Uuid::new_v4(),"receipt":receipt,"receiptSha256":state::json_digest(&receipt),"paths":owned["paths"],"inventories":owned["inventories"],"helper":helper,"helperSha256":state::digest(b"fixture helper"),"fenceJournalSha256":"a".repeat(64),"protectedStoreRemoved":true,"cleanup":{"moved":[target],"deletingStarted":[target]}});
        save(&paths, &journal).unwrap();
        Fixture {
            _root: root,
            paths,
            journal,
            target,
            quarantine,
        }
    }
    pub(super) fn historical_fixture() -> Fixture {
        let mut fixture = fixture();
        fs::rename(&fixture.quarantine, &fixture.target).unwrap();
        fs::write(fixture.target.join("bin/deleted"), b"deleted").unwrap();
        fs::set_permissions(
            fixture.target.join("bin/deleted"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        fixture.journal["schema"] = json!(OLD_SCHEMA);
        fixture.journal["phase"] = json!("prepared");
        let mut operation =
            lifecycle::Operation::new(lifecycle::OperationKind::Install, "completed", None);
        operation.auth_baseline = Some(lifecycle::AuthBaseline::SignedOut {
            installation_id: Some(Uuid::new_v4()),
        });
        operation.previous_target = Some(fixture.target.clone());
        state::write_json(
            &fixture.paths.state_dir.join("lifecycle-operation.json"),
            &operation,
        )
        .unwrap();
        save(&fixture.paths, &fixture.journal).unwrap();
        fixture
    }
    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn current_prepared_v2_recovery_routes_modern_controller_and_preserves_existing_fence() {
        const CHILD: &str = "LOOMEX_TEST_CURRENT_V2_RECOVERY_ROOT";
        if let Some(root) = std::env::var_os(CHILD) {
            let root = PathBuf::from(root);
            let paths = lifecycle::Paths {
                install_base: root.join("install"),
                state_dir: root.join("state"),
                launch_agents_dir: root.join("agents"),
            };
            let expected = std::env::var("LOOMEX_TEST_EXPECTED_CURRENT_SHA").unwrap();
            let args = Arguments {
                release: Some(root.join("release")),
                allow_unsigned_development: true,
                development_api_origin: Some("http://127.0.0.1:9".into()),
                expected_old_journal_sha256: Some(expected),
                install_base: Some(paths.install_base.clone()),
                state_dir: Some(paths.state_dir.clone()),
                launch_agents_dir: Some(paths.launch_agents_dir.clone()),
                json: true,
                ..Default::default()
            };
            let adoption_expected = std::env::var_os("LOOMEX_TEST_ADOPTION_EXPECTED").is_some();
            let release = root.join("release");
            let manifest = read_manifest(&release).unwrap();
            let readonly = recovery_preflight(
                &paths,
                &args,
                &release,
                &manifest,
                &root.join("candidate-payload"),
            )
            .await;
            assert_eq!(readonly.is_ok(), adoption_expected, "{readonly:?}");
            let activation = args.activation.clone();
            let error = run(args, true).await.unwrap_err();
            assert!(!root.join("old-helper-dispatched").exists());
            let current: Value =
                state::read_json(&paths.state_dir.join("bootstrap-uninstall.json")).unwrap();
            let facts = activation.lock().unwrap().clone();
            let output = activation_error_record(&facts, &error, true);
            assert_eq!(output["outcome"], "blocked");
            if std::env::var_os("LOOMEX_TEST_ADOPTION_EXPECTED").is_some() {
                assert!(
                    error.to_string().contains("AFTER_RECOVERY_ADOPTION"),
                    "{error:#}"
                );
                assert_eq!(current["recovery"]["adoptedCurrent"], true);
                assert_eq!(output["operationId"], current["operationId"]);
            } else {
                assert!(error.to_string().contains("digest mismatch"), "{error:#}");
                assert!(current["recovery"].is_null());
            }
            return;
        }
        let mut fixture = historical_fixture();
        let base = fixture.paths.state_dir.parent().unwrap().to_path_buf();
        fs::write(
            fixture
                .paths
                .launch_agents_dir
                .join("app.loomex.runner.plist"),
            b"owned fixture service configuration",
        )
        .unwrap();
        let helper = fixture.paths.state_dir.join("bootstrap-uninstall-helper");
        let helper_bytes =
            b"#!/bin/sh\nprintf dispatched > \"$LOOMEX_TEST_OLD_HELPER_MARKER\"\nexit 64\n";
        fs::write(&helper, helper_bytes).unwrap();
        fs::set_permissions(&helper, fs::Permissions::from_mode(0o700)).unwrap();
        let executable = std::env::current_exe().unwrap();
        fs::copy(&executable, fixture.target.join("bin/loomex-runner")).unwrap();
        let runner = fixture.target.join("bin/loomex-runner");
        let runner_meta = fs::metadata(&runner).unwrap();
        let mut files = fixture.journal["inventories"][0]["files"]
            .as_array()
            .unwrap()
            .clone();
        files.push(json!({"path":"bin/loomex-runner","sha256":digest_file(&runner).unwrap(),"size":runner_meta.len(),"mode":runner_meta.mode() & 0o777}));
        fixture.journal["inventories"][0]["files"] = json!(files);
        fixture.journal["receipt"]["bootstrapSha256"] = json!(state::digest(helper_bytes));
        fixture.journal["receipt"]["developmentOnly"] = json!(true);
        fixture.journal["receipt"]["developmentApiOrigin"] = json!("http://127.0.0.1:9/");
        fixture.journal["helperSha256"] = json!(state::digest(helper_bytes));
        fixture.journal["receiptSha256"] = json!(state::json_digest(&fixture.journal["receipt"]));
        state::write_json(
            &fixture.paths.state_dir.join("install-receipt.json"),
            &fixture.journal["receipt"],
        )
        .unwrap();
        fixture.journal["receiptFileSha256"] =
            json!(digest_file(&fixture.paths.state_dir.join("install-receipt.json")).unwrap());
        state::write_json(
            &fixture.paths.state_dir.join("owned-versions.json"),
            &journal_owned(&fixture.journal),
        )
        .unwrap();
        fixture.journal["schema"] = json!(SCHEMA);
        fixture.journal["expectedIdentity"] =
            json!({"installationId":Uuid::new_v4(),"deviceId":null});
        fixture.journal["cleanup"] = json!({"moved":[],"deletingStarted":[]});
        fixture.journal["fenceJournalSha256"] = json!("f".repeat(64));
        save(&fixture.paths, &fixture.journal).unwrap();
        let id = Uuid::parse_str(fixture.journal["operationId"].as_str().unwrap()).unwrap();
        lifecycle::begin_uninstall_fence_locked(&fixture.paths, id, &"f".repeat(64)).unwrap();
        let fence_before =
            fs::read(fixture.paths.state_dir.join("lifecycle-operation.json")).unwrap();
        let original = fs::read(fixture.paths.state_dir.join("bootstrap-uninstall.json")).unwrap();
        let digest = state::digest(&original);
        assert_ne!(digest, "f".repeat(64));
        let payload = base.join("candidate-payload");
        fs::create_dir_all(payload.join("bin")).unwrap();
        fs::create_dir_all(payload.join("metadata")).unwrap();
        for name in ["loomex", "loomex-runner", "loomex-lifecycle-bootstrap"] {
            fs::hard_link(&executable, payload.join("bin").join(name)).unwrap();
        }
        state::write_json(&payload.join("metadata/project.json"),&json!({"project":"loomex-runner","version":env!("CARGO_PKG_VERSION"),"platform":"darwin-arm64"})).unwrap();
        let source = json!({"schema":"app.loomex.source-content/v1","sourceRevision":"test-original-source","files":[]});
        let mut source_bytes = serde_json::to_vec(&source).unwrap();
        source_bytes.push(b'\n');
        fs::write(
            payload.join("metadata/source-content-manifest.json"),
            source_bytes,
        )
        .unwrap();
        let mut candidate_files = Vec::new();
        for name in [
            "bin/loomex",
            "bin/loomex-runner",
            "bin/loomex-lifecycle-bootstrap",
            "metadata/project.json",
            "metadata/source-content-manifest.json",
        ] {
            let path = payload.join(name);
            let metadata = fs::metadata(&path).unwrap();
            candidate_files.push(json!({"path":name,"sha256":digest_file(&path).unwrap(),"size":metadata.len(),"mode":metadata.mode() & 0o777}));
        }
        candidate_files.sort_by(|a, b| a["path"].as_str().cmp(&b["path"].as_str()));
        let release = base.join("release");
        fs::create_dir(&release).unwrap();
        assert!(
            std::process::Command::new("/usr/bin/tar")
                .arg("-czf")
                .arg(release.join("payload.tar.gz"))
                .arg("-C")
                .arg(&payload)
                .args(["bin", "metadata"])
                .status()
                .unwrap()
                .success()
        );
        fs::hard_link(&executable, release.join("loomex-lifecycle-bootstrap")).unwrap();
        let manifest = json!({"schema":"app.loomex.release/v1","project":"loomex-runner","platform":"darwin-arm64","version":env!("CARGO_PKG_VERSION"),"developmentOnly":true,"sourceRevision":"test-original-source","sourceContent":{"file":"metadata/source-content-manifest.json","sha256":digest_file(&payload.join("metadata/source-content-manifest.json")).unwrap()},"payload":{"file":"payload.tar.gz","sha256":digest_file(&release.join("payload.tar.gz")).unwrap(),"files":candidate_files},"bootstrap":{"file":"loomex-lifecycle-bootstrap","sha256":digest_file(&executable).unwrap(),"size":fs::metadata(&executable).unwrap().len()}});
        let mut manifest_bytes = serde_json::to_vec(&manifest).unwrap();
        manifest_bytes.push(b'\n');
        fs::write(release.join("manifest.json"), manifest_bytes).unwrap();
        let child = |expected: &str, adoption: bool| {
            let mut command = std::process::Command::new(&executable);
            command.args(["--exact","bootstrap_uninstall::tests::current_prepared_v2_recovery_routes_modern_controller_and_preserves_existing_fence","--nocapture"])
                .env(CHILD,&base).env("LOOMEX_TEST_EXPECTED_CURRENT_SHA",expected).env("LOOMEX_TEST_OLD_HELPER_MARKER",base.join("old-helper-dispatched"))
                .env("LOOMEX_ALLOW_UNSAFE_DEV_INSTALL","1").env("LOOMEX_TEST_UNINSTALL_FAIL_AFTER_RECOVERY_ADOPTION","1").env_remove("LOOMEX_INSTALL_TEST_MODE");
            if adoption {
                command.env("LOOMEX_TEST_ADOPTION_EXPECTED", "1");
            }
            let output = command.output().unwrap();
            assert!(
                output.status.success(),
                "{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        };
        child(&"0".repeat(64), false);
        assert_eq!(
            fs::read(fixture.paths.state_dir.join("bootstrap-uninstall.json")).unwrap(),
            original
        );
        child(&digest, true);
        let adopted: Value =
            state::read_json(&fixture.paths.state_dir.join("bootstrap-uninstall.json")).unwrap();
        assert_eq!(adopted["operationId"], id.to_string());
        assert_eq!(adopted["fenceJournalSha256"], "f".repeat(64));
        assert_eq!(adopted["drainKey"], fixture.journal["drainKey"]);
        assert_eq!(
            fs::read(fixture.paths.state_dir.join("lifecycle-operation.json")).unwrap(),
            fence_before
        );
        assert_eq!(fs::read(&helper).unwrap(), helper_bytes);
        assert_eq!(
            fs::read(
                fixture
                    .paths
                    .state_dir
                    .join(format!("bootstrap-uninstall-original-{digest}.json"))
            )
            .unwrap(),
            original
        );
        assert!(!base.join("old-helper-dispatched").exists());
        let mut retry = Arguments {
            expected_old_journal_sha256: Some(digest.clone()),
            ..Default::default()
        };
        assert!(
            recovery_preflight(&fixture.paths, &retry, &release, &manifest, &payload)
                .await
                .unwrap()
        );
        retry.expected_release_path = Some(base.join("relocated-identical-release"));
        assert!(
            recovery_preflight(&fixture.paths, &retry, &release, &manifest, &payload)
                .await
                .is_err()
        );
    }
    #[tokio::test]
    async fn unresolved_current_work_reports_known_blocked_operation_before_old_helper_dispatch() {
        let mut fixture = historical_fixture();
        fixture.journal["schema"] = json!(SCHEMA);
        fixture.journal["expectedIdentity"] =
            json!({"installationId":Uuid::new_v4(),"deviceId":null});
        save(&fixture.paths, &fixture.journal).unwrap();
        let job = fixture
            .paths
            .state_dir
            .join("jobs")
            .join(Uuid::new_v4().to_string());
        fs::create_dir_all(&job).unwrap();
        state::write_json(&job.join("journal.json"), &json!({"phase":"running"})).unwrap();
        let args = Arguments {
            install_base: Some(fixture.paths.install_base.clone()),
            state_dir: Some(fixture.paths.state_dir.clone()),
            launch_agents_dir: Some(fixture.paths.launch_agents_dir.clone()),
            json: true,
            ..Default::default()
        };
        let activation = args.activation.clone();
        let error = run(args, false).await.unwrap_err();
        let report = activation_error_record(&activation.lock().unwrap(), &error, false);
        assert_eq!(report["outcome"], "blocked");
        assert_eq!(report["reasonCode"], "MANAGED_WORK_UNRESOLVED");
        assert_eq!(report["operationId"], fixture.journal["operationId"]);
        assert!(job.join("journal.json").exists());
        assert!(!fixture.paths.state_dir.join("drain.json").exists());
    }
    #[tokio::test]
    async fn terminal_cleanup_retains_command_operation_identity_after_journals_are_removed() {
        const CHILD: &str = "LOOMEX_TEST_TERMINAL_IDENTITY_ROOT";
        if let Some(root) = std::env::var_os(CHILD) {
            let root = PathBuf::from(root);
            let args = Arguments {
                install_base: Some(root.join("install")),
                state_dir: Some(root.join("state")),
                launch_agents_dir: Some(root.join("agents")),
                json: true,
                ..Default::default()
            };
            let activation = args.activation.clone();
            run(args, false).await.unwrap();
            let report = activation_record(
                &activation.lock().unwrap(),
                "completed",
                "UNINSTALL_COMPLETED",
                "none",
            );
            assert_eq!(
                report["operationId"],
                std::env::var("LOOMEX_TEST_TERMINAL_OPERATION").unwrap()
            );
            assert!(
                !root
                    .join("state/bootstrap-uninstall-terminal.json")
                    .exists()
            );
            assert!(!root.join("state/lifecycle-operation.json").exists());
            return;
        }
        let fixture = fixture();
        let mut terminal = fixture.journal.clone();
        terminal["phase"] = json!("terminal");
        state::write_json(
            &fixture
                .paths
                .state_dir
                .join("bootstrap-uninstall-terminal.json"),
            &terminal,
        )
        .unwrap();
        for name in [
            "bootstrap-uninstall.json",
            "install-receipt.json",
            "owned-versions.json",
        ] {
            fs::remove_file(fixture.paths.state_dir.join(name)).unwrap();
        }
        fs::remove_file(fixture.paths.install_base.join("current")).unwrap();
        let id = Uuid::parse_str(terminal["operationId"].as_str().unwrap()).unwrap();
        lifecycle::begin_uninstall_fence_locked(
            &fixture.paths,
            id,
            terminal["fenceJournalSha256"].as_str().unwrap(),
        )
        .unwrap();
        let output=std::process::Command::new(std::env::current_exe().unwrap()).args(["--exact","bootstrap_uninstall::tests::terminal_cleanup_retains_command_operation_identity_after_journals_are_removed","--nocapture"])
            .env(CHILD,fixture.paths.state_dir.parent().unwrap()).env("LOOMEX_TEST_TERMINAL_OPERATION",id.to_string()).env("LOOMEX_INSTALL_TEST_MODE","1").output().unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    #[tokio::test]
    async fn nonprepared_current_owner_refuses_release_adoption_with_original_owner_action() {
        let mut fixture = historical_fixture();
        fixture.journal["schema"] = json!(SCHEMA);
        fixture.journal["phase"] = json!("idle_verified");
        save(&fixture.paths, &fixture.journal).unwrap();
        let args = Arguments {
            install_base: Some(fixture.paths.install_base.clone()),
            state_dir: Some(fixture.paths.state_dir.clone()),
            launch_agents_dir: Some(fixture.paths.launch_agents_dir.clone()),
            expected_old_journal_sha256: Some(
                digest_file(&fixture.paths.state_dir.join("bootstrap-uninstall.json")).unwrap(),
            ),
            json: true,
            ..Default::default()
        };
        let activation = args.activation.clone();
        let before =
            regular_bytes(&fixture.paths.state_dir.join("bootstrap-uninstall.json")).unwrap();
        let error = run(args, true).await.unwrap_err();
        let report = activation_error_record(&activation.lock().unwrap(), &error, true);
        assert_eq!(report["outcome"], "blocked");
        assert_eq!(report["nextAction"], "resume_original_uninstall_owner");
        assert_eq!(
            recovery_ownership(&fixture.paths)["nextAction"],
            "resume_original_uninstall_owner"
        );
        assert_eq!(
            regular_bytes(&fixture.paths.state_dir.join("bootstrap-uninstall.json")).unwrap(),
            before
        );
    }
    #[test]
    fn selected_replacement_intent_rejects_same_candidate_relocated_before_adoption() {
        let fixture = historical_fixture();
        let args = Arguments {
            replace_pre_adoption_candidate: true,
            expected_recovery_intent_sha256: Some("c".repeat(64)),
            ..Default::default()
        };
        let id = Uuid::new_v4();
        let old = "a".repeat(64);
        let manifest = "b".repeat(64);
        let (intent, a) = recovery_release_selection(
            &fixture.paths,
            &args,
            id,
            &old,
            &manifest,
            Path::new("/release-a"),
        );
        immutable_copy(&intent, &serde_json::to_vec(&a).unwrap()).unwrap();
        let (_, b) = recovery_release_selection(
            &fixture.paths,
            &args,
            id,
            &old,
            &manifest,
            Path::new("/release-b"),
        );
        assert!(validate_retained_selection(&intent, &a).is_ok());
        assert!(validate_retained_selection(&intent, &b).is_err());
        assert_eq!(
            regular_bytes(&intent).unwrap(),
            serde_json::to_vec(&a).unwrap()
        );
    }
    #[tokio::test]
    async fn explicit_candidate_replacement_preserves_original_intent_and_same_fence() {
        let fixture = historical_fixture();
        let old_path = fixture.paths.state_dir.join("bootstrap-uninstall.json");
        let old_bytes = fs::read(&old_path).unwrap();
        let old_sha = state::digest(&old_bytes);
        let id = Uuid::new_v4();
        lifecycle::begin_uninstall_fence_locked(&fixture.paths, id, &old_sha).unwrap();
        let fence_before =
            fs::read(fixture.paths.state_dir.join("lifecycle-operation.json")).unwrap();
        let intent = fixture.paths.state_dir.join(format!(
            "bootstrap-uninstall-recovery-release-{old_sha}.json"
        ));
        let original = json!({"schema":"app.loomex.runner.uninstall-recovery-release/v1","operationId":id,"oldJournalSha256":old_sha,"releasePath":"/original-release","manifestSha256":"a".repeat(64),"stage":fixture.paths.state_dir.join(format!("uninstall-recovery-{old_sha}"))});
        immutable_copy(&intent, &serde_json::to_vec(&original).unwrap()).unwrap();
        let original_bytes = fs::read(&intent).unwrap();
        let mut args = Arguments {
            replace_pre_adoption_candidate: true,
            expected_old_journal_sha256: Some(old_sha.clone()),
            expected_recovery_intent_sha256: Some(state::digest(&original_bytes)),
            ..Default::default()
        };
        validate_replacement(
            &fixture.paths,
            &args,
            &fixture.journal,
            &old_sha,
            id,
            &intent,
        )
        .unwrap();
        args.expected_recovery_intent_sha256 = Some("b".repeat(64));
        assert!(
            validate_replacement(
                &fixture.paths,
                &args,
                &fixture.journal,
                &old_sha,
                id,
                &intent
            )
            .is_err()
        );
        args.expected_recovery_intent_sha256 = Some(state::digest(&original_bytes));
        let selected = fixture.paths.state_dir.join("replacement-qualified.json");
        adopt_recovery_binding(
            &fixture.paths,
            id,
            &old_sha,
            &selected,
            &json!({"candidate":"corrected"}),
            async { Ok(()) },
        )
        .await
        .unwrap();
        assert_eq!(fs::read(&intent).unwrap(), original_bytes);
        assert_eq!(fs::read(&old_path).unwrap(), old_bytes);
        assert_eq!(
            fs::read(fixture.paths.state_dir.join("lifecycle-operation.json")).unwrap(),
            fence_before
        );
        fs::write(
            fixture
                .paths
                .state_dir
                .join(format!("uninstall-maintenance-{id}.json")),
            b"uncertain dispatch",
        )
        .unwrap();
        assert!(
            validate_replacement(
                &fixture.paths,
                &args,
                &fixture.journal,
                &old_sha,
                id,
                &intent
            )
            .is_err()
        );
    }
    #[test]
    fn stopped_prepared_identity_or_unresolved_work_never_advances_checkpoint() {
        let fixture = fixture();
        let mut journal = fixture.journal.clone();
        journal["phase"] = json!("prepared");
        journal["expectedIdentity"] = json!({"installationId":Uuid::new_v4(),"deviceId":null});
        let before = fs::read(fixture.paths.state_dir.join("bootstrap-uninstall.json")).unwrap();
        assert!(
            checkpoint_prepared_stopped(
                &fixture.paths,
                &mut journal,
                json!({"installationId":Uuid::new_v4(),"deviceId":null}),
                "a".repeat(64)
            )
            .is_err()
        );
        assert_eq!(journal["phase"], "prepared");
        let job = fixture
            .paths
            .state_dir
            .join("jobs")
            .join(Uuid::new_v4().to_string());
        fs::create_dir_all(&job).unwrap();
        state::write_json(&job.join("journal.json"), &json!({"phase":"running"})).unwrap();
        let native = journal["expectedIdentity"].clone();
        assert!(
            checkpoint_prepared_stopped(&fixture.paths, &mut journal, native, "a".repeat(64))
                .is_err()
        );
        assert_eq!(
            fs::read(fixture.paths.state_dir.join("bootstrap-uninstall.json")).unwrap(),
            before
        );
    }
    #[test]
    fn recovery_ownership_keeps_journal_digest_when_candidate_or_owner_is_ineligible() {
        let fixture = historical_fixture();
        let ownership = recovery_ownership(&fixture.paths);
        assert_eq!(ownership["status"], "pending");
        assert_eq!(ownership["nextAction"], "recover_uninstall");
        assert_eq!(
            ownership["journalSha256"],
            digest_file(&fixture.paths.state_dir.join("bootstrap-uninstall.json")).unwrap()
        );
        fs::write(
            fixture.paths.state_dir.join("lifecycle-operation.json"),
            b"malformed",
        )
        .unwrap();
        let blocked = recovery_ownership(&fixture.paths);
        assert_eq!(blocked["status"], "blocked");
        assert_eq!(blocked["nextAction"], "inspect_protected_ownership");
        assert_eq!(blocked["journalSha256"], ownership["journalSha256"]);
    }
    #[tokio::test]
    async fn rejected_recovery_candidate_does_not_pin_fence_or_intent() {
        let fixture = fixture();
        let intent = fixture.paths.state_dir.join("candidate-intent.json");
        let result = adopt_recovery_binding(
            &fixture.paths,
            Uuid::new_v4(),
            &"b".repeat(64),
            &intent,
            &json!({"candidate":"incompatible"}),
            async { signing_transition(Some("old"), Some("different"), false, false).map(|_| ()) },
        )
        .await;
        assert!(result.is_err());
        assert!(
            !intent.exists(),
            "rejected candidate pinned immutable release intent"
        );
        assert!(
            !fixture
                .paths
                .state_dir
                .join("lifecycle-operation.json")
                .exists(),
            "rejected candidate pinned lifecycle fence"
        );
    }
    #[tokio::test]
    async fn stopped_prepared_retry_does_not_need_a_live_admission_socket() {
        let fixture = fixture();
        let mut journal = fixture.journal.clone();
        journal["phase"] = json!("prepared");
        journal["expectedIdentity"] = json!({"installationId":Uuid::new_v4(),"deviceId":null});
        let native = journal["expectedIdentity"].clone();
        checkpoint_prepared_stopped(&fixture.paths, &mut journal, native, "a".repeat(64)).unwrap();
        require_initial_admission(journal["phase"].as_str().unwrap(), async {
            Err(anyhow::anyhow!("dead admission socket contacted"))
        })
        .await
        .unwrap();
        assert_eq!(journal["phase"], "stopped");
        assert!(journal["stopEvidence"]["pid"].is_null());
        assert!(!fixture.paths.state_dir.join("drain.json").exists());
    }
    #[tokio::test]
    async fn interrupted_quarantine_cleanup_resumes_subset_and_retains_same_lock_inode() {
        let mut fixture = fixture();
        let guard = singleton(&fixture.paths, true).unwrap();
        let inode = guard.metadata().unwrap().ino();
        fs::write(
            fixture.paths.state_dir.join("user-provider-state"),
            b"preserved",
        )
        .unwrap();
        validate_journal(&fixture.paths, &fixture.journal).unwrap();
        cleanup(&fixture.paths, &mut fixture.journal, &guard, true)
            .await
            .unwrap();
        assert!(!fixture.target.exists() && !fixture.quarantine.exists());
        assert_eq!(
            fs::read(fixture.paths.state_dir.join("user-provider-state")).unwrap(),
            b"preserved"
        );
        assert_eq!(
            fs::metadata(fixture.paths.state_dir.join("daemon.lock"))
                .unwrap()
                .ino(),
            inode
        );
        assert!(
            singleton(&fixture.paths, false).is_err(),
            "cleanup must retain exclusion until the owner drops its guard"
        );
        drop(guard);
        assert!(singleton(&fixture.paths, false).is_ok());
    }
    #[tokio::test]
    async fn interrupted_quarantine_unknown_file_refuses_before_deleting_remaining_owned_file() {
        let mut fixture = fixture();
        let guard = singleton(&fixture.paths, true).unwrap();
        fs::write(fixture.quarantine.join("user-file"), b"preserve").unwrap();
        assert!(
            cleanup(&fixture.paths, &mut fixture.journal, &guard, true)
                .await
                .is_err()
        );
        assert!(fixture.quarantine.join("bin/remaining").exists());
        assert!(fixture.quarantine.join("user-file").exists());
        assert!(
            fixture
                .paths
                .state_dir
                .join("bootstrap-uninstall.json")
                .exists()
        );
    }
    #[test]
    fn unresolved_work_blocks_cleanup_and_does_not_erase_evidence() {
        let fixture = fixture();
        let jobs = fixture
            .paths
            .state_dir
            .join("jobs")
            .join(Uuid::new_v4().to_string());
        fs::create_dir_all(&jobs).unwrap();
        let path = jobs.join("journal.json");
        state::write_json(&path, &json!({"phase":"delivery_blocked"})).unwrap();
        let before = fs::read(&path).unwrap();
        assert!(reject_unresolved_work(&fixture.paths).is_err());
        assert_eq!(before, fs::read(&path).unwrap());
    }
    #[test]
    fn singleton_symlink_never_redirects_cleanup_exclusion() {
        let fixture = fixture();
        let other = fixture.paths.state_dir.join("other");
        fs::write(&other, b"preserve").unwrap();
        std::os::unix::fs::symlink(&other, fixture.paths.state_dir.join("daemon.lock")).unwrap();
        assert!(singleton(&fixture.paths, false).is_err());
        assert_eq!(fs::read(&other).unwrap(), b"preserve");
    }
    #[tokio::test]
    async fn unobserved_child_retains_real_singleton_until_process_exit() {
        let fixture = fixture();
        let guard = singleton(&fixture.paths, true).unwrap();
        let inherited = guard.try_clone().unwrap();
        let fd = inherited.as_raw_fd();
        let mut command = tokio::process::Command::new("/bin/sleep");
        command
            .arg("0.4")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(false);
        unsafe {
            command.pre_exec(move || {
                let flags = libc::fcntl(fd, libc::F_GETFD);
                if flags < 0 || libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = command.spawn().unwrap();
        assert!(
            observe_maintenance(&mut child, std::time::Duration::from_millis(20))
                .await
                .is_err()
        );
        drop(inherited);
        drop(guard);
        assert!(
            singleton(&fixture.paths, false).is_err(),
            "observation timeout cannot release the child's inherited owner"
        );
        assert!(
            tokio::time::timeout(std::time::Duration::from_secs(2), child.wait())
                .await
                .unwrap()
                .unwrap()
                .success()
        );
        assert!(singleton(&fixture.paths, false).is_ok());
    }
    #[test]
    fn maintenance_error_projection_preserves_fixed_native_facts_and_omits_arbitrary_text() {
        let stderr=serde_json::to_vec(&json!({"code":"STORE_ACCESS_DENIED","failureStage":"protected_store_read","failureCategory":"access_denied","nativeOsStatus":-25293,"message":"SECRET MATERIAL"})).unwrap();
        let projected = maintenance_failure(&stderr).to_string();
        assert!(projected.contains("STORE_ACCESS_DENIED") && projected.contains("-25293"));
        assert!(!projected.contains("SECRET MATERIAL"));
        assert!(
            !maintenance_failure(b"SECRET MATERIAL")
                .to_string()
                .contains("SECRET MATERIAL")
        );
    }
    fn resolved_job(fixture: &Fixture) -> PathBuf {
        let id = Uuid::new_v4();
        let path = fixture.paths.state_dir.join("jobs").join(id.to_string());
        fs::create_dir_all(&path).unwrap();
        state::write_json(
            &path.join("journal.json"),
            &json!({"phase":"acknowledged","acknowledgedAt":1,"job":{"id":id}}),
        )
        .unwrap();
        path
    }
    #[tokio::test]
    async fn partial_resolved_state_deletion_resumes_without_requiring_removed_journal() {
        let mut fixture = fixture();
        let job = resolved_job(&fixture);
        fixture.journal["stateEntries"] = capture_state_entries(&fixture.paths).unwrap();
        fixture.journal["cleanup"]["stateDeletingStarted"] = json!(true);
        fs::remove_file(job.join("journal.json")).unwrap();
        save(&fixture.paths, &fixture.journal).unwrap();
        let guard = singleton(&fixture.paths, true).unwrap();
        cleanup(&fixture.paths, &mut fixture.journal, &guard, true)
            .await
            .unwrap();
        assert!(!job.exists());
    }
    #[test]
    fn native_patch_inventory_capture_and_removal_stays_in_exact_owned_namespace() {
        let mut fixture = fixture();
        let path = fixture
            .paths
            .state_dir
            .join("workflow-patches")
            .join(format!("{}.json", "a".repeat(64)));
        let workflow = Uuid::new_v4();
        let body = json!({"definition":{},"expectedVersion":0});
        state::write_json(&path,&json!({"identity":"b".repeat(64),"workflowId":workflow,"status":"submitted","expectedVersion":0,"expectedDefinitionChecksum":"c".repeat(64),"updateDigest":state::json_digest(&body["definition"]),"payloadDigest":state::json_digest(&body),"updateBody":body})).unwrap();
        assert!(capture_state_entries(&fixture.paths).is_err());
        assert!(path.exists());
        state::write_json(&path,&json!({"identity":"b".repeat(64),"workflowId":workflow,"status":"rejected","code":"WORKFLOW_VERSION_CONFLICT"})).unwrap();
        fixture.journal["stateEntries"] = capture_state_entries(&fixture.paths).unwrap();
        assert!(
            fixture.journal["stateEntries"]
                .as_array()
                .unwrap()
                .iter()
                .any(|entry| entry["path"] == format!("workflow-patches/{}.json", "a".repeat(64)))
        );
        assert!(!owned_state_namespace(Path::new(
            "workflow-patches/unknown.json"
        )));
        assert!(!owned_state_namespace(Path::new(
            "workflow-patches/../state.json"
        )));
        remove_state_entries(&fixture.paths, &mut fixture.journal).unwrap();
        assert!(!path.exists());
        assert!(!fixture.paths.state_dir.join("workflow-patches").exists());
    }
    #[test]
    fn new_unowned_state_child_blocks_whole_state_deletion_before_any_owned_file() {
        let mut fixture = fixture();
        let job = resolved_job(&fixture);
        fixture.journal["stateEntries"] = capture_state_entries(&fixture.paths).unwrap();
        fs::write(job.join("user-file"), b"preserve").unwrap();
        assert!(remove_state_entries(&fixture.paths, &mut fixture.journal).is_err());
        assert!(job.join("journal.json").exists());
        assert_eq!(fs::read(job.join("user-file")).unwrap(), b"preserve");
    }
    #[test]
    fn old_prepared_recovery_without_historical_auth_baseline_fails_without_mutation() {
        let fixture = fixture();
        let path = fixture.paths.state_dir.join("lifecycle-operation.json");
        let mut operation =
            lifecycle::Operation::new(lifecycle::OperationKind::Install, "completed", None);
        operation.schema = "app.loomex.runner.lifecycle-operation/v1".into();
        assert!(lifecycle::operation_is_terminal(&operation).unwrap());
        state::write_json(&path, &operation).unwrap();
        let original = fs::read(&path).unwrap();
        assert!(
            prior_identity(&fixture.paths)
                .unwrap_err()
                .to_string()
                .contains("trusted authentication baseline")
        );
        assert_eq!(fs::read(&path).unwrap(), original);
    }
    #[test]
    fn fresh_never_signed_in_requires_both_public_and_verified_native_absence() {
        let expected = public_identity(
            &json!({"code":"AUTH_REQUIRED","authenticated":false,"loginPending":false}),
        )
        .unwrap();
        assert!(expected.is_null());
        let mut journal = json!({"expectedIdentity":expected});
        assert!(!revocation_satisfied(&journal));
        assert!(record_native_identity(&mut journal, Value::Null).unwrap());
        assert!(
            journal["nativeAbsenceVerified"] == true
                && journal["remoteRevocation"] == "not_required"
                && journal["protectedStoreRemoved"] == true
                && revocation_satisfied(&journal)
        );
        assert!(
            public_identity(
                &json!({"code":"AUTHENTICATED","authenticated":true,"loginPending":false})
            )
            .is_err()
        );
        let mut changed = json!({"expectedIdentity":null});
        let before = changed.clone();
        assert!(
            record_native_identity(
                &mut changed,
                json!({"installationId":Uuid::new_v4(),"deviceId":"new-device"})
            )
            .is_err()
        );
        assert_eq!(changed, before);
        let mut old =
            json!({"expectedIdentity":null,"recovery":{"oldJournalSha256":"a".repeat(64)}});
        assert!(record_native_identity(&mut old, Value::Null).is_err());
    }
    #[tokio::test]
    async fn idle_verified_retry_does_not_require_the_dead_daemon_socket() {
        let fixture = fixture();
        let mut journal = fixture.journal.clone();
        journal["phase"] = json!("idle_verified");
        let mut exited = std::process::Command::new("/usr/bin/true").spawn().unwrap();
        let pid = exited.id();
        exited.wait().unwrap();
        let agent = fixture
            .paths
            .launch_agents_dir
            .join("app.loomex.runner.plist");
        fs::write(&agent, b"owned fixture agent").unwrap();
        let agent_sha = digest_file(&agent).unwrap();
        journal["stopEvidence"] = json!({"pid":pid,"launchAgentSha256":agent_sha});
        save(&fixture.paths, &journal).unwrap();
        require_initial_admission(journal["phase"].as_str().unwrap(), async {
            Err(anyhow::anyhow!("dead daemon socket contacted"))
        })
        .await
        .unwrap();
        qualify_before_effects(&fixture.paths).unwrap();
        checkpoint_idle_stop_intent(&fixture.paths, &mut journal, false).unwrap();
        assert_eq!(journal["phase"], "stop_intent");
        assert_eq!(journal["stopEvidence"]["request"], "prepared");
        assert_eq!(journal["stopEvidence"]["pid"], pid);
        assert_eq!(journal["stopEvidence"]["launchAgentSha256"], agent_sha);
        verify_recorded_process_exit(&journal).unwrap();
        assert!(!fixture.paths.state_dir.join("control.sock").exists());
        let owner = singleton(&fixture.paths, true).unwrap();
        assert!(singleton(&fixture.paths, false).is_err());
        drop(owner);
        assert!(
            require_initial_admission("prepared", async {
                Err(anyhow::anyhow!("fresh admission still required"))
            })
            .await
            .is_err()
        );
    }
    #[test]
    fn unknown_jobs_names_are_preserved_by_early_work_gate() {
        let fixture = fixture();
        let jobs = fixture.paths.state_dir.join("jobs");
        fs::create_dir_all(jobs.join("user-notes")).unwrap();
        fs::write(jobs.join("notes.txt"), b"unowned file").unwrap();
        fs::write(jobs.join("user-notes/note"), b"unowned directory").unwrap();
        reject_unresolved_work(&fixture.paths).unwrap();
        assert_eq!(fs::read(jobs.join("notes.txt")).unwrap(), b"unowned file");
        assert_eq!(
            fs::read(jobs.join("user-notes/note")).unwrap(),
            b"unowned directory"
        );
        fs::create_dir(jobs.join(Uuid::new_v4().to_string())).unwrap();
        assert!(
            reject_unresolved_work(&fixture.paths).is_err(),
            "known job namespace with missing journal remains unresolved"
        );
    }
    #[test]
    fn predictable_pending_state_is_rejected_by_the_readonly_gate_before_drain_or_stop() {
        let fixture = fixture();
        let root = fixture.paths.state_dir.join("operations");
        fs::create_dir(&root).unwrap();
        let path = root.join(format!("{}.json", Uuid::new_v4()));
        state::write_json(
            &path,
            &json!({"method":"workflows.create","digest":"a".repeat(64)}),
        )
        .unwrap();
        let before = fs::read(&path).unwrap();
        assert!(qualify_before_effects(&fixture.paths).is_err());
        assert_eq!(fs::read(path).unwrap(), before);
        assert!(!fixture.paths.state_dir.join("drain.json").exists());
        assert!(fixture.paths.install_base.join("current").is_symlink());
    }
    #[test]
    fn maintenance_error_projection_preserves_only_typed_bounded_remote_diagnostics() {
        let correlation = Uuid::new_v4();
        let record = json!({"code":"AUTH_LOGOUT_FAILED","failureStage":"remote_revocation","failureCategory":"remote_unconfirmed","httpStatus":422,"correlationId":correlation,"remoteCode":"DEVICE_AUTHORITY_INVALID_422","message":"PROVIDER SECRET TEXT","body":{"token":"PRIVATE"}});
        let error = maintenance_failure(&serde_json::to_vec(&record).unwrap()).to_string();
        let projected: Value = serde_json::from_str(&error).unwrap();
        assert_eq!(projected["code"], "AUTH_LOGOUT_FAILED");
        assert_eq!(projected["httpStatus"], 422);
        assert_eq!(projected["correlationId"], correlation.to_string());
        assert_eq!(projected["remoteCode"], "DEVICE_AUTHORITY_INVALID_422");
        assert!(!error.contains("PROVIDER SECRET TEXT") && !error.contains("PRIVATE"));
        for (status, reference, remote) in [
            (
                json!(99),
                json!("https://provider.example/private"),
                json!("provider secret text"),
            ),
            (
                json!(600),
                json!({"uuid":correlation}),
                json!("VALID_CODE\nSECRET"),
            ),
            (json!("422"), json!(7), json!("A".repeat(121))),
            (json!(422.5), json!("not-a-uuid"), json!("")),
            (json!(-1), json!(" uuid "), json!("UNICODE_Ü")),
        ] {
            let record = json!({"httpStatus":status,"correlationId":reference,"remoteCode":remote,"stderr":"PROVIDER SECRET TEXT"});
            let error = maintenance_failure(&serde_json::to_vec(&record).unwrap()).to_string();
            let projected: Value = serde_json::from_str(&error).unwrap();
            assert!(
                projected.get("httpStatus").is_none()
                    && projected.get("correlationId").is_none()
                    && projected.get("remoteCode").is_none()
            );
            assert!(!error.contains("PROVIDER SECRET TEXT"));
        }
    }
    #[test]
    fn maintenance_decoder_preserves_actual_public_error_record_envelope_details() {
        let correlation = Uuid::new_v4();
        let details = json!({"failureStage":"remote_revocation","failureCategory":"remote_unconfirmed","nativeOsStatus":null,"httpStatus":409,"correlationId":correlation,"remoteCode":"DEVICE_AUTHORITY_REVOKE_REJECTED","remoteRevocation":"pending","protectedStoreRemoved":false,"message":"PROVIDER PRIVATE TEXT","body":{"token":"PRIVATE TOKEN"}});
        let error: anyhow::Error = loomex_runner::api::ApiError {
            code: "AUTH_LOGOUT_FAILED".into(),
            retryable: false,
            status: Some(409),
            data: Some(details),
            correlation_id: Some(correlation.to_string()),
        }
        .into();
        let envelope = control::public_error_record(&error);
        assert!(envelope["data"].is_object());
        let output = maintenance_failure(&serde_json::to_vec(&envelope).unwrap()).to_string();
        let projected: Value = serde_json::from_str(&output).unwrap();
        assert_eq!(projected["code"], "AUTH_LOGOUT_FAILED");
        assert_eq!(projected["failureStage"], "remote_revocation");
        assert_eq!(projected["failureCategory"], "remote_unconfirmed");
        assert_eq!(projected["httpStatus"], 409);
        assert_eq!(projected["correlationId"], correlation.to_string());
        assert_eq!(projected["remoteCode"], "DEVICE_AUTHORITY_REVOKE_REJECTED");
        assert_eq!(projected["remoteRevocation"], "pending");
        assert_eq!(projected["protectedStoreRemoved"], false);
        assert_eq!(projected["outcome"], envelope["outcome"]);
        assert_eq!(projected["recovery"], envelope["recovery"]);
        assert!(!output.contains("PROVIDER PRIVATE TEXT") && !output.contains("PRIVATE TOKEN"));
        for category in [
            "native_os_error",
            "native_io_timeout",
            "native_worker_failed",
            "serialization_timeout",
        ] {
            let error:anyhow::Error=loomex_runner::api::ApiError{code:"STORE_UNAVAILABLE".into(),retryable:false,status:None,data:Some(json!({"failureStage":"credential_store","failureCategory":category,"nativeOsStatus":-36,"remoteRevocation":"not_dispatched","protectedStoreRemoved":false})),correlation_id:None}.into();
            let envelope = control::public_error_record(&error);
            let projected: Value = serde_json::from_str(
                &maintenance_failure(&serde_json::to_vec(&envelope).unwrap()).to_string(),
            )
            .unwrap();
            assert_eq!(projected["failureCategory"], category);
            assert_eq!(projected["nativeOsStatus"], -36);
            assert_eq!(projected["remoteRevocation"], "not_dispatched");
        }
    }
    #[test]
    fn maintenance_auth_failures_preserve_conservative_outcomes_and_correlations() {
        for code in ["AUTH_REQUIRED", "AUTH_EXPIRED"] {
            let mut envelope = state::safe_error(code, false);
            assert_eq!(envelope["outcome"], "unknown");
            assert_eq!(envelope["recovery"], "reconcile_outcome");
            let correlation = envelope["correlationId"].clone();
            envelope["message"] = json!("PRIVATE AUTH TEXT");
            envelope["error"] = json!({"token":"PRIVATE"});
            let output = maintenance_failure(&serde_json::to_vec(&envelope).unwrap()).to_string();
            let projected: Value = serde_json::from_str(&output).unwrap();
            assert_eq!(projected["code"], code);
            assert_eq!(projected["outcome"], "unknown");
            assert_eq!(projected["recovery"], "reconcile_outcome");
            assert_eq!(projected["correlationId"], correlation);
            assert!(!output.contains("PRIVATE"));
        }
    }
    #[test]
    fn nested_maintenance_diagnostics_reject_malformed_fields_without_flat_fallback() {
        let error:anyhow::Error=loomex_runner::api::ApiError{code:"AUTH_LOGOUT_FAILED".into(),retryable:false,status:Some(409),data:Some(json!({"failureStage":"SECRET stage","failureCategory":"SECRET category","httpStatus":"409","correlationId":"https://provider.invalid/SECRET","remoteCode":"SECRET provider text","remoteRevocation":"SECRET revocation","protectedStoreRemoved":"false","body":"SECRET body"})),correlation_id:None}.into();
        let mut envelope = control::public_error_record(&error);
        envelope["outcome"] = json!("SECRET outcome");
        envelope["recovery"] = json!("SECRET recovery");
        envelope["failureStage"] = json!("remote_revocation");
        envelope["httpStatus"] = json!(422);
        envelope["remoteCode"] = json!("TOP_LEVEL_CODE");
        let output = maintenance_failure(&serde_json::to_vec(&envelope).unwrap()).to_string();
        let projected: Value = serde_json::from_str(&output).unwrap();
        assert_eq!(projected["failureStage"], "maintenance_daemon");
        assert_eq!(projected["failureCategory"], "unavailable");
        for name in [
            "httpStatus",
            "correlationId",
            "remoteCode",
            "outcome",
            "recovery",
            "remoteRevocation",
            "protectedStoreRemoved",
        ] {
            assert!(
                projected.get(name).is_none(),
                "malformed {name} must be omitted"
            );
        }
        assert!(!output.contains("SECRET") && !output.contains("TOP_LEVEL_CODE"));
    }
}
