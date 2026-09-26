//! Native runner administration state.
//!
//! This module deliberately does not take the daemon lock.  A lifecycle
//! operation may drain or replace the daemon, while workflow execution keeps
//! using `daemon.lock`; the two ownership domains must remain independent.
use anyhow::{Context, Result, bail, ensure};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    fs::{self, File, OpenOptions},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    time::Duration,
};
use uuid::Uuid;

use crate::state;

#[cfg(test)]
use std::sync::atomic::{AtomicBool, Ordering};

#[cfg(test)]
static TEST_MODE: AtomicBool = AtomicBool::new(false);
#[cfg(test)]
static TEST_BOOTOUT_FAIL: AtomicBool = AtomicBool::new(false);
#[cfg(test)]
static TEST_DRAIN_HAS_ACTIVE_WORK: AtomicBool = AtomicBool::new(false);
#[cfg(test)]
static TEST_CANDIDATE_HEALTH_FAIL: AtomicBool = AtomicBool::new(false);
#[cfg(test)]
static TEST_SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
#[cfg(test)]
static TEST_RECOVERY_STATUS: std::sync::Mutex<Option<Value>> = std::sync::Mutex::new(None);
#[cfg(test)]
static TEST_RECOVERY_FAULT: std::sync::Mutex<Option<&'static str>> = std::sync::Mutex::new(None);
#[cfg(test)]
static TEST_RESTART_COUNT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

#[cfg(test)]
fn recovery_fault(stage: &str) -> Result<()> {
    if TEST_RECOVERY_FAULT
        .lock()
        .unwrap()
        .as_ref()
        .is_some_and(|value| *value == stage)
    {
        bail!("injected recovery interruption: {stage}");
    }
    Ok(())
}

fn lifecycle_test_mode() -> bool {
    #[cfg(test)]
    if TEST_MODE.load(Ordering::SeqCst) {
        return true;
    }
    std::env::var_os("LOOMEX_INSTALL_TEST_MODE").as_deref() == Some(std::ffi::OsStr::new("1"))
}

pub const OPERATION_SCHEMA: &str = "app.loomex.runner.lifecycle-operation/v1";
const LOCK_NAME: &str = "lifecycle.lock";
const OPERATION_NAME: &str = "lifecycle-operation.json";
const NATIVE_EXECUTABLES: &[&str] = &["launchctl"];

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum OperationKind {
    Install,
    Update,
    Uninstall,
    Repair,
    Rollback,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Operation {
    pub schema: String,
    pub id: Uuid,
    pub kind: OperationKind,
    pub phase: String,
    pub created_at: u64,
    pub updated_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub package: Option<PackageIdentity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_target: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resources: Option<OperationResources>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkpoint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PackageIdentity {
    pub version: String,
    pub target: PathBuf,
    pub manifest_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct OperationResources {
    pub launch_agent: PathBuf,
    pub staged_launch_agent: PathBuf,
    pub staged_launch_agent_sha256: String,
    pub launch_agent_backup: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub launch_agent_backup_sha256: Option<String>,
    pub owned_versions: Vec<PathBuf>,
}

impl Operation {
    pub fn new(kind: OperationKind, phase: impl Into<String>, detail: Option<String>) -> Self {
        let now = state::now();
        Self {
            schema: OPERATION_SCHEMA.into(),
            id: Uuid::new_v4(),
            kind,
            phase: phase.into(),
            created_at: now,
            updated_at: now,
            detail,
            package: None,
            previous_target: None,
            resources: None,
            checkpoint: None,
        }
    }

    fn validate(&self) -> Result<()> {
        if self.schema != OPERATION_SCHEMA || self.phase.is_empty() || self.phase.len() > 128 {
            bail!("invalid lifecycle operation")
        }
        if let Some(package) = &self.package {
            if !package.target.is_absolute()
                || package.manifest_sha256.len() != 64
                || !package
                    .manifest_sha256
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit())
            {
                bail!("invalid lifecycle package identity")
            }
        }
        if let Some(resources) = &self.resources {
            if !resources.launch_agent.is_absolute()
                || !resources.staged_launch_agent.is_absolute()
                || !resources.launch_agent_backup.is_absolute()
                || resources.staged_launch_agent_sha256.len() != 64
                || !resources
                    .staged_launch_agent_sha256
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit())
                || resources.owned_versions.is_empty()
            {
                bail!("invalid lifecycle resource inventory")
            }
            if let Some(digest) = &resources.launch_agent_backup_sha256
                && (digest.len() != 64 || !digest.bytes().all(|b| b.is_ascii_hexdigit()))
            {
                bail!("invalid lifecycle LaunchAgent backup digest")
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct Paths {
    pub install_base: PathBuf,
    pub state_dir: PathBuf,
    pub launch_agents_dir: PathBuf,
}

impl Paths {
    pub fn from_environment() -> Result<Self> {
        let home = PathBuf::from(std::env::var_os("HOME").context("HOME is missing")?);
        let install_base = std::env::var_os("LOOMEX_INSTALL_BASE")
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join("Library/Application Support/Loomex/runner"));
        let state_dir = state::state_dir()?;
        let launch_agents_dir = std::env::var_os("LOOMEX_LAUNCH_AGENTS_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join("Library/LaunchAgents"));
        let paths = Self {
            install_base,
            state_dir,
            launch_agents_dir,
        };
        paths.validate()?;
        Ok(paths)
    }

    pub fn validate(&self) -> Result<()> {
        let home = PathBuf::from(std::env::var_os("HOME").context("HOME is missing")?);
        for path in [&self.install_base, &self.state_dir, &self.launch_agents_dir] {
            if !path.is_absolute() || path == Path::new("/") || *path == home {
                bail!("unsafe lifecycle directory")
            }
            validate_lifecycle_root(path)?;
        }
        Ok(())
    }

    fn versions(&self) -> PathBuf {
        self.install_base.join("versions")
    }
    fn current(&self) -> PathBuf {
        self.install_base.join("current")
    }
    fn operation(&self) -> PathBuf {
        self.state_dir.join(OPERATION_NAME)
    }
}

/// Validate a lifecycle root without resolving it.  `canonicalize` is too late
/// for this boundary: it follows a malicious component before the caller gets
/// a chance to reject it.  We inspect every existing component lexically, and
/// require the root (or the directory in which it will be created) to be owned
/// by this user and not writable by group or world.
fn validate_lifecycle_root(path: &Path) -> Result<()> {
    let uid = unsafe { libc::geteuid() };
    let mut current = PathBuf::from("/");
    let mut nearest_existing = None;
    for component in path.components().skip(1) {
        current.push(component.as_os_str());
        match fs::symlink_metadata(&current) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() {
                    bail!("lifecycle directory contains a symlink component")
                }
                if !metadata.is_dir() {
                    bail!("lifecycle directory component is not a directory")
                }
                nearest_existing = Some((current.clone(), metadata));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
            Err(error) => return Err(error.into()),
        }
    }
    let (existing, metadata) = nearest_existing.context("lifecycle root has no existing parent")?;
    // System-owned ancestors such as / and /Users are expected.  The exact
    // root, or the directory that will receive the first new component, is the
    // mutation boundary and must be private to the invoking user.
    if existing != Path::new("/") && (metadata.uid() != uid || metadata.mode() & 0o022 != 0) {
        bail!("lifecycle root is not privately owned")
    }
    Ok(())
}

/// An exclusive, advisory OS lock.  The guard owns the descriptor for the
/// entire operation, so a crash automatically releases it.
pub struct LifecycleLock(File);

impl LifecycleLock {
    pub fn acquire(paths: &Paths) -> Result<Self> {
        paths.validate()?;
        state::private_dir(&paths.state_dir)?;
        let path = paths.state_dir.join(LOCK_NAME);
        if fs::symlink_metadata(&path).is_ok_and(|m| m.file_type().is_symlink()) {
            bail!("unsafe lifecycle lock")
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(path)?;
        file.try_lock_exclusive()
            .map_err(|_| anyhow::anyhow!("LIFECYCLE_BUSY"))?;
        Ok(Self(file))
    }
}

impl Drop for LifecycleLock {
    fn drop(&mut self) {
        let _ = FileExt::unlock(&self.0);
    }
}

fn read_optional<T: for<'a> Deserialize<'a>>(path: &Path) -> Result<Option<T>> {
    if !path.exists() {
        return Ok(None);
    }
    if fs::symlink_metadata(path)?.file_type().is_symlink() {
        bail!("unsafe lifecycle state")
    }
    Ok(Some(state::read_json(path)?))
}

fn validate_version_path(versions: &Path, value: &str) -> Result<PathBuf> {
    let raw = PathBuf::from(value);
    if !raw.is_absolute() || fs::symlink_metadata(&raw)?.file_type().is_symlink() {
        bail!("unsafe owned version path")
    }
    let parent = fs::canonicalize(raw.parent().context("version has no parent")?)?;
    let versions = fs::canonicalize(versions)?;
    let semver = raw.file_name().and_then(|v| v.to_str()).is_some_and(|v| {
        let p: Vec<_> = v.split('.').collect();
        p.len() == 3
            && p.iter()
                .all(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
    });
    if parent != versions || !semver {
        bail!("unsafe owned version path")
    }
    Ok(raw)
}

fn owned_versions(paths: &Paths) -> Result<Vec<PathBuf>> {
    #[derive(Deserialize)]
    struct Owned {
        schema: String,
        paths: Vec<String>,
    }
    let owned: Owned = state::read_json(&paths.state_dir.join("owned-versions.json"))?;
    if owned.schema != "app.loomex.runner.owned-versions/v1" || owned.paths.is_empty() {
        bail!("invalid owned versions inventory")
    }
    owned
        .paths
        .iter()
        .map(|p| validate_version_path(&paths.versions(), p))
        .collect()
}

fn verify_owned_version(paths: &Paths, target: &Path) -> Result<()> {
    let owned: Value = state::read_json(&paths.state_dir.join("owned-versions.json"))?;
    verify_owned_version_from_inventory(target, &owned)
}

/// Validate a retained version against the immutable inventory captured in an
/// operation/uninstall journal.  This remains usable after the live ownership
/// file has been removed during a partial uninstall.
pub fn verify_owned_version_from_inventory(target: &Path, owned: &Value) -> Result<()> {
    let inventories = owned["inventories"]
        .as_array()
        .context("owned version inventory has no signed file inventory")?;
    let expected = inventories
        .iter()
        .find(|entry| entry["path"].as_str() == Some(target.to_string_lossy().as_ref()))
        .and_then(|entry| entry["files"].as_array())
        .context("owned version has no signed file inventory")?;
    let mut actual = Vec::new();
    fn visit(root: &Path, directory: &Path, output: &mut Vec<Value>) -> Result<()> {
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path)?;
            if metadata.file_type().is_symlink() {
                bail!("installed package contains a symlink")
            }
            if metadata.is_dir() {
                visit(root, &path, output)?;
            } else if metadata.is_file() {
                output.push(json!({"path":path.strip_prefix(root)?.to_string_lossy(),"sha256":state::digest(&fs::read(&path)?),"size":metadata.len(),"mode":metadata.permissions().mode() & 0o777}));
            } else {
                bail!("installed package contains an unsupported entry")
            }
        }
        Ok(())
    }
    visit(target, target, &mut actual)?;
    actual.sort_by(|a, b| a["path"].as_str().cmp(&b["path"].as_str()));
    if &actual != expected {
        bail!("owned version no longer matches the release inventory")
    }
    Ok(())
}

fn verify_all_owned_versions(paths: &Paths) -> Result<()> {
    for version in owned_versions(paths)? {
        verify_owned_version(paths, &version)?;
    }
    Ok(())
}

fn validate_rollback_target(target: &Path, version: &str) -> Result<()> {
    let metadata = fs::symlink_metadata(target)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        bail!("unsafe rollback target")
    }
    let project: Value = state::read_json(&target.join("metadata/project.json"))?;
    if project["project"] != "loomex-runner"
        || project["version"] != version
        || project["platform"] != "darwin-arm64"
    {
        bail!("rollback target metadata does not match requested version")
    }
    if fs::read(target.join("metadata/compatibility-manifest.json"))?
        != include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/contracts/compatibility-manifest.json"
        ))
    {
        bail!("rollback target compatibility manifest differs from this CLI")
    }
    let binary = target.join("bin/loomex");
    let metadata = fs::symlink_metadata(binary)?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.permissions().mode() & 0o111 == 0
    {
        bail!("rollback target CLI is not executable")
    }
    Ok(())
}

fn validate_rollback_status(response: &Value) -> Result<()> {
    let status = response["result"]
        .as_object()
        .context("lifecycle status is unavailable")?;
    let active = status
        .get("activeJobs")
        .and_then(Value::as_u64)
        .context("lifecycle status has no active-job count")?;
    if active != 0 || status.get("draining").and_then(Value::as_bool) != Some(true) {
        bail!("ROLLBACK_REQUIRES_DRAINED_IDLE_DAEMON")
    }
    Ok(())
}

fn launch_agent(paths: &Paths) -> PathBuf {
    paths.launch_agents_dir.join("app.loomex.runner.plist")
}

fn current_target(paths: &Paths) -> Result<Option<PathBuf>> {
    let link = paths.current();
    let target = match fs::read_link(&link) {
        Ok(value) => value,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let target = if target.is_absolute() {
        target
    } else {
        paths.install_base.join(target)
    };
    Ok(Some(validate_version_path(
        &paths.versions(),
        &target.display().to_string(),
    )?))
}

fn checked_regular(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        bail!("unsafe lifecycle resource")
    }
    Ok(())
}

fn replace_regular_atomically(
    source: &Path,
    destination: &Path,
    operation: &Operation,
) -> Result<()> {
    checked_regular(source)?;
    if destination.exists() {
        checked_regular(destination)?;
    }
    let parent = destination
        .parent()
        .context("lifecycle resource has no parent")?;
    let temporary = parent.join(format!(
        ".{}.{}.new",
        destination
            .file_name()
            .and_then(|v| v.to_str())
            .context("invalid lifecycle resource name")?,
        operation.id
    ));
    if temporary.exists() || temporary.is_symlink() {
        bail!("lifecycle plist temporary already exists")
    }
    let bytes = fs::read(source)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)?;
    use std::io::Write;
    file.write_all(&bytes)?;
    file.sync_all()?;
    fs::rename(&temporary, destination)?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

fn remove_regular_and_sync(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.is_file() || metadata.file_type().is_symlink() {
                bail!("unsafe lifecycle resource")
            }
            fs::remove_file(path)?;
            File::open(path.parent().context("lifecycle resource has no parent")?)?.sync_all()?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

fn installed_tree_digest(root: &Path) -> Result<String> {
    fn visit(
        root: &Path,
        directory: &Path,
        entries: &mut Vec<(String, String, u32)>,
    ) -> Result<()> {
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path)?;
            if metadata.file_type().is_symlink() {
                bail!("installed package contains a symlink")
            }
            if metadata.is_dir() {
                visit(root, &path, entries)?;
            } else if metadata.is_file() {
                entries.push((
                    path.strip_prefix(root)?.to_string_lossy().into_owned(),
                    state::digest(&fs::read(&path)?),
                    metadata.permissions().mode() & 0o777,
                ));
            } else {
                bail!("installed package contains an unsupported entry")
            }
        }
        Ok(())
    }
    let mut entries = Vec::new();
    visit(root, root, &mut entries)?;
    entries.sort();
    Ok(state::digest(&serde_json::to_vec(&entries)?))
}

fn write_pointer(paths: &Paths, target: &Path, operation: &Operation) -> Result<()> {
    fs::create_dir_all(&paths.install_base)?;
    let temporary = paths
        .install_base
        .join(format!(".current.{}.new", operation.id));
    if temporary.exists() || temporary.is_symlink() {
        bail!("lifecycle pointer temporary already exists")
    }
    if paths.current().exists() && !paths.current().is_symlink() {
        bail!("current installation pointer is not a symlink")
    }
    std::os::unix::fs::symlink(target, &temporary)?;
    fs::rename(&temporary, paths.current())?;
    File::open(&paths.install_base)?.sync_all()?;
    Ok(())
}

async fn launchctl(action: &str, agent: &Path) -> Result<()> {
    if (action == "bootout"
        && (std::env::var_os("LOOMEX_LIFECYCLE_TEST_BOOTOUT_FAIL").is_some() || {
            #[cfg(test)]
            {
                TEST_BOOTOUT_FAIL.load(Ordering::SeqCst)
            }
            #[cfg(not(test))]
            {
                false
            }
        }))
        || (action == "bootstrap"
            && std::env::var_os("LOOMEX_LIFECYCLE_TEST_BOOTSTRAP_FAIL").is_some())
    {
        bail!("injected lifecycle service failure")
    }
    if lifecycle_test_mode() {
        #[cfg(test)]
        if action == "kickstart" {
            recovery_fault("restart_failed")?;
            TEST_RESTART_COUNT.fetch_add(1, Ordering::SeqCst);
            if let Some(status) = TEST_RECOVERY_STATUS.lock().unwrap().as_mut() {
                status["draining"] = json!(false);
            }
        }
        return Ok(());
    }
    let uid = unsafe { libc::geteuid() };
    let status = match action {
        "bootout" => {
            tokio::process::Command::new(NATIVE_EXECUTABLES[0])
                .arg("bootout")
                .arg(format!("gui/{uid}/app.loomex.runner"))
                .status()
                .await?
        }
        "bootstrap" => {
            tokio::process::Command::new(NATIVE_EXECUTABLES[0])
                .arg("bootstrap")
                .arg(format!("gui/{uid}"))
                .arg(agent)
                .status()
                .await?
        }
        "kickstart" => {
            tokio::process::Command::new(NATIVE_EXECUTABLES[0])
                .arg("kickstart")
                .arg("-k")
                .arg(format!("gui/{uid}/app.loomex.runner"))
                .status()
                .await?
        }
        _ => bail!("invalid launchctl lifecycle action"),
    };
    if !status.success() {
        // A non-zero bootout is only harmless if launchd confirms that the
        // exact label is already absent.  Treating every non-zero exit as
        // success can switch files while the old daemon still owns work.
        if action != "bootout" || !launchctl_label_absent().await? {
            bail!("launchctl lifecycle operation failed")
        }
        return Ok(());
    }
    if action == "bootout" && !launchctl_label_absent().await? {
        bail!("launchctl service remained loaded after bootout")
    }
    // `bootstrap` registers a LaunchAgent but does not reliably start it on
    // every supported launchd state, even when the plist declares RunAtLoad.
    // Start the exact registered label before the health check so activation
    // observes a running candidate rather than merely a loaded definition.
    if action == "bootstrap" {
        let status = tokio::process::Command::new(NATIVE_EXECUTABLES[0])
            .arg("kickstart")
            .arg("-k")
            .arg(format!("gui/{uid}/app.loomex.runner"))
            .status()
            .await?;
        if !status.success() {
            bail!("launchctl failed to start lifecycle service")
        }
    }
    Ok(())
}

async fn launchctl_label_absent() -> Result<bool> {
    if lifecycle_test_mode() {
        return Ok(true);
    }
    let uid = unsafe { libc::geteuid() };
    // launchd can acknowledge bootout before `print` observes the final
    // teardown.  This is bounded observation, not a blind delay.
    for _ in 0..20 {
        let status = tokio::process::Command::new(NATIVE_EXECUTABLES[0])
            .arg("print")
            .arg(format!("gui/{uid}/app.loomex.runner"))
            .status()
            .await?;
        if !status.success() {
            return Ok(true);
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    Ok(false)
}

async fn daemon_status(paths: &Paths) -> Result<Value> {
    #[cfg(test)]
    if let Some(status) = TEST_RECOVERY_STATUS.lock().unwrap().clone() {
        return Ok(status);
    }
    let response =
        crate::control::lifecycle_client(&paths.state_dir, "status.get", json!({})).await?;
    response
        .get("result")
        .cloned()
        .context("lifecycle status is unavailable")
}

async fn drain_and_require_idle(paths: &Paths, required: bool) -> Result<()> {
    if lifecycle_test_mode() {
        #[cfg(test)]
        if TEST_DRAIN_HAS_ACTIVE_WORK.load(Ordering::SeqCst) {
            bail!("ROLLBACK_REQUIRES_DRAINED_IDLE_DAEMON")
        }
        return Ok(());
    }
    match crate::control::lifecycle_client(
        &paths.state_dir,
        "daemon.drain",
        json!({"idempotencyKey":Uuid::new_v4()}),
    )
    .await
    {
        Ok(response) if response["result"]["draining"] == true => {}
        Ok(response) if response["error"]["code"] == "ACTIVE_WORK_REQUIRES_DRAIN" => {
            bail!("ROLLBACK_REQUIRES_DRAINED_IDLE_DAEMON")
        }
        Ok(_) => bail!("LIFECYCLE_DRAIN_REJECTED"),
        Err(_error) if !required => return Ok(()),
        Err(error) => return Err(error),
    }
    let status = daemon_status(paths).await?;
    validate_rollback_status(&json!({"result":status}))
}

async fn healthy_candidate(paths: &Paths, version: &str) -> Result<()> {
    #[cfg(test)]
    if TEST_CANDIDATE_HEALTH_FAIL.load(Ordering::SeqCst) {
        bail!("candidate health is unconfirmed")
    }
    for _ in 0..20 {
        if let Ok(status) = daemon_status(paths).await
            && status["version"] == version
            && status["activeJobs"].as_u64().is_some()
            && status["draining"] == false
        {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    bail!("candidate health is unconfirmed")
}

fn candidate_health_check_required() -> bool {
    if !lifecycle_test_mode() {
        return true;
    }
    #[cfg(test)]
    {
        TEST_CANDIDATE_HEALTH_FAIL.load(Ordering::SeqCst)
    }
    #[cfg(not(test))]
    {
        false
    }
}

fn regular_digest(path: &Path) -> Result<Option<String>> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.is_file() || metadata.file_type().is_symlink() {
                bail!("unsafe lifecycle resource")
            }
            Ok(Some(state::digest(&fs::read(path)?)))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn set_checkpoint(
    paths: &Paths,
    operation: &mut Operation,
    phase: &str,
    checkpoint: &str,
) -> Result<()> {
    operation.phase = phase.into();
    operation.checkpoint = Some(checkpoint.into());
    operation.updated_at = state::now();
    save_operation(paths, operation)
}

fn terminal(phase: &str) -> bool {
    matches!(phase, "completed" | "rolled_back")
}

/// Validate a persisted lifecycle operation before a caller decides whether a
/// bootstrap-local retry record may be superseded.  The terminal decision is
/// deliberately owned here so callers cannot treat malformed state as safe to
/// discard.
pub fn operation_is_terminal(operation: &Operation) -> Result<bool> {
    operation.validate()?;
    Ok(terminal(&operation.phase))
}

/// Reconcile an interrupted install before a bootstrap stages another package
/// or changes the ownership inventory.  The caller supplies the release-bound
/// identity; differing identities are never allowed to share a journal.
pub async fn preflight_package(
    paths: &Paths,
    kind: OperationKind,
    package: PackageIdentity,
) -> Result<Value> {
    let _lock = LifecycleLock::acquire(paths)?;
    preflight_package_locked(paths, kind, package).await
}

/// Caller already owns `LifecycleLock`; used by bootstrap to make preflight,
/// extraction, inventory and activation one serialized transaction.
pub async fn preflight_package_locked(
    paths: &Paths,
    kind: OperationKind,
    package: PackageIdentity,
) -> Result<Value> {
    if let Some(value) = reconcile_matching_operation(paths, kind, &package).await? {
        if value["pending"] == true {
            return Ok(json!({"reconciled":false,"pending":true,"transaction":value}));
        }
        return Ok(json!({"reconciled":true,"transaction":value}));
    }
    Ok(json!({"reconciled":false}))
}

/// A second installer must never replace an unfinished transaction with a new
/// journal.  It may only finish reconciling the *same* package transaction.
/// This is intentionally checked while the lifecycle lock is held, after all
/// caller supplied values have been validated but before any service resource
/// is captured or replaced.
async fn reconcile_matching_operation(
    paths: &Paths,
    kind: OperationKind,
    package: &PackageIdentity,
) -> Result<Option<Value>> {
    let Some(mut existing) = read_optional::<Operation>(&paths.operation())? else {
        return Ok(None);
    };
    existing.validate()?;
    if terminal(&existing.phase) {
        if existing.phase == "completed"
            && existing.kind == kind
            && existing.package.as_ref() == Some(package)
        {
            let resources = existing
                .resources
                .as_ref()
                .context("completed lifecycle operation has no resources")?;
            ensure!(
                current_target(paths)?.as_ref() == Some(&package.target)
                    && regular_digest(&resources.launch_agent)?.as_deref()
                        == Some(&resources.staged_launch_agent_sha256),
                "LIFECYCLE_COMPLETED_STATE_MISMATCH"
            );
            verify_owned_version(paths, &package.target)?;
            if candidate_health_check_required() {
                healthy_candidate(paths, &package.version).await?;
            }
            return Ok(Some(json!({"reconciled":true,"operation":existing})));
        }
        return Ok(None);
    }
    if existing.kind != kind || existing.package.as_ref() != Some(package) {
        bail!("LIFECYCLE_OPERATION_IDENTITY_MISMATCH")
    }
    if existing.resources.is_none() {
        // This is a protected migration/repair operation.  Starting another
        // install over it would discard the only durable description of the
        // interrupted namespace.
        bail!("LIFECYCLE_OPERATION_PENDING")
    }
    let value = reconcile_activation(paths, &mut existing).await?;
    if existing.phase == "completed" {
        return Ok(Some(value));
    }
    if existing.phase == "rolled_back" {
        return Ok(None);
    }
    if value["pending"] == true {
        return Ok(Some(value));
    }
    bail!("LIFECYCLE_OPERATION_PENDING")
}

async fn restore_activation(paths: &Paths, operation: &mut Operation) -> Result<()> {
    let resources = operation
        .resources
        .as_ref()
        .context("activation resources missing")?;
    // The candidate must be visibly idle before a prior daemon can be restored.
    // If it never reached launchd (for example bootstrap failed), launchd must
    // still prove the label absent.  We never infer that from an operation
    // phase alone.
    match daemon_status(paths).await {
        Ok(_) => {
            let drained = crate::control::lifecycle_client(
                &paths.state_dir,
                "daemon.drain",
                json!({"idempotencyKey":Uuid::new_v4()}),
            )
            .await?;
            ensure!(
                drained["result"]["draining"] == true,
                "LIFECYCLE_DRAIN_REJECTED"
            );
            validate_rollback_status(&json!({"result":daemon_status(paths).await?}))?;
        }
        Err(_) if launchctl_label_absent().await? => {}
        Err(error) => return Err(error.context("candidate state cannot be proven safe")),
    }
    launchctl("bootout", &resources.launch_agent).await?;
    match &operation.previous_target {
        Some(previous) => write_pointer(paths, previous, operation)?,
        None => {
            if paths.current().exists() || paths.current().is_symlink() {
                fs::remove_file(paths.current())?;
            }
        }
    }
    if resources.launch_agent_backup.exists() {
        checked_regular(&resources.launch_agent_backup)?;
        if let Some(expected) = &resources.launch_agent_backup_sha256
            && state::digest(&fs::read(&resources.launch_agent_backup)?) != *expected
        {
            bail!("stored LaunchAgent backup changed during recovery")
        }
        replace_regular_atomically(
            &resources.launch_agent_backup,
            &resources.launch_agent,
            operation,
        )?;
    } else if resources.launch_agent.exists() {
        remove_regular_and_sync(&resources.launch_agent)?;
    }
    if let Some(previous) = &operation.previous_target {
        launchctl("bootstrap", &resources.launch_agent).await?;
        if candidate_health_check_required() {
            let version = previous
                .file_name()
                .and_then(|value| value.to_str())
                .context("previous runner version is invalid")?;
            healthy_candidate(paths, version).await?;
        }
    }
    set_checkpoint(paths, operation, "rolled_back", "previous_service_restored")
}

/// Reconcile from the observable pointer, plist and launchd/control state.
/// Journal checkpoints show what the writer intended, not what survived a
/// crash; this function deliberately never treats a checkpoint as evidence.
async fn reconcile_activation(paths: &Paths, operation: &mut Operation) -> Result<Value> {
    let package = operation
        .package
        .clone()
        .context("activation package missing")?;
    let resources = operation
        .resources
        .clone()
        .context("activation resources missing")?;
    if operation.phase == "pending_active_work" {
        return continue_pending_activation(paths, operation, &package, &resources).await;
    }
    let pointer = current_target(paths)?;
    let plist_digest = regular_digest(&resources.launch_agent)?;
    let candidate_plist_matches =
        plist_digest.as_deref() == Some(&resources.staged_launch_agent_sha256);
    if operation.phase == "recovery_required"
        && pointer.as_ref() == Some(&package.target)
        && candidate_plist_matches
    {
        let status = daemon_status(paths).await?;
        if candidate_drain_can_be_released(&status, &package.version) {
            // A failed retry can leave the already-activated candidate drained.
            // Only the exact journaled candidate, with no managed work, may be
            // returned to service while the lifecycle lock is held.
            #[cfg(test)]
            recovery_fault("before_drain_removal")?;
            let drain = paths.state_dir.join("drain.json");
            if drain.exists() || drain.is_symlink() {
                remove_regular_and_sync(&drain)?;
            }
            #[cfg(test)]
            recovery_fault("after_drain_removal")?;
            // The daemon also holds its draining state in memory. Restart the
            // exact registered service after proving it has no managed jobs.
            launchctl("kickstart", &resources.launch_agent).await?;
            #[cfg(test)]
            recovery_fault("after_restart")?;
        }
    }
    if pointer.as_ref() == Some(&package.target)
        && candidate_plist_matches
        && healthy_candidate(paths, &package.version).await.is_ok()
    {
        #[cfg(test)]
        recovery_fault("before_completion")?;
        set_checkpoint(
            paths,
            operation,
            "completed",
            "candidate_healthy_after_reconciliation",
        )?;
        return Ok(json!({"resumed":true,"state":"candidate_healthy","operation":operation}));
    }

    // If the old target and its exact plist are already visible, bootstrap and
    // health-check it before declaring rollback.  This repairs a crash between
    // replacement steps without assuming the phase describes reality.
    let previous_plist_matches = match &resources.launch_agent_backup_sha256 {
        Some(expected) => plist_digest.as_deref() == Some(expected),
        None => plist_digest.is_none(),
    };
    if pointer == operation.previous_target && previous_plist_matches {
        if let Some(previous) = &operation.previous_target {
            let version = previous
                .file_name()
                .and_then(|value| value.to_str())
                .context("previous runner version is invalid")?;
            if healthy_candidate(paths, version).await.is_err() {
                if !launchctl_label_absent().await? {
                    bail!("previous runner health is unconfirmed and launchd label remains loaded")
                }
                launchctl("bootstrap", &resources.launch_agent).await?;
                if candidate_health_check_required() {
                    healthy_candidate(paths, version).await?;
                }
            }
        }
        set_checkpoint(
            paths,
            operation,
            "rolled_back",
            "previous_service_healthy_after_reconciliation",
        )?;
        return Ok(json!({"resumed":true,"state":"previous_healthy","operation":operation}));
    }

    // A pointer/plist mismatch cannot be repaired by merely starting a daemon.
    // `restore_activation` first proves the candidate safe, then restores the
    // exact saved resources and verifies the previous version.
    restore_activation(paths, operation).await?;
    Ok(json!({"resumed":true,"state":"previous_restored","operation":operation}))
}

fn candidate_drain_can_be_released(status: &Value, version: &str) -> bool {
    status["version"] == version
        && status["activeJobs"].as_u64() == Some(0)
        && status["draining"] == true
}

/// `pending_active_work` is an intentional pause before any service switch.
/// Re-check the daemon and continue this exact journal once it is idle; do not
/// mistake the still-running old daemon for a failed candidate.
async fn continue_pending_activation(
    paths: &Paths,
    operation: &mut Operation,
    package: &PackageIdentity,
    resources: &OperationResources,
) -> Result<Value> {
    if let Err(error) = drain_and_require_idle(paths, operation.previous_target.is_some()).await {
        if error
            .to_string()
            .contains("ROLLBACK_REQUIRES_DRAINED_IDLE_DAEMON")
        {
            return Ok(
                json!({"resumed":false,"pending":true,"reason":"active_work","operation":operation}),
            );
        }
        return Err(error);
    }
    set_checkpoint(paths, operation, "draining", "daemon_drained_after_pending")?;
    launchctl("bootout", &resources.launch_agent).await?;
    set_checkpoint(paths, operation, "service_stopped", "old_service_stopped")?;
    write_pointer(paths, &package.target, operation)?;
    if state::digest(&fs::read(&resources.staged_launch_agent)?)
        != resources.staged_launch_agent_sha256
    {
        bail!("staged LaunchAgent changed during pending update")
    }
    replace_regular_atomically(
        &resources.staged_launch_agent,
        &resources.launch_agent,
        operation,
    )?;
    set_checkpoint(
        paths,
        operation,
        "pointer_switched",
        "pointer_and_plist_switched",
    )?;
    remove_regular_and_sync(&paths.state_dir.join("drain.json"))?;
    launchctl("bootstrap", &resources.launch_agent).await?;
    if candidate_health_check_required() {
        healthy_candidate(paths, &package.version).await?;
    }
    set_checkpoint(
        paths,
        operation,
        "completed",
        "candidate_healthy_after_pending",
    )?;
    Ok(json!({"resumed":true,"state":"candidate_healthy_after_pending","operation":operation}))
}

/// Performs the service half of a verified installation/update after the
/// compatibility wrapper has verified and staged the package.  All mutable
/// resources are captured in the operation before the first service action.
pub async fn activate(
    paths: &Paths,
    target: PathBuf,
    version: String,
    manifest_sha256: String,
    staged_launch_agent: PathBuf,
) -> Result<Value> {
    let _lock = LifecycleLock::acquire(paths)?;
    activate_as_locked(
        paths,
        OperationKind::Update,
        target,
        version,
        manifest_sha256,
        staged_launch_agent,
    )
    .await
}

async fn activate_as(
    paths: &Paths,
    kind: OperationKind,
    target: PathBuf,
    version: String,
    manifest_sha256: String,
    staged_launch_agent: PathBuf,
) -> Result<Value> {
    let _lock = LifecycleLock::acquire(paths)?;
    activate_as_locked(
        paths,
        kind,
        target,
        version,
        manifest_sha256,
        staged_launch_agent,
    )
    .await
}

/// Complete activation while the caller owns the lifecycle lock.
pub async fn activate_locked(
    paths: &Paths,
    target: PathBuf,
    version: String,
    manifest_sha256: String,
    staged_launch_agent: PathBuf,
) -> Result<Value> {
    activate_as_locked(
        paths,
        OperationKind::Update,
        target,
        version,
        manifest_sha256,
        staged_launch_agent,
    )
    .await
}

async fn activate_as_locked(
    paths: &Paths,
    kind: OperationKind,
    target: PathBuf,
    version: String,
    manifest_sha256: String,
    staged_launch_agent: PathBuf,
) -> Result<Value> {
    if manifest_sha256.len() != 64 || !manifest_sha256.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("invalid manifest digest")
    }
    let target = validate_version_path(&paths.versions(), &target.display().to_string())?;
    if !owned_versions(paths)?.contains(&target) {
        bail!("activation target is not owned")
    }
    verify_all_owned_versions(paths)?;
    validate_rollback_target(&target, &version)?;
    checked_regular(&staged_launch_agent)?;
    let package = PackageIdentity {
        version: version.clone(),
        target: target.clone(),
        manifest_sha256: manifest_sha256.clone(),
    };
    // A terminal journal still owns its operation-specific staging files.
    // Release those exact files before this writer replaces the journal with a
    // new transaction; if this cleanup is interrupted the terminal journal
    // remains durable and the next attempt repeats the idempotent cleanup.
    release_terminal_operation_resources_before_supersede(paths)?;
    if let Some(value) = reconcile_matching_operation(paths, kind, &package).await? {
        if value["pending"] == true {
            return Ok(
                json!({"activated":false,"pending":true,"resumed":true,"transaction":value}),
            );
        }
        return Ok(json!({"activated":true,"resumed":true,"transaction":value}));
    }
    let previous_target = current_target(paths)?;
    let agent = launch_agent(paths);
    if agent.exists() {
        checked_regular(&agent)?;
    }
    let mut operation = Operation::new(
        kind,
        "prepared",
        Some("verified package staged by compatibility installer".into()),
    );
    operation.package = Some(package);
    operation.previous_target = previous_target;
    // Resource names are bound to this operation before any bytes are copied.
    // A crash after the journal write is therefore recoverable (or remains a
    // protected repair state) rather than leaving a staged file attributed to
    // whichever installer happens to run next.
    let staged_copy = paths
        .state_dir
        .join(format!("lifecycle-staged-{}.plist", operation.id));
    let backup = paths
        .state_dir
        .join(format!("lifecycle-agent-{}.plist", operation.id));
    operation.resources = Some(OperationResources {
        launch_agent: agent.clone(),
        staged_launch_agent: staged_copy.clone(),
        staged_launch_agent_sha256: state::digest(&fs::read(&staged_launch_agent)?),
        launch_agent_backup: backup.clone(),
        launch_agent_backup_sha256: None,
        owned_versions: owned_versions(paths)?,
    });
    operation.checkpoint = Some("resources_captured".into());
    save_operation(paths, &operation)?;
    // The journal now owns both resources.  Do not use the caller's staging
    // path after this point: bootstrap cleanup may remove that directory.
    replace_regular_atomically(&staged_launch_agent, &staged_copy, &operation)?;
    if agent.exists() {
        replace_regular_atomically(&agent, &backup, &operation)?;
        operation
            .resources
            .as_mut()
            .context("activation resources missing")?
            .launch_agent_backup_sha256 = Some(state::digest(&fs::read(&backup)?));
        save_operation(paths, &operation)?;
    }
    let staged_launch_agent_sha256 = operation
        .resources
        .as_ref()
        .context("activation resources missing")?
        .staged_launch_agent_sha256
        .clone();

    let result: Result<()> = async {
        drain_and_require_idle(paths, operation.previous_target.is_some()).await?;
        set_checkpoint(paths, &mut operation, "draining", "daemon_drained")?;
        launchctl("bootout", &agent).await?;
        set_checkpoint(
            paths,
            &mut operation,
            "service_stopped",
            "old_service_stopped",
        )?;
        write_pointer(paths, &target, &operation)?;
        if staged_copy != agent {
            if state::digest(&fs::read(&staged_copy)?) != staged_launch_agent_sha256 {
                bail!("staged LaunchAgent changed after lifecycle preparation")
            }
            replace_regular_atomically(&staged_copy, &agent, &operation)?;
        }
        set_checkpoint(
            paths,
            &mut operation,
            "pointer_switched",
            "pointer_and_plist_switched",
        )?;
        let drain = paths.state_dir.join("drain.json");
        if drain.exists() && !fs::symlink_metadata(&drain)?.file_type().is_symlink() {
            fs::remove_file(drain)?;
        }
        launchctl("bootstrap", &agent).await?;
        set_checkpoint(
            paths,
            &mut operation,
            "candidate_started",
            "candidate_bootstrapped",
        )?;
        if candidate_health_check_required() {
            healthy_candidate(paths, &version).await?;
        }
        set_checkpoint(paths, &mut operation, "completed", "candidate_healthy")
    }
    .await;
    match result {
        Ok(()) => Ok(json!({"activated":true,"operation":operation})),
        Err(error) => {
            if error
                .to_string()
                .contains("ROLLBACK_REQUIRES_DRAINED_IDLE_DAEMON")
            {
                set_checkpoint(
                    paths,
                    &mut operation,
                    "pending_active_work",
                    "daemon_has_active_work",
                )?;
                return Ok(
                    json!({"activated":false,"pending":true,"reason":"active_work","operation":operation}),
                );
            }
            if restore_activation(paths, &mut operation).await.is_err() {
                set_checkpoint(
                    paths,
                    &mut operation,
                    "recovery_required",
                    "candidate_or_previous_service_not_safe_to_restore",
                )?;
                return Err(
                    error.context("activation failed; service state requires lifecycle repair")
                );
            }
            Err(error.context("activation failed; previous service restored"))
        }
    }
}

fn legacy(path: &Path) -> Result<Option<Value>> {
    read_optional(path)
}

pub fn status(paths: &Paths) -> Result<Value> {
    let operation = read_optional::<Operation>(&paths.operation())?;
    if let Some(op) = &operation {
        op.validate()?;
    }
    let current = match fs::read_link(paths.current()) {
        Ok(target) => Some(target.to_string_lossy().into_owned()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error.into()),
    };
    let legacy_install = legacy(&paths.state_dir.join("install-operation.json"))?.is_some();
    let legacy_uninstall = legacy(&paths.state_dir.join("uninstall-operation.json"))?.is_some();
    let native_pending = operation
        .as_ref()
        .is_some_and(|op| !matches!(op.phase.as_str(), "completed" | "rolled_back"));
    Ok(json!({
        "schema":"app.loomex.runner.lifecycle-status/v1",
        "current":current,
        "operation":operation,
        "legacyJournal":{"install":legacy_install,"uninstall":legacy_uninstall},
        "actionRequired": native_pending || legacy_install || legacy_uninstall,
    }))
}

fn save_operation(paths: &Paths, operation: &Operation) -> Result<()> {
    operation.validate()?;
    state::write_json(&paths.operation(), operation)
}

/// Remove only files whose names are bound to the persisted operation.  The
/// native bootstrap calls this after its own revocation journal is terminal;
/// until then these recovery resources remain intact.
pub fn remove_operation_resources_after_uninstall(paths: &Paths) -> Result<()> {
    let Some(operation) = read_optional::<Operation>(&paths.operation())? else {
        return Ok(());
    };
    operation.validate()?;
    remove_operation_resources(paths, &operation)
}

/// A terminal operation is about to be replaced by a new lifecycle journal.
/// Its only remaining owned files are operation-specific recovery resources;
/// clean those first while the old journal still provides the exact, validated
/// names.  No journal mutation is needed, so a crash leaves this retry-safe.
fn release_terminal_operation_resources_before_supersede(paths: &Paths) -> Result<()> {
    let Some(operation) = read_optional::<Operation>(&paths.operation())? else {
        return Ok(());
    };
    operation.validate()?;
    if terminal(&operation.phase) {
        remove_operation_resources(paths, &operation)?;
    }
    Ok(())
}

fn remove_operation_resources(paths: &Paths, operation: &Operation) -> Result<()> {
    let Some(resources) = operation.resources.as_ref() else {
        return Ok(());
    };
    for (path, prefix) in [
        (&resources.staged_launch_agent, "lifecycle-staged-"),
        (&resources.launch_agent_backup, "lifecycle-agent-"),
    ] {
        if path.parent() != Some(paths.state_dir.as_path())
            || path
                .file_name()
                .and_then(|name| name.to_str())
                .is_none_or(|name| name != format!("{prefix}{}.plist", operation.id))
        {
            bail!("unsafe lifecycle recovery resource")
        }
        remove_regular_and_sync(path)?;
    }
    Ok(())
}

pub async fn resume(paths: &Paths) -> Result<Value> {
    let _lock = LifecycleLock::acquire(paths)?;
    if let Some(mut operation) = read_optional::<Operation>(&paths.operation())? {
        operation.validate()?;
        if terminal(&operation.phase) {
            let snapshot = status(paths)?;
            if snapshot["legacyJournal"]["install"] == true
                || snapshot["legacyJournal"]["uninstall"] == true
            {
                return Ok(json!({
                    "resumed":false,
                    "reason":"legacy journal is protected for native repair",
                    "operation":operation,
                    "legacyJournal":snapshot["legacyJournal"],
                }));
            }
            return Ok(
                json!({"resumed":false,"reason":"operation is terminal","operation":operation}),
            );
        }
        if operation.package.is_some() && operation.resources.is_some() {
            match reconcile_activation(paths, &mut operation).await {
                Ok(value) => return Ok(value),
                Err(error) => {
                    set_checkpoint(
                        paths,
                        &mut operation,
                        "recovery_required",
                        "observed state could not be reconciled safely",
                    )?;
                    return Ok(json!({
                        "resumed":false,
                        "operation":operation,
                        "reason":"observed runner state remains protected",
                        "error":error.to_string(),
                    }));
                }
            }
        }
        operation.phase = "protected_repair_required".into();
        operation.updated_at = state::now();
        operation.detail =
            Some("operation has no native resource inventory; repair remains protected".into());
        save_operation(paths, &operation)?;
        return Ok(
            json!({"resumed":false,"reason":"protected repair required","operation":operation}),
        );
    }
    let snapshot = status(paths)?;
    if snapshot["legacyJournal"]["install"] == true
        || snapshot["legacyJournal"]["uninstall"] == true
    {
        let mut operation = Operation::new(
            OperationKind::Repair,
            "protected_legacy_repair",
            Some("legacy installer journal migrated into protected native repair state".into()),
        );
        operation.checkpoint = Some("legacy_journal_retained".into());
        save_operation(paths, &operation)?;
        return Ok(
            json!({"resumed":false,"reason":"legacy journal is protected for native repair","operation":operation}),
        );
    }
    Ok(json!({"resumed":false,"reason":"no pending lifecycle operation"}))
}

pub async fn rollback(paths: &Paths, version: &str) -> Result<Value> {
    let target = owned_versions(paths)?
        .into_iter()
        .find(|path| path.file_name().is_some_and(|v| v == version))
        .context("requested version is not owned")?;
    validate_rollback_target(&target, version)?;
    current_target(paths)?.context("rollback requires an installed current target")?;
    let agent = launch_agent(paths);
    checked_regular(&agent)?;
    let transaction = activate_as(
        paths,
        OperationKind::Rollback,
        target.clone(),
        version.into(),
        installed_tree_digest(&target)?,
        agent,
    )
    .await?;
    if transaction["pending"] == true {
        return Ok(json!({
            "schema":"app.loomex.runner.lifecycle-rollback/v1",
            "rolledBack":false,
            "pending":true,
            "target":target,
            "transaction":transaction,
        }));
    }
    Ok(json!({
        "schema":"app.loomex.runner.lifecycle-rollback/v1",
        "rolledBack":true,
        "target":target,
        "transaction":transaction,
    }))
}

pub async fn repair(paths: &Paths) -> Result<Value> {
    let reconciliation = resume(paths).await?;
    // A completed operation and the absence of an operation are both stable
    // states. They may still leave bootstrap-owned metadata behind after a
    // crash between native activation and receipt replacement.
    let stable = matches!(
        reconciliation["reason"].as_str(),
        Some("no pending lifecycle operation") | Some("operation is terminal")
    );
    if reconciliation["resumed"] != true && !stable {
        return Ok(json!({
            "repaired":false,
            "reconciliation":reconciliation,
            "actionRequired":true,
        }));
    }
    let _lock = LifecycleLock::acquire(paths)?;
    // Resume releases its lock. Recheck under this lock before touching receipt
    // metadata in case another lifecycle operation began in between.
    if let Some(operation) = read_optional::<Operation>(&paths.operation())? {
        operation.validate()?;
        if !terminal(&operation.phase) {
            return Ok(
                json!({"repaired":false,"actionRequired":true,"reason":"lifecycle operation changed; resume it first"}),
            );
        }
    }
    let temporary = paths.state_dir.join(format!("{OPERATION_NAME}.new"));
    let removed_temporary = if temporary.exists() {
        if fs::symlink_metadata(&temporary)?.file_type().is_symlink() {
            bail!("unsafe lifecycle temporary")
        }
        fs::remove_file(&temporary)?;
        true
    } else {
        false
    };
    let observed = observe_receipt_identity(paths).await?;
    let receipt = reconcile_install_receipt(paths, &observed)?;
    Ok(
        json!({"repaired":true,"removedTemporary":removed_temporary,"receipt":receipt,"reconciliation":reconciliation}),
    )
}

/// Reconcile only bootstrap-owned receipt identity after the native lifecycle
/// transaction is stable. It never selects a target, installs a service, or
/// invents provider configuration.
#[derive(Debug)]
struct ReceiptObservation {
    target: PathBuf,
    version: String,
    plist_digest: String,
}

async fn observe_receipt_identity(paths: &Paths) -> Result<ReceiptObservation> {
    let target = current_target(paths)?.context("LIFECYCLE_IDENTITY_CONFLICT")?;
    verify_owned_version(paths, &target)?;
    let plist = launch_agent(paths);
    checked_regular(&plist)?;
    let output = tokio::process::Command::new("/usr/bin/plutil")
        .args(["-convert", "json", "-o", "-"])
        .arg(&plist)
        .output()
        .await?;
    if !output.status.success() {
        bail!("LIFECYCLE_IDENTITY_CONFLICT")
    }
    let value: Value = serde_json::from_slice(&output.stdout)?;
    let program = value["ProgramArguments"][0]
        .as_str()
        .context("LIFECYCLE_IDENTITY_CONFLICT")?;
    if value["Label"] != "app.loomex.runner"
        || fs::canonicalize(program)? != fs::canonicalize(target.join("bin/loomex-runner"))?
        || value["EnvironmentVariables"]["LOOMEX_STATE_DIR"] != json!(paths.state_dir)
    {
        bail!("LIFECYCLE_IDENTITY_CONFLICT")
    }
    let status = daemon_status(paths).await?;
    let version = target
        .file_name()
        .and_then(|v| v.to_str())
        .context("LIFECYCLE_IDENTITY_CONFLICT")?
        .to_owned();
    if status["version"] != version {
        bail!("LIFECYCLE_IDENTITY_CONFLICT")
    }
    Ok(ReceiptObservation {
        target,
        version,
        plist_digest: state::digest(&fs::read(plist)?),
    })
}

fn reconcile_install_receipt(paths: &Paths, observed: &ReceiptObservation) -> Result<Value> {
    let receipt_path = paths.state_dir.join("install-receipt.json");
    let Some(receipt) = read_optional::<Value>(&receipt_path)? else {
        return Ok(json!({"reconciled":false,"reason":"receipt is absent"}));
    };
    let target = match current_target(paths)? {
        Some(target) => target,
        None => return Ok(json!({"reconciled":false,"reason":"current target is absent"})),
    };
    verify_owned_version(paths, &target)?;
    let version = target
        .file_name()
        .and_then(|name| name.to_str())
        .context("current runner version is invalid")?;
    let project: Value = state::read_json(&target.join("metadata/project.json"))?;
    if target != observed.target
        || version != observed.version
        || project["version"] != version
        || project["project"] != "loomex-runner"
        || state::digest(&fs::read(launch_agent(paths))?) != observed.plist_digest
    {
        bail!("LIFECYCLE_IDENTITY_CONFLICT")
    }

    let development_only = receipt["developmentOnly"]
        .as_bool()
        .context("install receipt has invalid development mode")?;
    let development_origin = &receipt["developmentApiOrigin"];
    if !(development_origin.is_null() || development_origin.is_string()) {
        bail!("install receipt has invalid development origin")
    }
    let providers = receipt["providerExecutables"]
        .as_object()
        .context("install receipt has invalid provider executables")?;
    for (provider, executable) in providers {
        if !matches!(
            provider.as_str(),
            "codex" | "claude" | "gemini" | "antigravity"
        ) || !executable
            .as_str()
            .is_some_and(|value| Path::new(value).is_absolute())
        {
            bail!("install receipt has invalid provider executables")
        }
    }
    let bootstrap = target.join("bin/loomex-lifecycle-bootstrap");
    checked_regular(&bootstrap)?;
    let expected = json!({
        "schema":"app.loomex.runner.install-receipt/v2",
        "version":version,
        "versionPath":target,
        "launchAgent":launch_agent(paths),
        "bootstrapSha256":state::digest(&fs::read(bootstrap)?),
        "developmentOnly":development_only,
        "developmentApiOrigin":development_origin,
        "providerExecutables":providers,
    });
    if receipt == expected {
        let intent_path = paths.state_dir.join("receipt-repair.json");
        if let Some(mut intent) = read_optional::<Value>(&intent_path)? {
            if intent["phase"] == "pending"
                && intent["expectedDigest"] == state::json_digest(&expected)
            {
                intent["phase"] = json!("completed");
                state::write_json(&intent_path, &intent)?;
            }
        }
        return Ok(json!({"reconciled":false,"reason":"receipt is current"}));
    }
    // Atomic intent and replacement make interruption resumable without inventing
    // a new installation. Re-observe all identities on every repair invocation.
    let intent = paths.state_dir.join("receipt-repair.json");
    state::write_json(
        &intent,
        &json!({"schema":"loomex.receipt-repair/v1","target":target,"version":version,"expectedDigest":state::json_digest(&expected),"phase":"pending"}),
    )?;
    if current_target(paths)?.as_ref() != Some(&target) {
        bail!("LIFECYCLE_IDENTITY_CONFLICT")
    }
    state::write_json(&receipt_path, &expected)?;
    state::write_json(
        &intent,
        &json!({"schema":"loomex.receipt-repair/v1","target":target,"version":version,"expectedDigest":state::json_digest(&expected),"phase":"completed"}),
    )?;
    Ok(json!({"reconciled":true,"version":version}))
}

pub fn readable(value: &Value) -> String {
    let current = value["current"].as_str().unwrap_or("none");
    let action = value["actionRequired"].as_bool().unwrap_or(false);
    let pending_active_work = value["operation"]["phase"] == "pending_active_work";
    format!(
        "Loomex lifecycle\ncurrent: {current}\naction required: {action}\npending active work: {pending_active_work}"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    fn paths(root: &Path) -> Paths {
        let root = fs::canonicalize(root).unwrap();
        let base = root.join("install");
        let state = root.join("state");
        let agents = root.join("agents");
        fs::create_dir_all(base.join("versions/1.2.3")).unwrap();
        fs::create_dir_all(&state).unwrap();
        fs::create_dir_all(&agents).unwrap();
        Paths {
            install_base: base,
            state_dir: state,
            launch_agents_dir: agents,
        }
    }

    fn make_compatible_target(paths: &Paths) {
        make_compatible_version(paths, "1.2.3");
    }

    fn make_compatible_version(paths: &Paths, version: &str) {
        let target = paths.versions().join(version);
        fs::create_dir_all(target.join("metadata")).unwrap();
        fs::create_dir_all(target.join("bin")).unwrap();
        state::write_json(
            &target.join("metadata/project.json"),
            &json!({
                "project":"loomex-runner", "version":version, "platform":"darwin-arm64"
            }),
        )
        .unwrap();
        fs::write(
            target.join("metadata/compatibility-manifest.json"),
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/contracts/compatibility-manifest.json"
            )),
        )
        .unwrap();
        fs::write(target.join("bin/loomex"), b"fixture").unwrap();
        fs::set_permissions(target.join("bin/loomex"), fs::Permissions::from_mode(0o700)).unwrap();
        let files = vec![
            json!({"path":"bin/loomex","sha256":state::digest(b"fixture"),"size":7,"mode":0o700}),
            json!({"path":"metadata/compatibility-manifest.json","sha256":state::digest(include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/contracts/compatibility-manifest.json"))),"size":include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/contracts/compatibility-manifest.json")).len(),"mode":0o644}),
            json!({"path":"metadata/project.json","sha256":state::digest(&fs::read(target.join("metadata/project.json")).unwrap()),"size":fs::metadata(target.join("metadata/project.json")).unwrap().len(),"mode":0o600}),
        ];
        let owned_path = paths.state_dir.join("owned-versions.json");
        let mut owned: Value = if owned_path.exists() {
            state::read_json(&owned_path).unwrap()
        } else {
            json!({"schema":"app.loomex.runner.owned-versions/v1","paths":[],"inventories":[]})
        };
        let paths_value = owned["paths"].as_array_mut().unwrap();
        if !paths_value.iter().any(|path| path == &json!(target)) {
            paths_value.push(json!(target));
        }
        let inventories = owned["inventories"].as_array_mut().unwrap();
        inventories.retain(|entry| entry["path"] != json!(target));
        inventories.push(json!({"path":target,"files":files}));
        state::write_json(&owned_path, &owned).unwrap();
    }

    fn add_owned_bootstrap(paths: &Paths, version: &str) {
        let target = paths.versions().join(version);
        let bootstrap = target.join("bin/loomex-lifecycle-bootstrap");
        fs::write(&bootstrap, b"bootstrap").unwrap();
        fs::set_permissions(&bootstrap, fs::Permissions::from_mode(0o700)).unwrap();
        let owned_path = paths.state_dir.join("owned-versions.json");
        let mut owned: Value = state::read_json(&owned_path).unwrap();
        let files = owned["inventories"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|entry| entry["path"] == json!(target))
            .unwrap()["files"]
            .as_array_mut()
            .unwrap();
        files.push(json!({"path":"bin/loomex-lifecycle-bootstrap","sha256":state::digest(b"bootstrap"),"size":9,"mode":0o700}));
        files.sort_by(|left, right| left["path"].as_str().cmp(&right["path"].as_str()));
        state::write_json(&owned_path, &owned).unwrap();
    }

    #[test]
    fn lifecycle_lock_serializes_writers_and_is_distinct_from_daemon_lock() {
        let temp = tempfile::tempdir().unwrap();
        let paths = paths(temp.path());
        let first = LifecycleLock::acquire(&paths).unwrap();
        assert!(LifecycleLock::acquire(&paths).is_err());
        assert_ne!(
            paths.state_dir.join(LOCK_NAME),
            paths.state_dir.join("daemon.lock")
        );
        drop(first);
        LifecycleLock::acquire(&paths).unwrap();
    }

    #[test]
    fn caller_supplied_lifecycle_paths_cannot_target_root_or_home() {
        let temp = tempfile::tempdir().unwrap();
        let mut paths = paths(temp.path());
        paths.state_dir = PathBuf::from("/");
        assert!(paths.validate().is_err());
    }

    #[tokio::test]
    async fn repair_reconciles_a_stale_receipt_to_the_verified_current_target() {
        let temp = tempfile::tempdir().unwrap();
        let paths = paths(temp.path());
        make_compatible_target(&paths);
        add_owned_bootstrap(&paths, "1.2.3");
        symlink(paths.versions().join("1.2.3"), paths.current()).unwrap();
        state::write_json(
            &paths.state_dir.join("install-receipt.json"),
            &json!({
                "schema":"app.loomex.runner.install-receipt/v2",
                "version":"1.2.2",
                "versionPath":paths.versions().join("1.2.2"),
                "launchAgent":launch_agent(&paths),
                "bootstrapSha256":"0".repeat(64),
                "developmentOnly":false,
                "developmentApiOrigin":null,
                "providerExecutables":{},
            }),
        )
        .unwrap();

        fs::write(launch_agent(&paths), b"fixture plist").unwrap();
        let observed = ReceiptObservation {
            target: paths.versions().join("1.2.3"),
            version: "1.2.3".into(),
            plist_digest: state::digest(b"fixture plist"),
        };
        let repaired = reconcile_install_receipt(&paths, &observed).unwrap();
        assert_eq!(repaired["reconciled"], true);
        let intent_path = paths.state_dir.join("receipt-repair.json");
        let mut intent: Value = state::read_json(&intent_path).unwrap();
        intent["phase"] = json!("pending");
        state::write_json(&intent_path, &intent).unwrap();
        reconcile_install_receipt(&paths, &observed).unwrap();
        assert_eq!(
            state::read_json::<Value>(&intent_path).unwrap()["phase"],
            "completed"
        );
        assert_eq!(
            reconcile_install_receipt(&paths, &observed).unwrap()["reconciled"],
            false
        );
        fs::write(launch_agent(&paths), b"changed").unwrap();
        assert!(reconcile_install_receipt(&paths, &observed).is_err());
        let receipt: Value =
            state::read_json(&paths.state_dir.join("install-receipt.json")).unwrap();
        assert_eq!(receipt["version"], "1.2.3");
        assert_eq!(
            receipt["versionPath"],
            json!(paths.versions().join("1.2.3"))
        );
        assert_eq!(receipt["bootstrapSha256"], state::digest(b"bootstrap"));
    }

    #[test]
    fn lifecycle_roots_reject_symlink_components_and_shared_mutation_parents() {
        let temp = tempfile::tempdir().unwrap();
        let canonical = fs::canonicalize(temp.path()).unwrap();
        let safe = paths(&canonical);
        let outside = canonical.join("outside");
        fs::create_dir(&outside).unwrap();
        let linked = canonical.join("linked");
        symlink(&outside, &linked).unwrap();
        let symlinked = Paths {
            install_base: linked.join("install"),
            state_dir: safe.state_dir.clone(),
            launch_agents_dir: safe.launch_agents_dir.clone(),
        };
        assert!(symlinked.validate().is_err());

        let shared = canonical.join("shared");
        fs::create_dir(&shared).unwrap();
        fs::set_permissions(&shared, fs::Permissions::from_mode(0o777)).unwrap();
        let unsafe_parent = Paths {
            install_base: shared.join("install"),
            state_dir: safe.state_dir,
            launch_agents_dir: safe.launch_agents_dir,
        };
        assert!(unsafe_parent.validate().is_err());
    }

    #[tokio::test]
    async fn preflight_rejects_a_different_package_before_staging() {
        let temp = tempfile::tempdir().unwrap();
        let paths = paths(temp.path());
        let target = paths.versions().join("1.2.3");
        let mut operation = Operation::new(OperationKind::Update, "prepared", None);
        operation.package = Some(PackageIdentity {
            version: "1.2.3".into(),
            target: target.clone(),
            manifest_sha256: "a".repeat(64),
        });
        save_operation(&paths, &operation).unwrap();
        let error = preflight_package(
            &paths,
            OperationKind::Update,
            PackageIdentity {
                version: "1.2.3".into(),
                target,
                manifest_sha256: "b".repeat(64),
            },
        )
        .await
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("LIFECYCLE_OPERATION_IDENTITY_MISMATCH")
        );
        let saved: Operation = state::read_json(&paths.operation()).unwrap();
        assert_eq!(saved.package.unwrap().manifest_sha256, "a".repeat(64));
    }

    #[tokio::test]
    async fn completed_matching_install_reconciles_without_reactivating() {
        let _serial = TEST_SERIAL.lock().await;
        let temp = tempfile::tempdir().unwrap();
        let paths = paths(temp.path());
        make_compatible_target(&paths);
        let target = paths.versions().join("1.2.3");
        std::os::unix::fs::symlink(&target, paths.current()).unwrap();
        fs::write(launch_agent(&paths), b"candidate-plist").unwrap();
        let package = PackageIdentity {
            version: "1.2.3".into(),
            target: target.clone(),
            manifest_sha256: "a".repeat(64),
        };
        let mut operation = Operation::new(OperationKind::Update, "completed", None);
        operation.package = Some(package.clone());
        operation.resources = Some(OperationResources {
            launch_agent: launch_agent(&paths),
            staged_launch_agent: paths.state_dir.join("staged.plist"),
            staged_launch_agent_sha256: state::digest(b"candidate-plist"),
            launch_agent_backup: paths.state_dir.join("backup.plist"),
            launch_agent_backup_sha256: None,
            owned_versions: vec![target],
        });
        save_operation(&paths, &operation).unwrap();
        TEST_MODE.store(true, Ordering::SeqCst);
        let result = preflight_package(&paths, OperationKind::Update, package).await;
        TEST_MODE.store(false, Ordering::SeqCst);
        assert_eq!(result.unwrap()["reconciled"], true);
        assert_eq!(
            state::read_json::<Operation>(&paths.operation())
                .unwrap()
                .phase,
            "completed"
        );
    }

    #[tokio::test]
    async fn interrupted_candidate_drain_recovery_resumes_exact_operation() {
        let _serial = TEST_SERIAL.lock().await;
        for stage in [
            "before_drain_removal",
            "after_drain_removal",
            "restart_failed",
            "after_restart",
            "before_completion",
        ] {
            let temp = tempfile::tempdir().unwrap();
            let paths = paths(temp.path());
            make_compatible_target(&paths);
            let target = paths.versions().join("1.2.3");
            std::os::unix::fs::symlink(&target, paths.current()).unwrap();
            fs::write(launch_agent(&paths), b"candidate-plist").unwrap();
            let mut operation = Operation::new(OperationKind::Update, "recovery_required", None);
            operation.package = Some(PackageIdentity {
                version: "1.2.3".into(),
                target: target.clone(),
                manifest_sha256: "a".repeat(64),
            });
            operation.resources = Some(OperationResources {
                launch_agent: launch_agent(&paths),
                staged_launch_agent: paths.state_dir.join("staged.plist"),
                staged_launch_agent_sha256: state::digest(b"candidate-plist"),
                launch_agent_backup: paths.state_dir.join("backup.plist"),
                launch_agent_backup_sha256: None,
                owned_versions: vec![target],
            });
            state::write_json(
                &paths.state_dir.join("drain.json"),
                &json!({"draining":true}),
            )
            .unwrap();
            save_operation(&paths, &operation).unwrap();
            TEST_MODE.store(true, Ordering::SeqCst);
            TEST_RESTART_COUNT.store(0, Ordering::SeqCst);
            *TEST_RECOVERY_STATUS.lock().unwrap() =
                Some(json!({"version":"1.2.3","activeJobs":0,"draining":true}));
            *TEST_RECOVERY_FAULT.lock().unwrap() = Some(stage);
            let failed = reconcile_activation(&paths, &mut operation).await;
            *TEST_RECOVERY_FAULT.lock().unwrap() = None;
            let mut restored: Operation = state::read_json(&paths.operation()).unwrap();
            let resumed = reconcile_activation(&paths, &mut restored).await;
            let restarts = TEST_RESTART_COUNT.load(Ordering::SeqCst);
            *TEST_RECOVERY_STATUS.lock().unwrap() = None;
            TEST_MODE.store(false, Ordering::SeqCst);
            assert!(failed.is_err(), "{stage}");
            assert!(resumed.is_ok(), "{stage}: {resumed:?}");
            assert_eq!(restored.id, operation.id);
            assert_eq!(restored.phase, "completed");
            assert_eq!(
                restarts, 1,
                "a recovered healthy candidate must not restart twice"
            );
        }
    }

    #[test]
    fn only_idle_exact_candidate_may_release_a_stale_drain() {
        assert!(candidate_drain_can_be_released(
            &json!({"version":"1.2.3","activeJobs":0,"draining":true}),
            "1.2.3"
        ));
        for status in [
            json!({"version":"1.2.4","activeJobs":0,"draining":true}),
            json!({"version":"1.2.3","activeJobs":1,"draining":true}),
            json!({"version":"1.2.3","activeJobs":0,"draining":false}),
            json!({"version":"1.2.3","draining":true}),
        ] {
            assert!(!candidate_drain_can_be_released(&status, "1.2.3"));
        }
    }

    #[tokio::test]
    async fn legacy_journal_becomes_protected_native_repair_state() {
        let temp = tempfile::tempdir().unwrap();
        let paths = paths(temp.path());
        state::write_json(
            &paths.state_dir.join("install-operation.json"),
            &json!({"schema":"app.loomex.runner.install-operation/v1","phase":"owned"}),
        )
        .unwrap();
        let result = resume(&paths).await.unwrap();
        assert_eq!(
            result["reason"],
            "legacy journal is protected for native repair"
        );
        let operation: Operation = state::read_json(&paths.operation()).unwrap();
        assert_eq!(operation.phase, "protected_legacy_repair");
    }

    #[tokio::test]
    async fn terminal_operation_does_not_hide_a_legacy_repair_journal() {
        let temp = tempfile::tempdir().unwrap();
        let paths = paths(temp.path());
        let operation = Operation::new(OperationKind::Update, "completed", None);
        save_operation(&paths, &operation).unwrap();
        state::write_json(
            &paths.state_dir.join("uninstall-operation.json"),
            &json!({"schema":"app.loomex.runner.uninstall-operation/v1","phase":"owned"}),
        )
        .unwrap();

        let result = resume(&paths).await.unwrap();
        assert_eq!(
            result["reason"],
            "legacy journal is protected for native repair"
        );
        assert_eq!(result["operation"]["phase"], "completed");
        assert_eq!(result["legacyJournal"]["uninstall"], true);
    }

    #[tokio::test]
    async fn pending_active_work_resumes_the_original_switch() {
        let _serial = TEST_SERIAL.lock().await;
        let temp = tempfile::tempdir().unwrap();
        let paths = paths(temp.path());
        make_compatible_target(&paths);
        let staged = paths.state_dir.join("lifecycle-staged-pending.plist");
        fs::write(&staged, b"candidate").unwrap();
        let mut operation = Operation::new(OperationKind::Update, "pending_active_work", None);
        operation.package = Some(PackageIdentity {
            version: "1.2.3".into(),
            target: paths.versions().join("1.2.3"),
            manifest_sha256: "d".repeat(64),
        });
        operation.resources = Some(OperationResources {
            launch_agent: launch_agent(&paths),
            staged_launch_agent: staged.clone(),
            staged_launch_agent_sha256: state::digest(b"candidate"),
            launch_agent_backup: paths.state_dir.join("lifecycle-agent-pending.plist"),
            launch_agent_backup_sha256: None,
            owned_versions: vec![paths.versions().join("1.2.3")],
        });
        save_operation(&paths, &operation).unwrap();
        TEST_MODE.store(true, Ordering::SeqCst);
        let result = resume(&paths).await.unwrap();
        TEST_MODE.store(false, Ordering::SeqCst);
        assert_eq!(result["state"], "candidate_healthy_after_pending");
        let saved: Operation = state::read_json(&paths.operation()).unwrap();
        assert_eq!(saved.phase, "completed");
    }

    #[tokio::test]
    async fn rollback_pending_active_work_preserves_target_and_resumes() {
        let _serial = TEST_SERIAL.lock().await;
        let temp = tempfile::tempdir().unwrap();
        let paths = paths(temp.path());
        make_compatible_target(&paths);
        make_compatible_version(&paths, "1.2.4");
        let target = paths.versions().join("1.2.3");
        std::os::unix::fs::symlink(paths.versions().join("1.2.4"), paths.current()).unwrap();
        fs::write(launch_agent(&paths), b"old-plist").unwrap();

        TEST_MODE.store(true, Ordering::SeqCst);
        TEST_DRAIN_HAS_ACTIVE_WORK.store(true, Ordering::SeqCst);
        let pending = rollback(&paths, "1.2.3").await.unwrap();
        TEST_DRAIN_HAS_ACTIVE_WORK.store(false, Ordering::SeqCst);

        assert_eq!(pending["schema"], "app.loomex.runner.lifecycle-rollback/v1");
        assert_eq!(pending["rolledBack"], false);
        assert_eq!(pending["pending"], true);
        assert_eq!(pending["target"], json!(target));
        let operation: Operation = state::read_json(&paths.operation()).unwrap();
        assert_eq!(operation.kind, OperationKind::Rollback);
        assert_eq!(operation.phase, "pending_active_work");
        assert_eq!(operation.package.unwrap().target, target);
        assert!(readable(&status(&paths).unwrap()).contains("pending active work: true"));

        let resumed = resume(&paths).await.unwrap();
        TEST_MODE.store(false, Ordering::SeqCst);
        assert_eq!(resumed["resumed"], true);
        assert_eq!(
            fs::read_link(paths.current()).unwrap(),
            paths.versions().join("1.2.3")
        );
        let operation: Operation = state::read_json(&paths.operation()).unwrap();
        assert_eq!(operation.kind, OperationKind::Rollback);
        assert_eq!(operation.phase, "completed");
    }

    #[test]
    fn rollback_requires_an_owned_direct_semver_child() {
        let temp = tempfile::tempdir().unwrap();
        let paths = paths(temp.path());
        state::write_json(
            &paths.state_dir.join("owned-versions.json"),
            &json!({
                "schema":"app.loomex.runner.owned-versions/v1",
                "paths":[paths.versions().join("1.2.3")]
            }),
        )
        .unwrap();
        // The native path refuses to touch a pointer until the running daemon
        // has supplied an idle, drained status.  This also keeps a missing
        // daemon from turning a rollback into an unsafe best-effort action.
        assert!(
            tokio::runtime::Runtime::new()
                .unwrap()
                .block_on(rollback(&paths, "1.2.3"))
                .is_err()
        );
        assert!(!paths.current().exists());
        assert!(
            validate_rollback_status(&json!({"result":{"activeJobs":0,"draining":true}})).is_ok()
        );
        assert!(
            validate_rollback_status(&json!({"result":{"activeJobs":1,"draining":true}})).is_err()
        );
        assert!(
            validate_rollback_status(&json!({"result":{"activeJobs":0,"draining":false}})).is_err()
        );
    }

    #[tokio::test]
    async fn injected_service_failure_leaves_pointer_unchanged_and_intent_durable() {
        let _serial = TEST_SERIAL.lock().await;
        let temp = tempfile::tempdir().unwrap();
        assert_eq!(NATIVE_EXECUTABLES, ["launchctl"]);
        let paths = paths(temp.path());
        make_compatible_target(&paths);
        let staged = temp.path().join("staged.plist");
        fs::write(&staged, b"plist").unwrap();
        TEST_MODE.store(true, Ordering::SeqCst);
        TEST_BOOTOUT_FAIL.store(true, Ordering::SeqCst);
        let result = activate(
            &paths,
            paths.versions().join("1.2.3"),
            "1.2.3".into(),
            "a".repeat(64),
            staged,
        )
        .await;
        TEST_BOOTOUT_FAIL.store(false, Ordering::SeqCst);
        TEST_MODE.store(false, Ordering::SeqCst);
        assert!(result.is_err());
        assert!(!paths.current().exists());
        let operation: Operation = state::read_json(&paths.operation()).unwrap();
        assert_eq!(operation.phase, "recovery_required");
        assert_eq!(operation.package.unwrap().manifest_sha256, "a".repeat(64));
    }

    #[tokio::test]
    async fn unconfirmed_candidate_health_never_reports_a_completed_rollback() {
        let _serial = TEST_SERIAL.lock().await;
        let temp = tempfile::tempdir().unwrap();
        let paths = paths(temp.path());
        make_compatible_target(&paths);
        make_compatible_version(&paths, "1.2.4");
        std::os::unix::fs::symlink(paths.versions().join("1.2.4"), paths.current()).unwrap();
        fs::write(launch_agent(&paths), b"old-plist").unwrap();

        TEST_MODE.store(true, Ordering::SeqCst);
        TEST_CANDIDATE_HEALTH_FAIL.store(true, Ordering::SeqCst);
        let result = rollback(&paths, "1.2.3").await;
        TEST_CANDIDATE_HEALTH_FAIL.store(false, Ordering::SeqCst);
        TEST_MODE.store(false, Ordering::SeqCst);

        assert!(result.is_err());
        let operation: Operation = state::read_json(&paths.operation()).unwrap();
        assert_eq!(operation.kind, OperationKind::Rollback);
        assert_eq!(operation.phase, "recovery_required");
        assert_eq!(
            fs::read_link(paths.current()).unwrap(),
            paths.versions().join("1.2.4")
        );
    }

    #[tokio::test]
    async fn native_activation_uses_no_python_npm_or_source_checkout_on_path() {
        let _serial = TEST_SERIAL.lock().await;
        let temp = tempfile::tempdir().unwrap();
        let paths = paths(temp.path());
        make_compatible_target(&paths);
        let staged = temp.path().join("staged.plist");
        fs::write(&staged, b"plist").unwrap();
        TEST_MODE.store(true, Ordering::SeqCst);
        let result = activate(
            &paths,
            paths.versions().join("1.2.3"),
            "1.2.3".into(),
            "b".repeat(64),
            staged,
        )
        .await;
        TEST_MODE.store(false, Ordering::SeqCst);
        assert!(result.is_ok());
        assert_eq!(
            fs::read_link(paths.current()).unwrap(),
            paths.versions().join("1.2.3")
        );
    }

    #[tokio::test]
    async fn activation_rejects_a_tampered_retained_binary() {
        let temp = tempfile::tempdir().unwrap();
        let paths = paths(temp.path());
        make_compatible_target(&paths);
        fs::write(paths.versions().join("1.2.3/bin/loomex"), b"tampered").unwrap();
        let staged = temp.path().join("staged.plist");
        fs::write(&staged, b"plist").unwrap();
        let error = activate(
            &paths,
            paths.versions().join("1.2.3"),
            "1.2.3".into(),
            "e".repeat(64),
            staged,
        )
        .await
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("owned version no longer matches the release inventory")
        );
    }

    #[tokio::test]
    async fn resume_reconciles_a_crash_after_pointer_write_from_observed_resources() {
        let _serial = TEST_SERIAL.lock().await;
        let temp = tempfile::tempdir().unwrap();
        let paths = paths(temp.path());
        make_compatible_target(&paths);
        make_compatible_version(&paths, "1.2.4");
        let candidate = paths.versions().join("1.2.3");
        let previous = paths.versions().join("1.2.4");
        state::write_json(
            &paths.state_dir.join("owned-versions.json"),
            &json!({
                "schema":"app.loomex.runner.owned-versions/v1",
                "paths":[candidate, previous]
            }),
        )
        .unwrap();
        std::os::unix::fs::symlink(&previous, paths.current()).unwrap();
        let agent = launch_agent(&paths);
        fs::write(&agent, b"old-plist").unwrap();
        let backup = paths.state_dir.join("agent-before.plist");
        state::atomic_write(&backup, b"old-plist").unwrap();
        let staged = temp.path().join("candidate.plist");
        fs::write(&staged, b"candidate-plist").unwrap();
        let mut operation = Operation::new(OperationKind::Update, "service_stopped", None);
        operation.package = Some(PackageIdentity {
            version: "1.2.3".into(),
            target: candidate.clone(),
            manifest_sha256: "c".repeat(64),
        });
        operation.previous_target = Some(previous.clone());
        operation.resources = Some(OperationResources {
            launch_agent: agent.clone(),
            staged_launch_agent: staged.clone(),
            staged_launch_agent_sha256: state::digest(b"candidate-plist"),
            launch_agent_backup: backup,
            launch_agent_backup_sha256: Some(state::digest(b"old-plist")),
            owned_versions: vec![candidate.clone(), previous.clone()],
        });
        save_operation(&paths, &operation).unwrap();
        // Model a process death after the durable pointer replacement but
        // before the checkpoint write.  The stale phase says service_stopped,
        // while the filesystem says candidate.
        write_pointer(&paths, &candidate, &operation).unwrap();
        replace_regular_atomically(&staged, &agent, &operation).unwrap();
        TEST_MODE.store(true, Ordering::SeqCst);
        let result = resume(&paths).await.unwrap();
        TEST_MODE.store(false, Ordering::SeqCst);
        assert_eq!(result["state"], "previous_restored");
        assert_eq!(fs::read_link(paths.current()).unwrap(), previous);
        assert_eq!(fs::read(&agent).unwrap(), b"old-plist");
        let saved: Operation = state::read_json(&paths.operation()).unwrap();
        assert_eq!(saved.phase, "rolled_back");
    }

    #[tokio::test]
    async fn rollback_reuses_the_native_service_transaction() {
        let _serial = TEST_SERIAL.lock().await;
        let temp = tempfile::tempdir().unwrap();
        let paths = paths(temp.path());
        make_compatible_target(&paths);
        make_compatible_version(&paths, "1.2.4");
        std::os::unix::fs::symlink(paths.versions().join("1.2.4"), paths.current()).unwrap();
        fs::write(launch_agent(&paths), b"plist").unwrap();
        TEST_MODE.store(true, Ordering::SeqCst);
        let result = rollback(&paths, "1.2.3").await;
        TEST_MODE.store(false, Ordering::SeqCst);
        assert!(result.unwrap()["rolledBack"] == true);
        assert_eq!(
            fs::read_link(paths.current()).unwrap(),
            paths.versions().join("1.2.3")
        );
        let operation: Operation = state::read_json(&paths.operation()).unwrap();
        assert_eq!(operation.kind, OperationKind::Rollback);
        assert_eq!(operation.phase, "completed");
        assert_eq!(
            operation.previous_target,
            Some(paths.versions().join("1.2.4"))
        );
    }

    #[tokio::test]
    async fn consecutive_activation_and_rollback_release_all_resources_on_uninstall() {
        let _serial = TEST_SERIAL.lock().await;
        let temp = tempfile::tempdir().unwrap();
        let paths = paths(temp.path());
        make_compatible_target(&paths);
        make_compatible_version(&paths, "1.2.4");
        let staged = temp.path().join("initial.plist");
        fs::write(&staged, b"initial-plist").unwrap();

        TEST_MODE.store(true, Ordering::SeqCst);
        activate(
            &paths,
            paths.versions().join("1.2.3"),
            "1.2.3".into(),
            "f".repeat(64),
            staged,
        )
        .await
        .unwrap();
        let first: Operation = state::read_json(&paths.operation()).unwrap();
        let first_resources = first.resources.clone().unwrap();
        assert!(first_resources.staged_launch_agent.exists());

        rollback(&paths, "1.2.4").await.unwrap();
        TEST_MODE.store(false, Ordering::SeqCst);

        // The succeeding rollback can supersede only after releasing the
        // exact files still owned by the completed activation journal.
        assert!(!first_resources.staged_launch_agent.exists());
        assert!(!first_resources.launch_agent_backup.exists());
        let latest: Operation = state::read_json(&paths.operation()).unwrap();
        let latest_resources = latest.resources.clone().unwrap();
        assert!(latest_resources.staged_launch_agent.exists());
        assert!(latest_resources.launch_agent_backup.exists());

        // This is the same helper called by native bootstrap uninstall while
        // it owns LifecycleLock; only the current journal's exact paths are
        // removed, while the earlier journal was already released above.
        remove_operation_resources_after_uninstall(&paths).unwrap();
        assert!(!latest_resources.staged_launch_agent.exists());
        assert!(!latest_resources.launch_agent_backup.exists());
    }

    #[test]
    fn symlinked_owned_version_is_rejected() {
        let temp = tempfile::tempdir().unwrap();
        let paths = paths(temp.path());
        let victim = temp.path().join("victim");
        fs::create_dir(&victim).unwrap();
        let bad = paths.versions().join("2.0.0");
        symlink(&victim, &bad).unwrap();
        state::write_json(
            &paths.state_dir.join("owned-versions.json"),
            &json!({
                "schema":"app.loomex.runner.owned-versions/v1", "paths":[bad]
            }),
        )
        .unwrap();
        assert!(
            tokio::runtime::Runtime::new()
                .unwrap()
                .block_on(rollback(&paths, "2.0.0"))
                .is_err()
        );
    }
}
