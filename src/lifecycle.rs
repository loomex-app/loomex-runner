//! Native runner administration state.
//!
//! Lifecycle writers have a distinct lock. After authoritative service/process
//! exit only, replacement briefly holds the existing daemon singleton lock;
//! it is released before bootstrap so the new daemon can acquire ownership.
use anyhow::{Context, Result, bail, ensure};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::io::Read;
use std::{
    fs::{self, File, OpenOptions},
    os::unix::{
        ffi::OsStrExt,
        fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Component, Path, PathBuf},
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
static TEST_STOP_WAIT_UNCONFIRMED: AtomicBool = AtomicBool::new(false);
#[cfg(test)]
static TEST_DRAIN_HAS_ACTIVE_WORK: AtomicBool = AtomicBool::new(false);
#[cfg(test)]
static TEST_CANDIDATE_HEALTH_FAIL: AtomicBool = AtomicBool::new(false);
#[cfg(test)]
static TEST_SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
#[cfg(test)]
static TEST_RECOVERY_STATUS: std::sync::Mutex<Option<Value>> = std::sync::Mutex::new(None);
#[cfg(test)]
static TEST_AUTH_STATUS: std::sync::Mutex<Option<Value>> = std::sync::Mutex::new(None);
#[cfg(test)]
static TEST_RECOVERY_FAULT: std::sync::Mutex<Option<&'static str>> = std::sync::Mutex::new(None);
#[cfg(test)]
static TEST_RESTART_COUNT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
#[cfg(test)]
static TEST_STATUS_UNAVAILABLE: AtomicBool = AtomicBool::new(false);
#[cfg(test)]
static TEST_ABANDONMENT_RESTART: AtomicBool = AtomicBool::new(false);
#[cfg(test)]
static TEST_LABEL_PRESENT: AtomicBool = AtomicBool::new(false);
#[cfg(test)]
static TEST_DELAYED_SERVICE_STOP: AtomicBool = AtomicBool::new(false);
#[cfg(test)]
static TEST_LABEL_OBSERVATION: std::sync::Mutex<Option<LabelObservation>> =
    std::sync::Mutex::new(None);
#[cfg(test)]
static TEST_PROCESS_OBSERVATION: std::sync::Mutex<Option<ProcessObservation>> =
    std::sync::Mutex::new(None);
#[cfg(test)]
static TEST_STOP_COUNT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
#[cfg(test)]
static TEST_STATUS_COUNT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
#[cfg(test)]
static TEST_PRUNE_IN_USE: std::sync::Mutex<Vec<PathBuf>> = std::sync::Mutex::new(Vec::new());
#[cfg(test)]
static TEST_PRUNE_FAULT: std::sync::Mutex<Option<&'static str>> = std::sync::Mutex::new(None);

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

// New records use schemas unknown to pre-auth-gate lifecycle owners. In
// particular, an older runner must reject rather than ignore authBaseline.
pub const OPERATION_SCHEMA: &str = "app.loomex.runner.lifecycle-operation/v4";
// Prune has different recovery semantics. Older lifecycle owners must reject
// an interrupted prune instead of interpreting it as an activation journal.
const PRUNE_OPERATION_SCHEMA: &str = "app.loomex.runner.lifecycle-operation/v6";
const ABANDONMENT_OPERATION_SCHEMA: &str = "app.loomex.runner.lifecycle-operation/v5";
const PRE_AUTH_OPERATION_SCHEMA: &str = "app.loomex.runner.lifecycle-operation/v2";
const PRE_AUTH_ABANDONMENT_SCHEMA: &str = "app.loomex.runner.lifecycle-operation/v3";
const LEGACY_OPERATION_SCHEMA: &str = "app.loomex.runner.lifecycle-operation/v1";
// Exact supported checkpoint meanings from the frozen v1 owner. Without a
// captured stop identity, newer/unknown meanings must not enter legacy repair.
const LEGACY_CHECKPOINTS: &[&str] = &[
    "resources_captured",
    "daemon_drained",
    "old_service_stopped",
    "pointer_and_plist_switched",
    "candidate_bootstrapped",
    "candidate_healthy",
    "daemon_has_active_work",
    "candidate_or_previous_service_not_safe_to_restore",
    "candidate_healthy_after_reconciliation",
    "previous_service_healthy_after_reconciliation",
    "previous_service_restored",
    "candidate_drain_release_pending",
    "previous_drain_release_pending",
    "daemon_drained_after_pending",
    "candidate_healthy_after_pending",
    "observed state could not be reconciled safely",
    "legacy_journal_retained",
];
const LOCK_NAME: &str = "lifecycle.lock";
const OPERATION_NAME: &str = "lifecycle-operation.json";
const NATIVE_EXECUTABLES: &[&str] = &["/bin/launchctl"];

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum OperationKind {
    Install,
    Update,
    Uninstall,
    Repair,
    Rollback,
    Prune,
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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub service_stops: Vec<ServiceStopIntent>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub abandonment: Option<PendingUpdateAbandonment>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_baseline: Option<AuthBaseline>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prune: Option<PruneIntent>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PruneIntent {
    pub targets: Vec<PathBuf>,
    pub retain: Vec<PathBuf>,
    pub moved: Vec<PathBuf>,
    pub deleting_started: Vec<PathBuf>,
    pub current_target: PathBuf,
    pub original_inventory_digest: String,
    pub result_inventory_digest: String,
    pub receipt_digest: String,
    pub drain_key: Uuid,
    pub launch_agent_digest: String,
    pub auth_baseline: AuthBaseline,
}

/// Only public auth.status fields. The Keychain remains the credential authority.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(
    tag = "state",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum AuthBaseline {
    Initial,
    SignedOut {
        installation_id: Option<Uuid>,
    },
    Authenticated {
        installation_id: Uuid,
        active_organization: Option<Uuid>,
    },
}

// Private abandonment schemas prevent older lifecycle owners from treating an
// abort as an executable Update. The UUID/package remain its transaction owner.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PendingUpdateAbandonment {
    operation_id: Uuid,
    package: PackageIdentity,
    previous_target: PathBuf,
    receipt_digest: String,
    inventory_digest: String,
    plist_digest: String,
    drain_digest: String,
    bootstrap_configuration_digest: String,
    process: ProcessIdentity,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    successor: Option<BootstrapSuccessor>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BootstrapSuccessor {
    package: PackageIdentity,
    configuration_digest: String,
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
            service_stops: Vec::new(),
            abandonment: None,
            auth_baseline: None,
            prune: None,
        }
    }

    fn validate(&self) -> Result<()> {
        if !matches!(
            self.schema.as_str(),
            OPERATION_SCHEMA
                | PRUNE_OPERATION_SCHEMA
                | LEGACY_OPERATION_SCHEMA
                | PRE_AUTH_OPERATION_SCHEMA
                | PRE_AUTH_ABANDONMENT_SCHEMA
                | ABANDONMENT_OPERATION_SCHEMA
        ) || self.phase.is_empty()
            || self.phase.len() > 128
        {
            bail!("invalid lifecycle operation")
        }
        ensure!(
            (self.schema == PRUNE_OPERATION_SCHEMA)
                == (self.kind == OperationKind::Prune && self.prune.is_some()),
            "invalid prune journal schema"
        );
        if let Some(prune) = &self.prune {
            ensure!(
                matches!(
                    self.phase.as_str(),
                    "prepared"
                        | "draining"
                        | "deleting"
                        | "metadata"
                        | "drain_release_pending"
                        | "completed"
                ) && self.package.is_none()
                    && self.previous_target.is_none()
                    && self.resources.is_none()
                    && self.checkpoint.is_none()
                    && self.service_stops.is_empty()
                    && self.abandonment.is_none()
                    && self.auth_baseline.is_none()
                    && !prune.targets.is_empty()
                    && !prune.retain.is_empty()
                    && prune.targets.len() <= 256
                    && prune.retain.len() <= 256
                    && valid_digest(&prune.original_inventory_digest)
                    && valid_digest(&prune.result_inventory_digest)
                    && valid_digest(&prune.receipt_digest)
                    && valid_digest(&prune.launch_agent_digest)
                    && prune.current_target.is_absolute()
                    && prune.targets.iter().all(|path| path.is_absolute())
                    && prune.retain.iter().all(|path| path.is_absolute())
                    && prune.moved.iter().all(|path| prune.targets.contains(path))
                    && prune
                        .deleting_started
                        .iter()
                        .all(|path| prune.moved.contains(path))
                    && prune
                        .deleting_started
                        .iter()
                        .collect::<std::collections::HashSet<_>>()
                        .len()
                        == prune.deleting_started.len()
                    && prune
                        .targets
                        .iter()
                        .collect::<std::collections::HashSet<_>>()
                        .len()
                        == prune.targets.len()
                    && prune
                        .retain
                        .iter()
                        .collect::<std::collections::HashSet<_>>()
                        .len()
                        == prune.retain.len(),
                "invalid prune journal binding"
            );
        }
        ensure!(
            matches!(
                self.schema.as_str(),
                ABANDONMENT_OPERATION_SCHEMA | PRE_AUTH_ABANDONMENT_SCHEMA
            ) == self.abandonment.is_some(),
            "invalid abandonment journal schema"
        );
        if let Some(intent) = &self.abandonment {
            ensure!(
                self.kind == OperationKind::Update
                    && intent.operation_id == self.id
                    && self.package.as_ref() == Some(&intent.package)
                    && self.previous_target.as_ref() == Some(&intent.previous_target)
                    && intent.previous_target.is_absolute()
                    && [
                        &intent.receipt_digest,
                        &intent.inventory_digest,
                        &intent.plist_digest,
                        &intent.drain_digest,
                        &intent.bootstrap_configuration_digest
                    ]
                    .iter()
                    .all(|digest| valid_digest(digest))
                    && intent.process.uid == unsafe { libc::geteuid() }
                    && intent.process.pid > 0
                    && intent.process.started_seconds > 0
                    && intent.process.started_micros < 1_000_000
                    && intent.process.executable
                        == intent.previous_target.join("bin/loomex-runner")
                    && matches!(
                        self.phase.as_str(),
                        "abandonment_pending"
                            | "service_stop_pending"
                            | "service_stopped"
                            | "pointer_switched"
                            | "candidate_started"
                            | "recovery_required"
                            | "rolled_back"
                    )
                    && (self.service_stops.is_empty() == (self.phase == "abandonment_pending"))
                    && self
                        .service_stops
                        .iter()
                        .all(|stop| stop.direction == StopDirection::RestorePrevious),
                "invalid abandonment transaction binding"
            );
            if let Some(successor) = &intent.successor {
                ensure!(
                    self.phase == "rolled_back"
                        && valid_digest(&successor.configuration_digest)
                        && successor.configuration_digest != intent.bootstrap_configuration_digest
                        && successor.package.target.is_absolute()
                        && valid_digest(&successor.package.manifest_sha256),
                    "invalid abandonment successor binding"
                );
            }
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
        if self.auth_baseline.is_some() {
            ensure!(
                matches!(
                    self.schema.as_str(),
                    OPERATION_SCHEMA | ABANDONMENT_OPERATION_SCHEMA
                ) && self.kind != OperationKind::Uninstall,
                "invalid lifecycle auth baseline"
            );
            ensure!(
                matches!(self.auth_baseline, Some(AuthBaseline::Initial))
                    == self.previous_target.is_none(),
                "lifecycle auth baseline differs from previous installation"
            );
        }
        if matches!(
            self.schema.as_str(),
            OPERATION_SCHEMA | ABANDONMENT_OPERATION_SCHEMA
        ) && matches!(
            self.kind,
            OperationKind::Install | OperationKind::Update | OperationKind::Rollback
        ) && self.resources.is_some()
        {
            ensure!(
                self.auth_baseline.is_some(),
                "lifecycle auth baseline is missing"
            );
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
        ensure!(
            self.schema != LEGACY_OPERATION_SCHEMA
                || (self.service_stops.is_empty() && self.phase != "service_stop_pending"),
            "legacy lifecycle operation cannot carry service-stop intent"
        );
        ensure!(
            self.service_stops.len() <= 2,
            "invalid service-stop history"
        );
        ensure!(
            self.phase != "service_stop_pending" || !self.service_stops.is_empty(),
            "pending service stop has no recorded identity"
        );
        ensure!(
            self.abandonment.is_some()
                || !self.service_stops.is_empty()
                || self
                    .checkpoint
                    .as_deref()
                    .is_none_or(|checkpoint| LEGACY_CHECKPOINTS.contains(&checkpoint)),
            "lifecycle checkpoint requires captured service-stop identity or supported legacy meaning"
        );
        for (index, stop) in self.service_stops.iter().enumerate() {
            ensure!(
                stop.operation_id == self.id
                    && self.package.as_ref() == Some(&stop.package)
                    && stop.uid == unsafe { libc::geteuid() }
                    && stop.label == format!("gui/{}/app.loomex.runner", stop.uid)
                    && stop
                        .target
                        .as_ref()
                        .is_none_or(|target| target.is_absolute())
                    && stop
                        .plist_digest
                        .as_ref()
                        .is_none_or(|digest| valid_digest(digest))
                    && stop
                        .receipt_digest
                        .as_ref()
                        .is_none_or(|digest| valid_digest(digest))
                    && valid_digest(&stop.inventory_digest)
                    && stop
                        .drain_digest
                        .as_ref()
                        .is_none_or(|digest| valid_digest(digest)),
                "invalid lifecycle service-stop binding"
            );
            if let Some(process) = &stop.process {
                ensure!(
                    process.pid > 0
                        && process.uid == stop.uid
                        && process.started_seconds > 0
                        && process.started_micros < 1_000_000
                        && stop.target.as_ref().is_some_and(
                            |target| process.executable == target.join("bin/loomex-runner")
                        ),
                    "invalid lifecycle stopped-process identity"
                );
            }
            ensure!(
                index + 1 == self.service_stops.len()
                    || stop.request == StopRequest::ObservedStopped,
                "unresolved stop intent cannot be superseded"
            );
        }
        Ok(())
    }
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|value| value.is_ascii_hexdigit())
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StopDirection {
    ActivateCandidate,
    RestorePrevious,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StopRequest {
    Prepared,
    Accepted,
    Unconfirmed,
    ObservedStopped,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ProcessIdentity {
    pid: i32,
    uid: u32,
    started_seconds: u64,
    started_micros: u64,
    executable: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ServiceStopIntent {
    operation_id: Uuid,
    direction: StopDirection,
    package: PackageIdentity,
    uid: u32,
    label: String,
    target: Option<PathBuf>,
    plist_digest: Option<String>,
    receipt_digest: Option<String>,
    inventory_digest: String,
    drain_digest: Option<String>,
    process: Option<ProcessIdentity>,
    request: StopRequest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum LabelObservation {
    Loaded { pid: i32, program: PathBuf },
    LoadedIdle { program: PathBuf },
    Absent,
    Unknown,
}
#[derive(Debug, Clone, PartialEq, Eq)]
enum ProcessObservation {
    Present(ProcessIdentity),
    Exited,
    Unknown,
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
    verify_directory_against_files(target, expected)
}

// Bound payload allocation independently of retained package size. Identity is
// checked against both the opened descriptor and the path after EOF; no digest
// is cached across lifecycle authorization/mutation boundaries.
const INTEGRITY_BUFFER_BYTES: usize = 64 * 1024;

fn same_file_identity(a: &fs::Metadata, b: &fs::Metadata) -> bool {
    a.dev() == b.dev()
        && a.ino() == b.ino()
        && a.len() == b.len()
        && a.mode() == b.mode()
        && a.mtime() == b.mtime()
        && a.mtime_nsec() == b.mtime_nsec()
        && a.ctime() == b.ctime()
        && a.ctime_nsec() == b.ctime_nsec()
}

fn streaming_file_digest(path: &Path) -> Result<(String, fs::Metadata)> {
    streaming_file_digest_checked(path, || {})
}

fn streaming_file_digest_checked(
    path: &Path,
    after_read: impl FnOnce(),
) -> Result<(String, fs::Metadata)> {
    let before = fs::symlink_metadata(path)?;
    ensure!(
        before.is_file() && !before.file_type().is_symlink(),
        "unsafe lifecycle resource"
    );
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    ensure!(
        same_file_identity(&before, &file.metadata()?),
        "lifecycle resource changed during verification"
    );
    let mut buffer = [0u8; INTEGRITY_BUFFER_BYTES];
    let mut digest = Sha256::new();
    let mut bytes = 0u64;
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        bytes += count as u64;
        digest.update(&buffer[..count]);
    }
    after_read();
    let after = fs::symlink_metadata(path)?;
    ensure!(
        bytes == before.len()
            && !after.file_type().is_symlink()
            && same_file_identity(&before, &file.metadata()?)
            && same_file_identity(&before, &after),
        "lifecycle resource changed during verification"
    );
    Ok((hex::encode(digest.finalize()), before))
}

fn verify_directory_against_files(target: &Path, expected: &[Value]) -> Result<()> {
    let root_metadata = fs::symlink_metadata(target)?;
    ensure!(
        root_metadata.is_dir() && !root_metadata.file_type().is_symlink(),
        "unsafe owned version path"
    );
    let mut actual = Vec::new();
    fn visit(root: &Path, directory: &Path, output: &mut Vec<Value>) -> Result<()> {
        let directory_before = fs::symlink_metadata(directory)?;
        ensure!(
            directory_before.is_dir() && !directory_before.file_type().is_symlink(),
            "unsafe owned version path"
        );
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
                let (digest, verified) = streaming_file_digest(&path)?;
                ensure!(
                    same_file_identity(&metadata, &verified),
                    "lifecycle resource changed during verification"
                );
                output.push(json!({"path":path.strip_prefix(root)?.to_string_lossy(),"sha256":digest,"size":verified.len(),"mode":verified.permissions().mode() & 0o777}));
            } else {
                bail!("installed package contains an unsupported entry")
            }
        }
        ensure!(
            same_file_identity(&directory_before, &fs::symlink_metadata(directory)?),
            "lifecycle directory changed during verification"
        );
        Ok(())
    }
    visit(target, target, &mut actual)?;
    actual.sort_by(|a, b| a["path"].as_str().cmp(&b["path"].as_str()));
    if actual != expected {
        bail!("owned version no longer matches the release inventory")
    }
    Ok(())
}

fn verify_all_owned_versions(paths: &Paths) -> Result<()> {
    // Read the immutable inventory once per pass, while hashing every version
    // freshly. Later authorization boundaries still perform their own pass.
    let owned: Value = state::read_json(&paths.state_dir.join("owned-versions.json"))?;
    for version in owned_versions(paths)? {
        verify_owned_version_from_inventory(&version, &owned)?;
    }
    Ok(())
}

fn validate_retained_target_metadata(target: &Path, version: &str) -> Result<()> {
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
    Ok(())
}

fn validate_retained_target_cli(target: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(target.join("bin/loomex"))?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.permissions().mode() & 0o111 == 0
    {
        bail!("rollback target CLI is not executable")
    }
    Ok(())
}

fn validate_rollback_target(target: &Path, version: &str) -> Result<()> {
    validate_retained_target_metadata(target, version)?;
    ensure!(
        streaming_file_digest(&target.join("metadata/compatibility-manifest.json"))?.0
            == state::digest(include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/contracts/compatibility-manifest.json"
            ))),
        "LIFECYCLE_ROLLBACK_COMPATIBILITY_MISMATCH"
    );
    validate_retained_target_cli(target)
}

// This is not general rollback compatibility negotiation. An abort restores
// only the already-running current package, exactly captured by its Update and
// verified against that package's own immutable inventory. A newer CLI's
// product catalog need not be byte-identical to the daemon it is preserving.
fn validate_abandonment_current_previous(
    paths: &Paths,
    operation: &Operation,
    previous: &Path,
    version: &str,
) -> Result<()> {
    ensure!(
        operation.kind == OperationKind::Update
            && operation.previous_target.as_deref() == Some(previous)
            && current_target(paths)?.as_deref() == Some(previous),
        "LIFECYCLE_ABANDONMENT_CURRENT_TARGET_MISMATCH"
    );
    let resources = operation
        .resources
        .as_ref()
        .context("LIFECYCLE_ABANDONMENT_RESOURCE_MISSING")?;
    ensure!(
        resources
            .owned_versions
            .iter()
            .any(|target| target == previous),
        "LIFECYCLE_ABANDONMENT_PREVIOUS_NOT_CAPTURED"
    );
    validate_retained_target_metadata(previous, version)
        .context("LIFECYCLE_ABANDONMENT_PREVIOUS_METADATA_MISMATCH")?;
    validate_retained_target_cli(previous).context("LIFECYCLE_ABANDONMENT_PREVIOUS_CLI_INVALID")?;
    verify_owned_version(paths, previous)
        .context("LIFECYCLE_ABANDONMENT_PREVIOUS_INVENTORY_MISMATCH")
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
        let before = fs::symlink_metadata(directory)?;
        ensure!(
            before.is_dir() && !before.file_type().is_symlink(),
            "unsafe owned version path"
        );
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
                let (digest, verified) = streaming_file_digest(&path)?;
                ensure!(
                    same_file_identity(&metadata, &verified),
                    "lifecycle resource changed during verification"
                );
                entries.push((
                    path.strip_prefix(root)?.to_string_lossy().into_owned(),
                    digest,
                    metadata.permissions().mode() & 0o777,
                ));
            } else {
                bail!("installed package contains an unsupported entry")
            }
        }
        ensure!(
            same_file_identity(&before, &fs::symlink_metadata(directory)?),
            "lifecycle directory changed during verification"
        );
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

// Only fixed, read-only launchd observations are parsed. Unknown command exits,
// truncated output and malformed identities never mean absence.
fn classify_label_output(
    uid: u32,
    code: Option<i32>,
    stdout: &[u8],
    stderr: &[u8],
) -> LabelObservation {
    let Ok(stdout) = std::str::from_utf8(stdout) else {
        return LabelObservation::Unknown;
    };
    let Ok(stderr) = std::str::from_utf8(stderr) else {
        return LabelObservation::Unknown;
    };
    let missing =
        format!("Could not find service \"app.loomex.runner\" in domain for user gui: {uid}");
    let lines: Vec<_> = stderr.lines().collect();
    if code == Some(113)
        && stdout.is_empty()
        && (lines == [missing.as_str()] || lines == ["Bad request.", missing.as_str()])
    {
        return LabelObservation::Absent;
    }
    if code != Some(0)
        || !stderr.is_empty()
        || !stdout.starts_with(&format!("gui/{uid}/app.loomex.runner = {{\n"))
        || !stdout.ends_with("}\n")
    {
        return LabelObservation::Unknown;
    }
    let mut pid = None;
    let mut program = None;
    for line in stdout.lines() {
        if let Some(value) = line.strip_prefix("\tpid = ") {
            if pid.is_some() {
                return LabelObservation::Unknown;
            }
            let Some(value) = value.parse::<i32>().ok().filter(|pid| *pid > 0) else {
                return LabelObservation::Unknown;
            };
            pid = Some(value);
        }
        if let Some(value) = line.strip_prefix("\tprogram = ") {
            if program.is_some() {
                return LabelObservation::Unknown;
            }
            let path = PathBuf::from(value);
            if !path.is_absolute() {
                return LabelObservation::Unknown;
            }
            program = Some(path);
        }
    }
    match (pid, program) {
        (Some(pid), Some(program)) => LabelObservation::Loaded { pid, program },
        (None, Some(program)) => LabelObservation::LoadedIdle { program },
        _ => LabelObservation::Unknown,
    }
}

async fn observe_label(_paths: &Paths) -> LabelObservation {
    if lifecycle_test_mode() {
        #[cfg(test)]
        {
            if let Some(value) = TEST_LABEL_OBSERVATION.lock().unwrap().clone() {
                return value;
            }
            if TEST_LABEL_PRESENT.load(Ordering::SeqCst) {
                return LabelObservation::Loaded {
                    pid: 111111,
                    program: _paths.current().join("bin/loomex-runner"),
                };
            }
        }
        return LabelObservation::Absent;
    }
    use tokio::io::AsyncReadExt;
    let uid = unsafe { libc::geteuid() };
    let child = tokio::process::Command::new("/bin/launchctl")
        .arg("print")
        .arg(format!("gui/{uid}/app.loomex.runner"))
        .env("LC_ALL", "C")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn();
    let Ok(mut child) = child else {
        return LabelObservation::Unknown;
    };
    let Some(stdout) = child.stdout.take() else {
        return LabelObservation::Unknown;
    };
    let Some(stderr) = child.stderr.take() else {
        return LabelObservation::Unknown;
    };
    let read = async {
        let mut out = Vec::new();
        let mut err = Vec::new();
        let mut stdout = stdout.take(65537);
        let mut stderr = stderr.take(65537);
        let (status, out_result, err_result) = tokio::join!(
            child.wait(),
            stdout.read_to_end(&mut out),
            stderr.read_to_end(&mut err)
        );
        match (status, out_result, err_result) {
            (Ok(status), Ok(_), Ok(_)) if out.len() <= 65536 && err.len() <= 65536 => {
                classify_label_output(uid, status.code(), &out, &err)
            }
            _ => LabelObservation::Unknown,
        }
    };
    // This kills only our read-only inspection child on timeout, never the
    // service or a stop request. No unbounded output or retained reader task.
    tokio::time::timeout(Duration::from_millis(250), read)
        .await
        .unwrap_or(LabelObservation::Unknown)
}

#[cfg(target_os = "macos")]
fn inspect_process(pid: i32) -> ProcessObservation {
    if pid <= 0 {
        return ProcessObservation::Unknown;
    }
    // Signal 0 is only a presence probe. EPERM/inspection failure is unknown.
    if unsafe { libc::kill(pid, 0) } != 0 {
        return if std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) {
            ProcessObservation::Exited
        } else {
            ProcessObservation::Unknown
        };
    }
    let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of::<libc::proc_bsdinfo>();
    if unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDTBSDINFO,
            0,
            (&mut info as *mut libc::proc_bsdinfo).cast(),
            size as i32,
        )
    } != size as i32
    {
        return ProcessObservation::Unknown;
    }
    let mut buffer = [0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    let len = unsafe { libc::proc_pidpath(pid, buffer.as_mut_ptr().cast(), buffer.len() as u32) };
    if len <= 0 {
        return ProcessObservation::Unknown;
    }
    let bytes = buffer.split(|byte| *byte == 0).next().unwrap_or_default();
    use std::os::unix::ffi::OsStrExt;
    let executable = PathBuf::from(std::ffi::OsStr::from_bytes(bytes));
    if !executable.is_absolute() || info.pbi_pid != pid as u32 {
        return ProcessObservation::Unknown;
    }
    ProcessObservation::Present(ProcessIdentity {
        pid,
        uid: info.pbi_uid,
        started_seconds: info.pbi_start_tvsec,
        started_micros: info.pbi_start_tvusec,
        executable,
    })
}

#[cfg(not(target_os = "macos"))]
fn inspect_process(_pid: i32) -> ProcessObservation {
    ProcessObservation::Unknown
}

fn observe_recorded_process(process: &ProcessIdentity) -> ProcessObservation {
    #[cfg(test)]
    if lifecycle_test_mode() {
        if let Some(value) = TEST_PROCESS_OBSERVATION.lock().unwrap().clone() {
            return value;
        }
        return if TEST_LABEL_PRESENT.load(Ordering::SeqCst) {
            ProcessObservation::Present(process.clone())
        } else {
            ProcessObservation::Exited
        };
    }
    inspect_process(process.pid)
}

fn stopped_singleton(paths: &Paths, first_install: bool) -> Result<File> {
    // Cooperative server authority is bound to this installation's state
    // namespace. control::serve acquires this same secure lock before socket
    // bind/admission and retains it through managed drain and native workers.
    // This does not classify unknown same-user processes or alternate manual
    // state directories as absent. Exact old PID/label proofs remain separate.
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(first_install || lifecycle_test_mode())
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(paths.state_dir.join("daemon.lock"))?;
    let metadata = lock.metadata()?;
    ensure!(
        metadata.is_file()
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.permissions().mode() & 0o077 == 0,
        "unsafe daemon singleton"
    );
    lock.try_lock_exclusive()
        .context("daemon ownership remains unavailable")?;
    Ok(lock)
}

fn verify_stop_binding(
    paths: &Paths,
    operation: &Operation,
    stop: &ServiceStopIntent,
    permit_switch: bool,
) -> Result<()> {
    operation.validate()?;
    let resources = operation
        .resources
        .as_ref()
        .context("activation resources missing")?;
    ensure!(
        resources.launch_agent == launch_agent(paths),
        "service-stop LaunchAgent namespace changed"
    );
    match stop.direction {
        StopDirection::ActivateCandidate => ensure!(
            stop.target == operation.previous_target
                && stop.plist_digest == resources.launch_agent_backup_sha256,
            "activation stop differs from captured previous service"
        ),
        StopDirection::RestorePrevious => ensure!(
            (stop.target.as_ref() == Some(&stop.package.target)
                && stop.plist_digest.as_ref() == Some(&resources.staged_launch_agent_sha256))
                || (stop.target == operation.previous_target
                    && stop.plist_digest == resources.launch_agent_backup_sha256),
            "rollback stop differs from captured service"
        ),
    }

    ensure!(
        regular_digest(&paths.state_dir.join("install-receipt.json"))? == stop.receipt_digest
            && regular_digest(&paths.state_dir.join("owned-versions.json"))?.as_deref()
                == Some(&stop.inventory_digest),
        "service-stop receipt or inventory changed"
    );
    verify_all_owned_versions(paths)?;
    ensure!(
        resources.owned_versions.contains(&stop.package.target)
            && owned_versions(paths)?.contains(&stop.package.target),
        "service-stop candidate ownership changed"
    );
    validate_rollback_target(&stop.package.target, &stop.package.version)?;
    ensure!(
        regular_digest(&resources.staged_launch_agent)?.as_deref()
            == Some(&resources.staged_launch_agent_sha256)
            && regular_digest(&resources.launch_agent_backup)?
                == resources.launch_agent_backup_sha256,
        "service-stop recovery configuration changed"
    );
    let pointer = current_target(paths)?;
    let plist = regular_digest(&resources.launch_agent)?;
    let desired = match stop.direction {
        StopDirection::ActivateCandidate => Some(&stop.package.target),
        StopDirection::RestorePrevious => operation.previous_target.as_ref(),
    };
    let desired_plist = match stop.direction {
        StopDirection::ActivateCandidate => Some(&resources.staged_launch_agent_sha256),
        StopDirection::RestorePrevious => resources.launch_agent_backup_sha256.as_ref(),
    };
    ensure!(
        (pointer == stop.target || (permit_switch && pointer.as_ref() == desired))
            && (plist == stop.plist_digest || (permit_switch && plist.as_ref() == desired_plist)),
        "service-stop pointer or configuration changed"
    );
    if !permit_switch {
        ensure!(
            regular_digest(&paths.state_dir.join("drain.json"))? == stop.drain_digest,
            "service-stop drain changed"
        );
    }
    if let Some(target) = &stop.target {
        ensure!(
            resources.owned_versions.contains(target) && owned_versions(paths)?.contains(target),
            "service-stop prior ownership changed"
        );
        verify_owned_version(paths, target)?;
    }
    Ok(())
}

fn service_stop_pending(operation: &Operation) -> Value {
    json!({"activated":false,"resumed":false,"pending":true,"reason":"service_stop","operation":operation})
}

fn require_recorded_process_exit(operation: &Operation) -> Result<()> {
    ensure!(
        operation.service_stops.iter().all(|stop| stop
            .process
            .as_ref()
            .is_none_or(|process| observe_recorded_process(process) == ProcessObservation::Exited)),
        "idle label recorded process exit is unconfirmed"
    );
    Ok(())
}

fn idle_service_singleton(paths: &Paths, operation: &Operation, program: &Path) -> Result<File> {
    let target = current_target(paths)?.context("idle label has no owned target")?;
    let plist = regular_digest(&launch_agent(paths))?.context("idle label has no configuration")?;
    verify_recovery_service(paths, operation, &target, &plist)?;
    ensure!(
        program == paths.current().join("bin/loomex-runner")
            || program == target.join("bin/loomex-runner"),
        "idle label program differs from owned target"
    );
    require_recorded_process_exit(operation)?;
    let singleton = stopped_singleton(paths, false)?;
    ensure!(
        matches!(fs::symlink_metadata(paths.state_dir.join("control.sock")), Err(error) if error.kind() == std::io::ErrorKind::NotFound),
        "idle label control socket is not absent"
    );
    Ok(singleton)
}

async fn prepare_service_stop(
    paths: &Paths,
    operation: &mut Operation,
    direction: StopDirection,
) -> Result<()> {
    ensure!(
        operation
            .service_stops
            .last()
            .is_none_or(|stop| stop.request == StopRequest::ObservedStopped),
        "unresolved stop cannot be replaced"
    );
    let target = current_target(paths)?;
    let plist_digest = regular_digest(&launch_agent(paths))?;
    let uid = unsafe { libc::geteuid() };
    let process = match observe_label(paths).await {
        LabelObservation::Loaded { pid, program } => {
            let target = target
                .as_ref()
                .context("loaded service has no owned current target")?;
            let digest = plist_digest
                .as_ref()
                .context("loaded service has no configuration")?;
            let version = verify_recovery_service(paths, operation, target, digest)?;
            ensure!(
                program == paths.current().join("bin/loomex-runner")
                    || program == target.join("bin/loomex-runner"),
                "loaded service program differs from owned target"
            );
            let status = daemon_status(paths).await?;
            ensure!(
                candidate_drain_can_be_released(&status, &version),
                "service stop requires the exact drained idle daemon"
            );
            let process = if lifecycle_test_mode() {
                ProcessIdentity {
                    pid,
                    uid,
                    started_seconds: 1,
                    started_micros: 0,
                    executable: target.join("bin/loomex-runner"),
                }
            } else {
                match inspect_process(pid) {
                    ProcessObservation::Present(process) => process,
                    _ => bail!("service process identity unavailable"),
                }
            };
            ensure!(
                process.uid == uid && process.executable == target.join("bin/loomex-runner"),
                "service process identity differs from owned target"
            );
            Some(process)
        }
        LabelObservation::Absent => {
            // Label absence is not server exclusivity. The exact bound state
            // directory's secure singleton fences every supported server
            // before socket bind/admission, including retained native workers.
            let _singleton = stopped_singleton(paths, target.is_none())?;
            None
        }
        LabelObservation::LoadedIdle { program } => {
            ensure!(
                direction == StopDirection::RestorePrevious
                    && !operation.service_stops.is_empty()
                    && operation.service_stops.len() < 2,
                "idle label requires captured restoration stop"
            );
            let _singleton = idle_service_singleton(paths, operation, &program)?;
            None
        }
        LabelObservation::Unknown => bail!("service label identity unavailable"),
    };
    if operation.abandonment.is_none() {
        operation.schema = if operation.auth_baseline.is_some() {
            OPERATION_SCHEMA
        } else {
            PRE_AUTH_OPERATION_SCHEMA
        }
        .into();
    }
    operation.service_stops.push(ServiceStopIntent {
        operation_id: operation.id,
        direction,
        package: operation
            .package
            .clone()
            .context("activation package missing")?,
        uid,
        label: format!("gui/{uid}/app.loomex.runner"),
        target,
        plist_digest,
        receipt_digest: regular_digest(&paths.state_dir.join("install-receipt.json"))?,
        inventory_digest: regular_digest(&paths.state_dir.join("owned-versions.json"))?
            .context("owned inventory unavailable")?,
        drain_digest: regular_digest(&paths.state_dir.join("drain.json"))?,
        process,
        request: StopRequest::Prepared,
    });
    set_checkpoint(
        paths,
        operation,
        "service_stop_pending",
        "service_stop_intent_prepared",
    )
}

// A failed spawn proves no child received the request. Only that definitive
// outcome may reset a v3 dispatch intent. A failed/ambiguous reset leaves the
// caller uncertain and never authorizes another stop in this invocation.
fn record_stop_not_dispatched(paths: &Paths, operation: &mut Operation) -> Result<()> {
    if operation.abandonment.is_some()
        || operation
            .service_stops
            .last()
            .is_some_and(|stop| stop.process.is_none())
    {
        let uncertain = operation.clone();
        #[cfg(test)]
        recovery_fault("before_stop_not_dispatched_checkpoint")?;
        operation
            .service_stops
            .last_mut()
            .context("service-stop intent missing")?
            .request = StopRequest::Prepared;
        if let Err(error) = set_checkpoint(
            paths,
            operation,
            "service_stop_pending",
            "service_stop_intent_prepared",
        ) {
            *operation = uncertain;
            return Err(error);
        }
    }
    Ok(())
}

async fn request_service_stop(paths: &Paths, operation: &mut Operation) -> Result<()> {
    let stop = operation
        .service_stops
        .last()
        .context("service-stop intent missing")?
        .clone();
    verify_stop_binding(paths, operation, &stop, false)?;
    let _idle_singleton = if let Some(process) = &stop.process {
        let label = observe_label(paths).await;
        ensure!(
            matches!(label, LabelObservation::Loaded { pid, program } if pid == process.pid && (program == process.executable || program == paths.current().join("bin/loomex-runner"))),
            "service label changed before stop"
        );
        ensure!(
            observe_recorded_process(process) == ProcessObservation::Present(process.clone()),
            "service process changed before stop"
        );
        let version = stop
            .target
            .as_ref()
            .and_then(|target| target.file_name())
            .and_then(|name| name.to_str())
            .context("stop target version missing")?;
        ensure!(
            candidate_drain_can_be_released(&daemon_status(paths).await?, version),
            "service stop requires fresh drained zero managed work"
        );
        None
    } else {
        let program = match observe_label(paths).await {
            LabelObservation::Absent => return Ok(()),
            LabelObservation::LoadedIdle { program } => program,
            _ => bail!("idle label identity changed before stop"),
        };
        ensure!(
            stop.direction == StopDirection::RestorePrevious && operation.service_stops.len() == 2,
            "idle label unload has no captured restoration intent"
        );
        let singleton = idle_service_singleton(paths, operation, &program)?;
        ensure!(
            observe_label(paths).await == LabelObservation::LoadedIdle { program },
            "idle label changed under singleton ownership"
        );
        verify_stop_binding(paths, operation, &stop, false)?;
        require_recorded_process_exit(operation)?;
        Some(singleton)
    };
    #[cfg(test)]
    recovery_fault("after_stop_intent")?;
    if operation.abandonment.is_some() || stop.process.is_none() {
        // Abandonment and no-process idle-label unloads record uncertainty
        // BEFORE their effect. Prepared is a definitive unsent intent;
        // Unconfirmed is observation-only, even if spawn never occurred.
        operation.service_stops.last_mut().unwrap().request = StopRequest::Unconfirmed;
        set_checkpoint(
            paths,
            operation,
            "service_stop_pending",
            "service_stop_dispatching",
        )?;
        #[cfg(test)]
        recovery_fault("after_abandonment_stop_dispatch_intent")?;
    }
    let request = if lifecycle_test_mode() {
        #[cfg(test)]
        {
            TEST_STOP_COUNT.fetch_add(1, Ordering::SeqCst);
            if TEST_BOOTOUT_FAIL.load(Ordering::SeqCst) {
                record_stop_not_dispatched(paths, operation)?;
                bail!("injected stop spawn failure");
            }
            if TEST_STOP_WAIT_UNCONFIRMED.load(Ordering::SeqCst) {
                operation.service_stops.last_mut().unwrap().request = StopRequest::Unconfirmed;
                return set_checkpoint(
                    paths,
                    operation,
                    "service_stop_pending",
                    "service_stop_requested",
                );
            }
            if !TEST_DELAYED_SERVICE_STOP.load(Ordering::SeqCst) {
                TEST_LABEL_PRESENT.store(false, Ordering::SeqCst);
                if stop.process.is_none() {
                    *TEST_LABEL_OBSERVATION.lock().unwrap() = None;
                }
            }
        }
        StopRequest::Accepted
    } else {
        let spawn = tokio::process::Command::new("/bin/launchctl")
            .arg("bootout")
            .arg(&stop.label)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn();
        let mut child = match spawn {
            Ok(child) => child,
            Err(error) => {
                record_stop_not_dispatched(paths, operation)?;
                return Err(error).context("service-stop request was not dispatched");
            }
        };
        // An expired caller budget does not terminate this mutating child and
        // does not authorize replay. The same sealed intent observes only.
        match tokio::time::timeout(Duration::from_secs(5), child.wait()).await {
            Ok(Ok(status)) if status.success() => StopRequest::Accepted,
            _ => StopRequest::Unconfirmed,
        }
    };
    operation.service_stops.last_mut().unwrap().request = request;
    set_checkpoint(
        paths,
        operation,
        "service_stop_pending",
        "service_stop_requested",
    )?;
    #[cfg(test)]
    recovery_fault("after_stop_request")?;
    Ok(())
}

// Return the singleton guard only after actual absence AND old-process exit.
// A later caller resumes this same intent; it never reissues bootout.
async fn observe_service_stop(
    paths: &Paths,
    operation: &mut Operation,
    bounded: bool,
) -> Result<Option<File>> {
    let stop = operation
        .service_stops
        .last()
        .context("service-stop intent missing")?
        .clone();
    let switched = stop.request == StopRequest::ObservedStopped;
    verify_stop_binding(paths, operation, &stop, switched)?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    for _ in 0..if bounded { 20 } else { 1 } {
        let interval = tokio::time::Instant::now() + Duration::from_millis(250);
        match observe_label(paths).await {
            LabelObservation::Loaded { pid, program } => {
                ensure!(
                    stop.process.as_ref().is_some_and(|old| old.pid == pid
                        && (program == old.executable
                            || program == paths.current().join("bin/loomex-runner"))),
                    "service label was replaced while stop pending"
                );
                if let Some(old) = &stop.process {
                    match observe_recorded_process(old) {
                        ProcessObservation::Present(actual) => ensure!(
                            actual == *old,
                            "service process was replaced while stop pending"
                        ),
                        ProcessObservation::Exited => {
                            bail!("loaded service process identity conflicts with recorded exit")
                        }
                        ProcessObservation::Unknown => {}
                    }
                }
            }
            LabelObservation::Absent => {
                if stop.process.is_none()
                    && stop.direction == StopDirection::RestorePrevious
                    && operation.service_stops.len() == 2
                {
                    require_recorded_process_exit(operation)?;
                }
                let exited = match &stop.process {
                    None => true,
                    Some(old) => match observe_recorded_process(old) {
                        ProcessObservation::Exited => true,
                        ProcessObservation::Present(actual) => {
                            ensure!(actual == *old, "recorded service PID was reused");
                            false
                        }
                        ProcessObservation::Unknown => false,
                    },
                };
                if exited && let Ok(singleton) = stopped_singleton(paths, stop.target.is_none()) {
                    // Verify the label again while singleton ownership fences
                    // a competing daemon. Unknown/loaded still cannot switch.
                    if observe_label(paths).await == LabelObservation::Absent {
                        operation.service_stops.last_mut().unwrap().request =
                            StopRequest::ObservedStopped;
                        set_checkpoint(
                            paths,
                            operation,
                            "service_stopped",
                            "old_service_stop_verified",
                        )?;
                        return Ok(Some(singleton));
                    }
                }
            }
            LabelObservation::LoadedIdle { .. } | LabelObservation::Unknown => {}
        }
        if bounded && !lifecycle_test_mode() {
            tokio::time::sleep_until(interval.min(deadline)).await;
            if tokio::time::Instant::now() >= deadline {
                break;
            }
        }
    }
    set_checkpoint(
        paths,
        operation,
        "service_stop_pending",
        "old_service_stop_unconfirmed",
    )?;
    Ok(None)
}

async fn stop_for_direction(
    paths: &Paths,
    operation: &mut Operation,
    direction: StopDirection,
) -> Result<Option<File>> {
    prepare_service_stop(paths, operation, direction).await?;
    request_service_stop(paths, operation).await?;
    observe_service_stop(paths, operation, true).await
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
        if action == "bootout" && TEST_DELAYED_SERVICE_STOP.load(Ordering::SeqCst) {
            // Faithful isolated seam: request accepted, but the old label was
            // still present at the original bounded observation deadline.
            bail!("launchctl service remained loaded after bootout");
        }
        #[cfg(test)]
        if action == "kickstart"
            || (action == "bootstrap" && TEST_ABANDONMENT_RESTART.load(Ordering::SeqCst))
        {
            recovery_fault("restart_failed")?;
            TEST_RESTART_COUNT.fetch_add(1, Ordering::SeqCst);
            if action == "bootstrap" {
                TEST_LABEL_PRESENT.store(true, Ordering::SeqCst);
            }
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
        #[cfg(test)]
        return Ok(!TEST_LABEL_PRESENT.load(Ordering::SeqCst));
        #[cfg(not(test))]
        return Ok(true);
    }
    let paths = Paths::from_environment()?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    for _ in 0..20 {
        let interval = tokio::time::Instant::now() + Duration::from_millis(250);
        match observe_label(&paths).await {
            LabelObservation::Absent => return Ok(true),
            LabelObservation::Unknown => bail!("service label observation unavailable"),
            LabelObservation::Loaded { .. } | LabelObservation::LoadedIdle { .. } => {}
        }
        tokio::time::sleep_until(interval.min(deadline)).await;
        if tokio::time::Instant::now() >= deadline {
            break;
        }
    }
    Ok(false)
}

async fn daemon_status(paths: &Paths) -> Result<Value> {
    #[cfg(test)]
    TEST_STATUS_COUNT.fetch_add(1, Ordering::SeqCst);
    #[cfg(test)]
    if TEST_STATUS_UNAVAILABLE.load(Ordering::SeqCst) {
        bail!("injected unavailable daemon status");
    }
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

async fn local_auth_status(paths: &Paths) -> Result<Value> {
    local_auth_observation(paths, json!({})).await
}

async fn local_auth_startup_status(paths: &Paths) -> Result<Value> {
    // The local client sends this read-only option only when the negotiated
    // server advertises auth:startup-observation/v1. A retained controller
    // without it receives the original {} status request on the same socket.
    local_auth_observation(paths, json!({"observation":"startup"})).await
}

async fn local_auth_observation(paths: &Paths, params: Value) -> Result<Value> {
    #[cfg(test)]
    if let Some(status) = TEST_AUTH_STATUS.lock().unwrap().clone() {
        return Ok(status);
    }
    let response =
        crate::control::lifecycle_client(&paths.state_dir, "auth.status", params).await?;
    ensure!(
        response.get("error").is_none(),
        "candidate auth status is unavailable"
    );
    response
        .get("result")
        .cloned()
        .context("candidate auth status is unavailable")
}

fn parse_auth_baseline(status: &Value) -> Result<AuthBaseline> {
    ensure!(
        status["loginPending"] == false,
        "authentication flow state is unconfirmed"
    );
    match (status["code"].as_str(), status["authenticated"].as_bool()) {
        (Some("AUTHENTICATED"), Some(true)) => Ok(AuthBaseline::Authenticated {
            installation_id: Uuid::parse_str(
                status["installationId"]
                    .as_str()
                    .context("auth installation is unavailable")?,
            )?,
            active_organization: status["activeOrganization"]
                .as_str()
                .map(Uuid::parse_str)
                .transpose()?,
        }),
        (Some("AUTH_REQUIRED"), Some(false)) => Ok(AuthBaseline::SignedOut {
            installation_id: status["installationId"]
                .as_str()
                .map(Uuid::parse_str)
                .transpose()?,
        }),
        (Some("AUTH_RECOVERY_PENDING" | "LOGOUT_PENDING"), _) => {
            bail!("prior authentication recovery is pending")
        }
        _ => bail!("prior authentication state is unconfirmed"),
    }
}

async fn capture_auth_baseline(
    paths: &Paths,
    previous_target: Option<&Path>,
) -> Result<AuthBaseline> {
    if previous_target.is_none() {
        return Ok(AuthBaseline::Initial);
    }
    #[cfg(test)]
    if lifecycle_test_mode() && TEST_AUTH_STATUS.lock().unwrap().is_none() {
        return Ok(AuthBaseline::SignedOut {
            installation_id: None,
        });
    }
    parse_auth_baseline(&local_auth_status(paths).await?)
}

fn require_auth_continuity(status: &Value, baseline: &AuthBaseline) -> Result<()> {
    let candidate =
        parse_auth_baseline(status).context("candidate authentication is unconfirmed")?;
    let matched = match (baseline, candidate) {
        (AuthBaseline::Initial, _) => true,
        (
            AuthBaseline::SignedOut {
                installation_id: before,
            },
            AuthBaseline::SignedOut {
                installation_id: after,
            },
        ) => before.is_none_or(|id| Some(id) == after),
        (
            AuthBaseline::Authenticated {
                installation_id: before_id,
                active_organization: before_org,
            },
            AuthBaseline::Authenticated {
                installation_id: after_id,
                active_organization: after_org,
            },
        ) => before_id == &after_id && before_org == &after_org,
        _ => false,
    };
    ensure!(
        matched,
        "candidate authentication scope differs from previous service"
    );
    Ok(())
}

fn transient_auth_store_observation(status: &Value) -> bool {
    // Only a read-only store availability failure is retryable. Pending auth,
    // interaction/permission failures, malformed status and scope changes are
    // definitive refusals; none can establish the captured baseline.
    status["code"] == "STORE_UNAVAILABLE"
        && status["authenticated"] == false
        && status["loginPending"] == false
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

async fn healthy_candidate(
    paths: &Paths,
    version: &str,
    baseline: Option<&AuthBaseline>,
) -> Result<()> {
    healthy_service(paths, version, baseline, false).await
}

// Only an exact restoration of the journal's prior target may use the
// pre-auth-gate journal's legacy status proof. A switched candidate may not.
async fn healthy_restored_previous(
    paths: &Paths,
    version: &str,
    baseline: Option<&AuthBaseline>,
) -> Result<()> {
    healthy_service(paths, version, baseline, true).await
}

// Qualified startup observation is independent of ordinary auth operation
// admission. A daemon performing a legitimate refresh may hold its shared auth
// state for longer than the short admission budget used by client mutations.
const STARTUP_AUTH_HEALTH_BUDGET: Duration = Duration::from_secs(22);
fn startup_health_budget() -> Duration {
    STARTUP_AUTH_HEALTH_BUDGET
}

async fn healthy_service(
    paths: &Paths,
    version: &str,
    baseline: Option<&AuthBaseline>,
    restoring_previous: bool,
) -> Result<()> {
    #[cfg(test)]
    if TEST_CANDIDATE_HEALTH_FAIL.load(Ordering::SeqCst) {
        bail!("candidate health is unconfirmed")
    }
    let deadline = tokio::time::Instant::now() + startup_health_budget();
    let mut auth_store_unavailable = false;
    for _ in 0..20 {
        let interval = tokio::time::Instant::now() + Duration::from_millis(250);
        if let Ok(Ok(status)) = tokio::time::timeout_at(deadline, daemon_status(paths)).await
            && status["version"] == version
            && status["activeJobs"].as_u64().is_some()
            && status["draining"] == false
        {
            if let Some(baseline) = baseline {
                #[cfg(test)]
                if lifecycle_test_mode() && TEST_AUTH_STATUS.lock().unwrap().is_none() {
                    return Ok(());
                }
                let auth_status = tokio::time::timeout_at(
                    deadline,
                    local_auth_startup_status(paths),
                )
                .await
                .context(
                    "candidate authentication is unconfirmed: observation deadline exceeded",
                )??;
                if transient_auth_store_observation(&auth_status) {
                    auth_store_unavailable = true;
                } else {
                    require_auth_continuity(&auth_status, baseline)?;
                    return Ok(());
                }
            } else if !restoring_previous && !lifecycle_test_mode() {
                // An older journal cannot prove which authenticated scope it replaced.
                bail!("lifecycle auth baseline is unavailable");
            } else {
                return Ok(());
            }
        }
        tokio::time::sleep_until(interval.min(deadline)).await;
        if tokio::time::Instant::now() >= deadline {
            break;
        }
    }
    if auth_store_unavailable {
        bail!("candidate authentication is unconfirmed: STORE_UNAVAILABLE");
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
            Ok(Some(streaming_file_digest(path)?.0))
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

/// Must run under LifecycleLock before uninstall writes, drain or logout.
pub fn require_terminal_before_uninstall(paths: &Paths) -> Result<()> {
    if let Some(operation) = read_optional::<Operation>(&paths.operation())? {
        operation.validate()?;
        ensure!(terminal(&operation.phase), "LIFECYCLE_OPERATION_PENDING");
    }
    Ok(())
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
            return Ok(
                json!({"reconciled":false,"pending":true,"reason":value["reason"],"transaction":value}),
            );
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
    if let Some(intent) = &existing.abandonment {
        ensure!(
            existing.phase == "rolled_back",
            "LIFECYCLE_OPERATION_PENDING"
        );
        let successor = intent
            .successor
            .as_ref()
            .context("LIFECYCLE_ABANDONMENT_ACKNOWLEDGEMENT_REQUIRED")?;
        let journal: Value = state::read_json(&paths.state_dir.join("bootstrap-install.json"))?;
        ensure!(
            &successor.package == package
                && journal["schema"] == "app.loomex.runner.bootstrap-install/v2"
                && journal["operationId"] == existing.id.to_string()
                && journal["successorConfigurationDigest"] == successor.configuration_digest
                && bootstrap_configuration_digest(&journal["successorConfiguration"])?
                    == successor.configuration_digest,
            "LIFECYCLE_ABANDONMENT_SUCCESSOR_MISMATCH"
        );
        abandonment_bootstrap_configuration(paths, &existing)?;
    }
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
                healthy_candidate(paths, &package.version, existing.auth_baseline.as_ref()).await?;
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

async fn restarted_service_identity_matches(paths: &Paths, target: &Path) -> bool {
    let LabelObservation::Loaded { pid, program } = observe_label(paths).await else {
        return false;
    };
    if program != target.join("bin/loomex-runner")
        && program != paths.current().join("bin/loomex-runner")
    {
        return false;
    }
    let actual = if lifecycle_test_mode() {
        #[cfg(test)]
        if let Some(value) = TEST_PROCESS_OBSERVATION.lock().unwrap().clone() {
            value
        } else {
            ProcessObservation::Present(ProcessIdentity {
                pid,
                uid: unsafe { libc::geteuid() },
                started_seconds: 1,
                started_micros: 0,
                executable: target.join("bin/loomex-runner"),
            })
        }
        #[cfg(not(test))]
        {
            ProcessObservation::Unknown
        }
    } else {
        inspect_process(pid)
    };
    matches!(actual, ProcessObservation::Present(actual) if actual.pid == pid && actual.uid == unsafe {libc::geteuid()} && actual.executable == target.join("bin/loomex-runner"))
}

async fn complete_stopped_transition(
    paths: &Paths,
    operation: &mut Operation,
    singleton: File,
) -> Result<Value> {
    let stop = operation
        .service_stops
        .last()
        .context("service-stop intent missing")?
        .clone();
    ensure!(
        stop.request == StopRequest::ObservedStopped,
        "service stop has not been verified"
    );
    verify_stop_binding(paths, operation, &stop, true)?;
    let resources = operation
        .resources
        .clone()
        .context("activation resources missing")?;
    let target = match stop.direction {
        StopDirection::ActivateCandidate => Some(stop.package.target.clone()),
        StopDirection::RestorePrevious => operation.previous_target.clone(),
    };
    let (source, digest) = match stop.direction {
        StopDirection::ActivateCandidate => (
            &resources.staged_launch_agent,
            Some(&resources.staged_launch_agent_sha256),
        ),
        StopDirection::RestorePrevious => (
            &resources.launch_agent_backup,
            resources.launch_agent_backup_sha256.as_ref(),
        ),
    };
    #[cfg(test)]
    recovery_fault("after_stop_verified")?;
    if current_target(paths)? != target {
        if let Some(target) = &target {
            write_pointer(paths, target, operation)?;
        } else if paths.current().is_symlink() {
            fs::remove_file(paths.current())?;
            File::open(&paths.install_base)?.sync_all()?;
        }
    }
    #[cfg(test)]
    recovery_fault("after_stop_pointer")?;
    if regular_digest(&resources.launch_agent)?.as_ref() != digest {
        if digest.is_some() {
            replace_regular_atomically(source, &resources.launch_agent, operation)?;
        } else {
            remove_regular_and_sync(&resources.launch_agent)?;
        }
    }
    set_checkpoint(
        paths,
        operation,
        "pointer_switched",
        "stopped_pointer_and_plist_switched",
    )?;
    #[cfg(test)]
    recovery_fault("after_stop_configuration")?;
    remove_regular_and_sync(&paths.state_dir.join("drain.json"))?;
    // Holding this guard through file replacement prevents another native
    // owner. Release only for the exact authorized daemon bootstrap.
    drop(singleton);
    #[cfg(test)]
    recovery_fault("before_stop_bootstrap")?;
    if target.is_some() {
        ensure!(
            observe_label(paths).await == LabelObservation::Absent,
            "service appeared before candidate bootstrap"
        );
        if let Err(error) = launchctl("bootstrap", &resources.launch_agent).await {
            set_checkpoint(
                paths,
                operation,
                "recovery_required",
                "stopped_service_start_failed",
            )?;
            return Err(error);
        }
        set_checkpoint(
            paths,
            operation,
            "candidate_started",
            "stopped_service_bootstrapped",
        )?;
        if candidate_health_check_required() {
            let version = target
                .as_ref()
                .and_then(|target| target.file_name())
                .and_then(|name| name.to_str())
                .context("restart version missing")?;
            let health = if stop.direction == StopDirection::RestorePrevious {
                healthy_restored_previous(paths, version, operation.auth_baseline.as_ref()).await
            } else {
                healthy_candidate(paths, version, operation.auth_baseline.as_ref()).await
            };
            if let Err(error) = health {
                set_checkpoint(
                    paths,
                    operation,
                    "recovery_required",
                    "stopped_service_health_failed",
                )?;
                return Err(error);
            }
            ensure!(
                restarted_service_identity_matches(paths, target.as_ref().unwrap()).await,
                "started service process identity is unconfirmed"
            );
        }
    }
    #[cfg(test)]
    recovery_fault("after_stop_bootstrap")?;
    let phase = match stop.direction {
        StopDirection::ActivateCandidate => "completed",
        StopDirection::RestorePrevious => "rolled_back",
    };
    set_checkpoint(paths, operation, phase, "stopped_service_healthy")?;
    Ok(
        json!({"activated":stop.direction == StopDirection::ActivateCandidate,"resumed":true,"operation":operation}),
    )
}

async fn reconcile_service_stop(paths: &Paths, operation: &mut Operation) -> Result<Value> {
    let stop = operation
        .service_stops
        .last()
        .context("service-stop intent missing")?
        .clone();
    verify_stop_binding(
        paths,
        operation,
        &stop,
        stop.request == StopRequest::ObservedStopped,
    )?;
    if stop.request == StopRequest::ObservedStopped
        && matches!(
            observe_label(paths).await,
            LabelObservation::LoadedIdle { .. }
        )
    {
        // The previous stop completed before the candidate was started. Its
        // now-idle loaded label is a different effect: capture the existing
        // restoration intent, never replay the completed activation stop.
        let Some(singleton) =
            stop_for_direction(paths, operation, StopDirection::RestorePrevious).await?
        else {
            return Ok(service_stop_pending(operation));
        };
        return complete_stopped_transition(paths, operation, singleton).await;
    }
    if stop.request == StopRequest::Prepared
        && stop.process.is_none()
        && stop.direction == StopDirection::RestorePrevious
        && operation.service_stops.len() == 2
    {
        // No-process unload journals uncertainty before dispatch. Prepared is
        // therefore a definitive unsent intent; Unconfirmed remains read-only.
        request_service_stop(paths, operation).await?;
    }
    if stop.request == StopRequest::ObservedStopped
        && stop.direction == StopDirection::ActivateCandidate
        && matches!(
            operation.checkpoint.as_deref(),
            Some("stopped_service_start_failed" | "stopped_service_health_failed")
        )
    {
        return restore_failed_candidate(paths, operation).await;
    }
    if stop.request == StopRequest::ObservedStopped {
        let resources = operation
            .resources
            .as_ref()
            .context("activation resources missing")?;
        let (target, digest) = match stop.direction {
            StopDirection::ActivateCandidate => (
                Some(&stop.package.target),
                Some(&resources.staged_launch_agent_sha256),
            ),
            StopDirection::RestorePrevious => (
                operation.previous_target.as_ref(),
                resources.launch_agent_backup_sha256.as_ref(),
            ),
        };
        if current_target(paths)?.as_ref() == target
            && regular_digest(&resources.launch_agent)?.as_ref() == digest
        {
            if let Some(target) = target {
                let version = target
                    .file_name()
                    .and_then(|name| name.to_str())
                    .context("restart version missing")?;
                // An older resume owner may have replaced a health-failure
                // checkpoint with its generic protection message. That message
                // is never evidence of failure or restoration authorization.
                // Verify the exact loaded candidate before any new health
                // observation; only an actual failed observation below can
                // establish a new categorical failure for this operation.
                let generic_loaded_candidate = stop.direction == StopDirection::ActivateCandidate
                    && operation.phase == "recovery_required"
                    && operation.checkpoint.as_deref()
                        == Some("observed state could not be reconciled safely")
                    && matches!(observe_label(paths).await, LabelObservation::Loaded { .. });
                if generic_loaded_candidate {
                    ensure!(
                        restarted_service_identity_matches(paths, target).await,
                        "candidate recovery process identity is unconfirmed"
                    );
                }
                let health = if stop.direction == StopDirection::RestorePrevious {
                    healthy_restored_previous(paths, version, operation.auth_baseline.as_ref())
                        .await
                } else {
                    healthy_candidate(paths, version, operation.auth_baseline.as_ref()).await
                };
                if health.is_ok() {
                    if !restarted_service_identity_matches(paths, target).await {
                        ensure!(
                            observe_label(paths).await == LabelObservation::Absent,
                            "restarted service identity is unconfirmed"
                        );
                    } else {
                        let phase = if stop.direction == StopDirection::ActivateCandidate {
                            "completed"
                        } else {
                            "rolled_back"
                        };
                        set_checkpoint(
                            paths,
                            operation,
                            phase,
                            "stopped_service_healthy_after_reconciliation",
                        )?;
                        return Ok(json!({"resumed":true,"operation":operation}));
                    }
                } else if generic_loaded_candidate
                    && operation.kind == OperationKind::Update
                    && operation.previous_target.is_some()
                {
                    // Missing captured auth cannot be reconstructed from the
                    // failed read, the generic checkpoint or the old receipt.
                    ensure!(
                        operation.auth_baseline.is_some(),
                        "lifecycle auth baseline is unavailable"
                    );
                    set_checkpoint(
                        paths,
                        operation,
                        "recovery_required",
                        "stopped_service_health_failed",
                    )?;
                    return restore_failed_candidate(paths, operation).await;
                }
            }
        }
    }
    match observe_service_stop(paths, operation, false).await? {
        Some(singleton) => complete_stopped_transition(paths, operation, singleton).await,
        None => Ok(service_stop_pending(operation)),
    }
}

// Both a newly retained failure and a freshly re-observed historical failure
// use the original restoration owner. This never admits ordinary downgrade or
// substitutes counters for exact stopped-process/singleton proof.
async fn restore_failed_candidate(paths: &Paths, operation: &mut Operation) -> Result<Value> {
    ensure!(
        operation.auth_baseline.is_some(),
        "lifecycle auth baseline is unavailable"
    );
    match restore_activation(paths, operation).await {
        Ok(()) => Ok(json!({"resumed":true,"operation":operation})),
        Err(_) if operation.phase == "service_stop_pending" => Ok(service_stop_pending(operation)),
        Err(error) => Err(error),
    }
}

async fn restore_activation(paths: &Paths, operation: &mut Operation) -> Result<()> {
    // The candidate must be visibly idle before a prior daemon can be restored.
    // If it never reached launchd (for example bootstrap failed), launchd must
    // still prove the label absent.  We never infer that from an operation
    // phase alone.
    match daemon_status(paths).await {
        Ok(status) => {
            let target = current_target(paths)?.context("rollback current target missing")?;
            let plist =
                regular_digest(&launch_agent(paths))?.context("rollback configuration missing")?;
            let version = verify_recovery_service(paths, operation, &target, &plist)?;
            ensure!(
                status["version"] == version && status["activeJobs"].as_u64().is_some(),
                "rollback daemon identity is unconfirmed"
            );
            if lifecycle_test_mode() {
                drain_and_require_idle(paths, true).await?;
                validate_rollback_status(&json!({"result":daemon_status(paths).await?}))?;
            } else {
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
        }
        Err(_) if launchctl_label_absent().await? => {}
        Err(error) => return Err(error.context("candidate state cannot be proven safe")),
    }
    let Some(singleton) =
        stop_for_direction(paths, operation, StopDirection::RestorePrevious).await?
    else {
        bail!("SERVICE_STOP_PENDING");
    };
    complete_stopped_transition(paths, operation, singleton).await?;
    Ok(())
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
    if !operation.service_stops.is_empty() {
        return reconcile_service_stop(paths, operation).await;
    }
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
        ensure!(
            status["version"] == package.version,
            "candidate daemon version differs from this operation"
        );
        if status["draining"] == true {
            release_service_drain(
                paths,
                operation,
                &package.target,
                &resources.staged_launch_agent_sha256,
                "candidate_drain_release_pending",
            )
            .await?;
        }
    }
    if pointer.as_ref() == Some(&package.target)
        && candidate_plist_matches
        && healthy_candidate(paths, &package.version, operation.auth_baseline.as_ref())
            .await
            .is_ok()
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

    // An earlier bootout may finish after its bounded absence probe. Reconcile
    // the exact previous service before attempting a wider restore transaction.
    let previous_plist_matches = match &resources.launch_agent_backup_sha256 {
        Some(expected) => plist_digest.as_deref() == Some(expected),
        None => plist_digest.is_none(),
    };
    if pointer == operation.previous_target && previous_plist_matches {
        if let Some(previous) = &operation.previous_target.clone() {
            recover_previous_service(paths, operation, previous, &resources).await?;
        }
        #[cfg(test)]
        recovery_fault("before_completion")?;
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
    match restore_activation(paths, operation).await {
        Ok(()) => Ok(json!({"resumed":true,"state":"previous_restored","operation":operation})),
        Err(_) if operation.phase == "service_stop_pending" => Ok(service_stop_pending(operation)),
        Err(error) => Err(error),
    }
}

// The captured operation inventory binds the service being reconciled; the
// live immutable inventory additionally proves its bytes have not changed.
fn verify_recovery_service(
    paths: &Paths,
    operation: &Operation,
    target: &Path,
    plist_digest: &str,
) -> Result<String> {
    let resources = operation
        .resources
        .as_ref()
        .context("activation resources missing")?;
    ensure!(
        resources.owned_versions.iter().any(|owned| owned == target),
        "recovery target is not captured by this operation"
    );
    ensure!(
        resources.launch_agent == launch_agent(paths),
        "recovery LaunchAgent is outside this lifecycle namespace"
    );
    ensure!(
        owned_versions(paths)?.iter().any(|owned| owned == target),
        "recovery target is no longer owned"
    );
    ensure!(
        current_target(paths)?.as_deref() == Some(target),
        "recovery target pointer differs from this operation"
    );
    ensure!(
        regular_digest(&resources.launch_agent)?.as_deref() == Some(plist_digest),
        "recovery LaunchAgent differs from this operation"
    );
    let metadata = fs::symlink_metadata(target)?;
    ensure!(
        metadata.is_dir() && !metadata.file_type().is_symlink(),
        "recovery target is not a regular owned directory"
    );
    verify_owned_version(paths, target)?;
    let version = target
        .file_name()
        .and_then(|value| value.to_str())
        .context("recovery version is invalid")?;
    let project: Value = state::read_json(&target.join("metadata/project.json"))?;
    ensure!(
        project["project"] == "loomex-runner"
            && project["version"] == version
            && project["platform"] == "darwin-arm64",
        "recovery version metadata differs from its target"
    );
    Ok(version.into())
}

async fn release_service_drain(
    paths: &Paths,
    operation: &mut Operation,
    target: &Path,
    plist_digest: &str,
    checkpoint: &str,
) -> Result<()> {
    let version = verify_recovery_service(paths, operation, target, plist_digest)?;
    let status = daemon_status(paths).await?;
    ensure!(
        candidate_drain_can_be_released(&status, &version),
        "recovery requires the exact drained idle service"
    );
    let drain = paths.state_dir.join("drain.json");
    // Only this operation's durable removal intent explains a missing file.
    // Fresh daemon identity and drained/zero status are still required above.
    ensure!(
        regular_digest(&drain)?.is_some() || operation.checkpoint.as_deref() == Some(checkpoint),
        "recovery drain is absent without a journaled removal intent"
    );
    set_checkpoint(paths, operation, "recovery_required", checkpoint)?;
    #[cfg(test)]
    recovery_fault("before_drain_removal")?;
    remove_regular_and_sync(&drain)?;
    #[cfg(test)]
    recovery_fault("after_drain_removal")?;
    let agent = operation
        .resources
        .as_ref()
        .context("activation resources missing")?
        .launch_agent
        .clone();
    // Removing the file does not release the running daemon's in-memory drain.
    // The existing restart is allowed only by the exact managed-zero proof.
    launchctl("kickstart", &agent).await?;
    #[cfg(test)]
    recovery_fault("after_restart")?;
    if operation.previous_target.as_deref() == Some(target) {
        healthy_restored_previous(paths, &version, operation.auth_baseline.as_ref()).await
    } else {
        healthy_candidate(paths, &version, operation.auth_baseline.as_ref()).await
    }
}

async fn recover_previous_service(
    paths: &Paths,
    operation: &mut Operation,
    previous: &Path,
    resources: &OperationResources,
) -> Result<()> {
    let expected = resources
        .launch_agent_backup_sha256
        .as_deref()
        .context("previous LaunchAgent has no captured digest")?;
    let version = verify_recovery_service(paths, operation, previous, expected)?;
    match daemon_status(paths).await {
        Ok(status) => {
            ensure!(
                status["version"] == version,
                "previous daemon version differs from this operation"
            );
            if status["draining"] == true {
                release_service_drain(
                    paths,
                    operation,
                    previous,
                    expected,
                    "previous_drain_release_pending",
                )
                .await?;
            } else {
                ensure!(
                    status["draining"] == false,
                    "previous daemon drain state is unavailable"
                );
            }
            healthy_restored_previous(paths, &version, operation.auth_baseline.as_ref()).await
        }
        Err(error) => {
            // Unavailable status never licenses replacement of a loaded daemon.
            if !launchctl_label_absent().await? {
                return Err(error.context(
                    "previous runner health is unconfirmed and launchd label remains loaded",
                ));
            }
            launchctl("bootstrap", &resources.launch_agent).await?;
            if candidate_health_check_required() {
                let status = daemon_status(paths).await?;
                ensure!(
                    status["version"] == version,
                    "previous daemon version differs from this operation"
                );
                if status["draining"] == true {
                    release_service_drain(
                        paths,
                        operation,
                        previous,
                        expected,
                        "previous_drain_release_pending",
                    )
                    .await?;
                }
                healthy_restored_previous(paths, &version, operation.auth_baseline.as_ref())
                    .await?;
            }
            Ok(())
        }
    }
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
    let Some(singleton) =
        stop_for_direction(paths, operation, StopDirection::ActivateCandidate).await?
    else {
        return Ok(service_stop_pending(operation));
    };
    let _ = (package, resources);
    let mut value = complete_stopped_transition(paths, operation, singleton).await?;
    value["state"] = json!("candidate_healthy_after_pending");
    Ok(value)
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
                json!({"activated":false,"pending":true,"reason":value["reason"],"resumed":true,"transaction":value}),
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
    // The journal owns this non-secret pre-switch scope through crash recovery.
    operation.auth_baseline =
        Some(capture_auth_baseline(paths, operation.previous_target.as_deref()).await?);
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
    let result: Result<Value> = async {
        drain_and_require_idle(paths, operation.previous_target.is_some()).await?;
        set_checkpoint(paths, &mut operation, "draining", "daemon_drained")?;
        let Some(singleton) =
            stop_for_direction(paths, &mut operation, StopDirection::ActivateCandidate).await?
        else {
            return Ok(service_stop_pending(&operation));
        };
        complete_stopped_transition(paths, &mut operation, singleton).await
    }
    .await;
    match result {
        Ok(value) => Ok(value),
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
            if matches!(
                operation.checkpoint.as_deref(),
                Some("stopped_service_start_failed" | "stopped_service_health_failed")
            ) && operation.service_stops.last().is_some_and(|stop| {
                stop.direction == StopDirection::ActivateCandidate
                    && stop.request == StopRequest::ObservedStopped
            }) {
                match restore_activation(paths, &mut operation).await {
                    Ok(()) => {
                        return Err(error.context("activation failed; previous service restored"));
                    }
                    Err(_) if operation.phase == "service_stop_pending" => {
                        return Ok(service_stop_pending(&operation));
                    }
                    Err(restore_error) => {
                        set_checkpoint(
                            paths,
                            &mut operation,
                            "recovery_required",
                            "previous_service_restore_unconfirmed",
                        )?;
                        return Err(restore_error
                            .context("activation failed; previous service is unconfirmed"));
                    }
                }
            }
            if !operation.service_stops.is_empty() {
                // Preserve both uncertain requests and stopped transition
                // interruptions. No speculative previous-service restart.
                set_checkpoint(
                    paths,
                    &mut operation,
                    "recovery_required",
                    "service_stop_reconciliation_required",
                )?;
                return Err(error.context("service-stop state retained for exact lifecycle resume"));
            }
            match restore_activation(paths, &mut operation).await {
                Ok(()) => Err(error.context("activation failed; previous service restored")),
                Err(_) if operation.phase == "service_stop_pending" => {
                    Ok(service_stop_pending(&operation))
                }
                Err(_) => {
                    set_checkpoint(
                        paths,
                        &mut operation,
                        "recovery_required",
                        "candidate_or_previous_service_not_safe_to_restore",
                    )?;
                    Err(error.context("activation failed; service state requires lifecycle repair"))
                }
            }
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

/// Eligibility under this controller's compiled product contract. This is a
/// read-only preflight, not activation authorization or a live downgrade proof.
pub fn rollback_preflight(paths: &Paths) -> Result<Value> {
    let mut targets = Vec::new();
    if paths.state_dir.join("owned-versions.json").exists() {
        let owned: Value = state::read_json(&paths.state_dir.join("owned-versions.json"))?;
        for target in owned_versions(paths)? {
            let version = target
                .file_name()
                .and_then(|v| v.to_str())
                .context("unsafe owned version path")?;
            let reason = if verify_owned_version_from_inventory(&target, &owned).is_err() {
                Some("inventory_verification_failed")
            } else {
                match validate_rollback_target(&target, version) {
                    Ok(()) => None,
                    Err(error)
                        if error.to_string() == "LIFECYCLE_ROLLBACK_COMPATIBILITY_MISMATCH" =>
                    {
                        Some("compatibility_manifest_mismatch")
                    }
                    Err(_) => Some("target_validation_failed"),
                }
            };
            targets.push(json!({"version":version,"eligible":reason.is_none(),"reason":reason}));
        }
    }
    Ok(json!({"schema":"app.loomex.runner.rollback-preflight/v1",
        "controllerVersion":env!("CARGO_PKG_VERSION"),
        "controllerCompatibilitySha256":state::digest(include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/contracts/compatibility-manifest.json"))),
        "targets":targets}))
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
        if operation.kind == OperationKind::Prune {
            return reconcile_prune(paths, &mut operation).await;
        }
        if operation.abandonment.is_some() {
            return reconcile_abandonment(paths, &mut operation).await;
        }
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
                    // A removal may already have happened. Keep its exact
                    // durable intent so the same operation can finish restart;
                    // fresh identity/status are still revalidated on resume.
                    let checkpoint = match operation.checkpoint.as_deref() {
                        Some("candidate_drain_release_pending") => {
                            "candidate_drain_release_pending"
                        }
                        Some("previous_drain_release_pending") => "previous_drain_release_pending",
                        // The transition owner has already established these
                        // categorical failures. Do not erase them at the outer
                        // error boundary and strand an exact loaded candidate.
                        Some("stopped_service_start_failed") => "stopped_service_start_failed",
                        Some("stopped_service_health_failed") => "stopped_service_health_failed",
                        _ => "observed state could not be reconciled safely",
                    };
                    set_checkpoint(paths, &mut operation, "recovery_required", checkpoint)?;
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

fn prune_version_name(value: &str) -> bool {
    let parts: Vec<_> = value.split('.').collect();
    parts.len() == 3
        && parts
            .iter()
            .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
}

fn prune_inventory_without(owned: &Value, targets: &[PathBuf]) -> Result<Value> {
    ensure!(
        owned["schema"] == "app.loomex.runner.owned-versions/v1",
        "invalid owned versions inventory"
    );
    let paths = owned["paths"]
        .as_array()
        .context("invalid owned version paths")?;
    let inventories = owned["inventories"]
        .as_array()
        .context("invalid owned version inventories")?;
    let removed: std::collections::HashSet<_> = targets
        .iter()
        .map(|path| path.to_string_lossy().into_owned())
        .collect();
    let path_names: Vec<_> = paths
        .iter()
        .map(|entry| entry.as_str().context("invalid owned version path"))
        .collect::<Result<_>>()?;
    let inventory_names: Vec<_> = inventories
        .iter()
        .map(|entry| {
            entry["path"]
                .as_str()
                .context("invalid owned inventory path")
        })
        .collect::<Result<_>>()?;
    ensure!(
        path_names.len() == inventory_names.len()
            && path_names
                .iter()
                .collect::<std::collections::HashSet<_>>()
                .len()
                == path_names.len()
            && path_names.iter().collect::<std::collections::HashSet<_>>()
                == inventory_names
                    .iter()
                    .collect::<std::collections::HashSet<_>>()
            && removed
                .iter()
                .all(|target| path_names.contains(&target.as_str())),
        "owned version inventory is inconsistent"
    );
    let mut result = owned.clone();
    result["paths"] = Value::Array(
        paths
            .iter()
            .filter(|entry| !removed.contains(entry.as_str().unwrap()))
            .cloned()
            .collect(),
    );
    result["inventories"] = Value::Array(
        inventories
            .iter()
            .filter(|entry| !removed.contains(entry["path"].as_str().unwrap()))
            .cloned()
            .collect(),
    );
    ensure!(
        result["paths"]
            .as_array()
            .is_some_and(|entries| !entries.is_empty()),
        "prune would remove every owned version"
    );
    Ok(result)
}

fn prune_quarantine(paths: &Paths, operation: &Operation, target: &Path) -> Result<PathBuf> {
    let version = target
        .file_name()
        .and_then(|name| name.to_str())
        .context("invalid prune target")?;
    ensure!(
        prune_version_name(version) && target.parent() == Some(paths.versions().as_path()),
        "unsafe prune target"
    );
    Ok(paths
        .versions()
        .join(format!(".prune-{}", operation.id))
        .join(version))
}

fn prune_quarantine_inventory(
    root: &Path,
    expected: &[Value],
    allow_missing: bool,
) -> Result<(Vec<PathBuf>, Vec<PathBuf>)> {
    let meta = fs::symlink_metadata(root)?;
    ensure!(
        meta.is_dir() && !meta.file_type().is_symlink(),
        "unsafe prune quarantine"
    );
    let mut files = std::collections::BTreeMap::<PathBuf, &Value>::new();
    let mut dirs = std::collections::HashSet::<PathBuf>::new();
    for entry in expected {
        let relative = PathBuf::from(
            entry["path"]
                .as_str()
                .context("invalid prune file inventory")?,
        );
        ensure!(
            !relative.as_os_str().is_empty()
                && relative
                    .components()
                    .all(|part| matches!(part, Component::Normal(_)))
                && files.insert(relative.clone(), entry).is_none(),
            "invalid prune file inventory"
        );
        let mut parent = relative.parent();
        while let Some(dir) = parent {
            if dir.as_os_str().is_empty() {
                break;
            }
            dirs.insert(dir.to_path_buf());
            parent = dir.parent();
        }
    }
    let mut present_files = Vec::new();
    fn walk(
        root: &Path,
        directory: &Path,
        expected_files: &std::collections::BTreeMap<PathBuf, &Value>,
        expected_dirs: &std::collections::HashSet<PathBuf>,
        present_files: &mut Vec<PathBuf>,
    ) -> Result<()> {
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            let path = entry.path();
            let relative = path.strip_prefix(root)?.to_path_buf();
            let meta = fs::symlink_metadata(&path)?;
            ensure!(!meta.file_type().is_symlink(), "unsafe prune quarantine");
            if meta.is_dir() {
                ensure!(
                    expected_dirs.contains(&relative),
                    "PRUNE_QUARANTINE_UNOWNED_ENTRY"
                );
                walk(root, &path, expected_files, expected_dirs, present_files)?;
            } else if meta.is_file() {
                let expected = expected_files
                    .get(&relative)
                    .context("PRUNE_QUARANTINE_UNOWNED_ENTRY")?;
                let (digest, verified) = streaming_file_digest(&path)?;
                ensure!(
                    same_file_identity(&meta, &verified),
                    "PRUNE_QUARANTINE_CONTENT_MISMATCH"
                );
                ensure!(
                    expected["size"].as_u64() == Some(meta.len())
                        && expected["mode"].as_u64()
                            == Some(u64::from(meta.permissions().mode() & 0o777))
                        && expected["sha256"] == digest,
                    "PRUNE_QUARANTINE_CONTENT_MISMATCH"
                );
                present_files.push(relative);
            } else {
                bail!("PRUNE_QUARANTINE_UNOWNED_ENTRY");
            }
        }
        Ok(())
    }
    walk(root, root, &files, &dirs, &mut present_files)?;
    ensure!(
        allow_missing || present_files.len() == files.len(),
        "PRUNE_QUARANTINE_CONTENT_MISMATCH"
    );
    let mut sorted_dirs: Vec<_> = dirs.into_iter().collect();
    sorted_dirs.sort_by(|a, b| {
        b.components()
            .count()
            .cmp(&a.components().count())
            .then_with(|| b.cmp(a))
    });
    Ok((present_files, sorted_dirs))
}

fn prune_remove_quarantine_exact(root: &Path, expected: &[Value]) -> Result<()> {
    let (files, dirs) = prune_quarantine_inventory(root, expected, true)?;
    for relative in files {
        fs::remove_file(root.join(relative))?;
        prune_fault("during_delete")?;
    }
    for relative in dirs {
        let path = root.join(relative);
        if path.exists() {
            fs::remove_dir(path)?;
        }
    }
    fs::remove_dir(root)?;
    Ok(())
}

fn sync_directory(path: &Path) -> Result<()> {
    File::open(path)?.sync_all()?;
    Ok(())
}

async fn prune_in_use(targets: &[PathBuf]) -> Result<()> {
    #[cfg(test)]
    if lifecycle_test_mode() {
        let references = TEST_PRUNE_IN_USE.lock().unwrap();
        ensure!(
            !targets.iter().any(|target| references
                .iter()
                .any(|path| path == target || path.starts_with(target))),
            "PRUNE_VERSION_IN_USE"
        );
        return Ok(());
    }
    let mut command = tokio::process::Command::new("/usr/sbin/lsof");
    command.args(["-n", "-F", "n"]);
    inspect_prune_processes(
        &mut command,
        targets,
        Duration::from_secs(20),
        16 * 1024 * 1024,
    )
    .await
}

// Both pipes are consumed concurrently, with one absolute deadline covering
// reads, EOF and child exit. A byte/line limit or stderr never proves absence.
async fn inspect_prune_processes(
    command: &mut tokio::process::Command,
    targets: &[PathBuf],
    deadline: Duration,
    byte_limit: usize,
) -> Result<()> {
    use tokio::io::AsyncReadExt;
    command
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true);
    let mut child = command
        .spawn()
        .context("PRUNE_PROCESS_OBSERVATION_UNAVAILABLE")?;
    let mut stdout = child
        .stdout
        .take()
        .context("PRUNE_PROCESS_OBSERVATION_UNAVAILABLE")?;
    let mut stderr = child
        .stderr
        .take()
        .context("PRUNE_PROCESS_OBSERVATION_UNAVAILABLE")?;
    let inspection = async {
        let mut out_buffer = [0u8; 8192];
        let mut err_buffer = [0u8; 8192];
        let mut pending = Vec::new();
        let mut stdout_bytes = 0usize;
        let mut stdout_done = false;
        let mut stderr_done = false;
        while !stdout_done || !stderr_done {
            tokio::select! {
                count = stdout.read(&mut out_buffer), if !stdout_done => {
                    let count = count.context("PRUNE_PROCESS_OBSERVATION_UNAVAILABLE")?;
                    if count == 0 { stdout_done = true; continue; }
                    stdout_bytes = stdout_bytes.checked_add(count).context("PRUNE_PROCESS_OBSERVATION_UNAVAILABLE")?;
                    ensure!(stdout_bytes <= byte_limit, "PRUNE_PROCESS_OBSERVATION_UNAVAILABLE");
                    for byte in &out_buffer[..count] {
                        if *byte == b'\n' {
                            check_prune_process_line(&pending, targets)?;
                            pending.clear();
                        } else {
                            ensure!(pending.len() < 64 * 1024, "PRUNE_PROCESS_OBSERVATION_UNAVAILABLE");
                            pending.push(*byte);
                        }
                    }
                },
                count = stderr.read(&mut err_buffer), if !stderr_done => {
                    let count = count.context("PRUNE_PROCESS_OBSERVATION_UNAVAILABLE")?;
                    ensure!(count == 0, "PRUNE_PROCESS_OBSERVATION_UNAVAILABLE");
                    stderr_done = true;
                },
            }
        }
        check_prune_process_line(&pending, targets)?;
        let status = child
            .wait()
            .await
            .context("PRUNE_PROCESS_OBSERVATION_UNAVAILABLE")?;
        ensure!(
            status.success() || (status.code() == Some(1) && stdout_bytes == 0),
            "PRUNE_PROCESS_OBSERVATION_UNAVAILABLE"
        );
        Ok(())
    };
    let result = tokio::time::timeout(deadline, inspection).await;
    if !matches!(result, Ok(Ok(()))) {
        // Do not await an unbounded process teardown after the observation
        // deadline; kill_on_drop remains a second safety net.
        let _ = child.start_kill();
    }
    result.context("PRUNE_PROCESS_OBSERVATION_UNAVAILABLE")?
}

fn check_prune_process_line(line: &[u8], targets: &[PathBuf]) -> Result<()> {
    if let Some(name) = line.strip_prefix(b"n") {
        let path = Path::new(std::ffi::OsStr::from_bytes(name));
        ensure!(
            !targets
                .iter()
                .any(|target| path == target || path.starts_with(target)),
            "PRUNE_VERSION_IN_USE"
        );
    }
    Ok(())
}

fn prune_fault(stage: &str) -> Result<()> {
    #[cfg(test)]
    if TEST_PRUNE_FAULT
        .lock()
        .unwrap()
        .as_ref()
        .is_some_and(|fault| *fault == stage)
    {
        bail!("injected prune interruption: {stage}");
    }
    let _ = stage;
    Ok(())
}

fn prune_drain_marker(paths: &Paths, plan: &PruneIntent) -> Result<bool> {
    let drain = paths.state_dir.join("drain.json");
    let Some(marker) = read_optional::<Value>(&drain)? else {
        return Ok(false);
    };
    ensure!(
        marker["idempotencyKey"] == plan.drain_key.to_string(),
        "PRUNE_DRAIN_IDENTITY_MISMATCH"
    );
    Ok(true)
}

async fn prune_acquire_drain(paths: &Paths, plan: &PruneIntent) -> Result<()> {
    let marker_exists = prune_drain_marker(paths, plan)?;
    #[cfg(test)]
    if !marker_exists && lifecycle_test_mode() {
        state::write_json(
            &paths.state_dir.join("drain.json"),
            &json!({"requestedAt":state::now(),"idempotencyKey":plan.drain_key}),
        )?;
        if let Some(status) = TEST_RECOVERY_STATUS.lock().unwrap().as_mut() {
            status["draining"] = json!(true);
        }
    }
    if !marker_exists && !lifecycle_test_mode() {
        let response = crate::control::lifecycle_client(
            &paths.state_dir,
            "daemon.drain",
            json!({"idempotencyKey":plan.drain_key}),
        )
        .await?;
        ensure!(
            response["result"]["draining"] == true,
            "PRUNE_DRAIN_REJECTED"
        );
    }
    ensure!(
        prune_drain_marker(paths, plan)?,
        "PRUNE_DRAIN_IDENTITY_MISMATCH"
    );
    let status = daemon_status(paths).await?;
    ensure!(
        status["version"]
            == plan
                .current_target
                .file_name()
                .unwrap()
                .to_string_lossy()
                .as_ref()
            && status["draining"] == true
            && status["activeJobs"] == 0,
        "PRUNE_REQUIRES_DRAINED_IDLE_DAEMON"
    );
    Ok(())
}

async fn prune_release_drain(paths: &Paths, plan: &PruneIntent) -> Result<()> {
    ensure!(
        regular_digest(&launch_agent(paths))?.as_deref() == Some(&plan.launch_agent_digest),
        "PRUNE_SERVICE_IDENTITY_MISMATCH"
    );
    let version = plan.current_target.file_name().unwrap().to_string_lossy();
    let status = daemon_status(paths).await?;
    ensure!(
        status["version"] == version.as_ref() && status["activeJobs"] == 0,
        "PRUNE_SERVICE_IDENTITY_MISMATCH"
    );
    if status["draining"] == true {
        if prune_drain_marker(paths, plan)? {
            remove_regular_and_sync(&paths.state_dir.join("drain.json"))?;
        }
        prune_fault("after_drain_removal")?;
        launchctl("kickstart", &launch_agent(paths)).await?;
        prune_fault("after_restart")?;
    } else {
        ensure!(
            status["draining"] == false && !prune_drain_marker(paths, plan)?,
            "PRUNE_SERVICE_IDENTITY_MISMATCH"
        );
    }
    healthy_candidate(paths, &version, Some(&plan.auth_baseline)).await?;
    Ok(())
}

pub async fn prune(paths: &Paths, remove: &[String], retain: &[String]) -> Result<Value> {
    ensure!(
        !remove.is_empty() && !retain.is_empty() && remove.len() <= 256 && retain.len() <= 256,
        "INVALID_REQUEST"
    );
    ensure!(
        remove
            .iter()
            .chain(retain)
            .all(|name| prune_version_name(name)),
        "INVALID_REQUEST"
    );
    ensure!(
        remove
            .iter()
            .collect::<std::collections::HashSet<_>>()
            .len()
            == remove.len()
            && retain
                .iter()
                .collect::<std::collections::HashSet<_>>()
                .len()
                == retain.len(),
        "INVALID_REQUEST"
    );
    let _lock = LifecycleLock::acquire(paths)?;
    if let Some(mut existing) = read_optional::<Operation>(&paths.operation())? {
        existing.validate()?;
        ensure!(terminal(&existing.phase), "LIFECYCLE_OPERATION_PENDING");
        if existing.kind == OperationKind::Prune {
            reconcile_prune(paths, &mut existing).await?;
        }
    }
    ensure!(
        !paths.state_dir.join("bootstrap-install.json").exists()
            && !paths.state_dir.join("bootstrap-uninstall.json").exists()
            && !paths.state_dir.join("install-operation.json").exists()
            && !paths.state_dir.join("uninstall-operation.json").exists(),
        "LIFECYCLE_OPERATION_PENDING"
    );
    if let Some(repair) = read_optional::<Value>(&paths.state_dir.join("receipt-repair.json"))? {
        ensure!(
            repair["schema"] == "loomex.receipt-repair/v1" && repair["phase"] == "completed",
            "LIFECYCLE_OPERATION_PENDING"
        );
    }
    let current = current_target(paths)?.context("runner current target is absent")?;
    let owned_paths = owned_versions(paths)?;
    let named = |name: &str| -> Result<PathBuf> {
        let target = paths.versions().join(name);
        ensure!(owned_paths.contains(&target), "VERSION_NOT_OWNED");
        validate_version_path(&paths.versions(), &target.to_string_lossy())
    };
    let targets = remove
        .iter()
        .map(|name| named(name))
        .collect::<Result<Vec<_>>>()?;
    let retained = retain
        .iter()
        .map(|name| named(name))
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        !targets.contains(&current)
            && !retained.contains(&current)
            && targets.iter().all(|target| !retained.contains(target)),
        "PRUNE_PROTECTED_VERSION"
    );
    for target in targets.iter().chain(&retained) {
        verify_owned_version(paths, target)?;
    }
    for target in &retained {
        validate_rollback_target(target, target.file_name().unwrap().to_str().unwrap())?;
    }
    verify_owned_version(paths, &current)?;
    let status = daemon_status(paths).await?;
    ensure!(
        status["version"] == current.file_name().unwrap().to_string_lossy().as_ref()
            && status["activeJobs"] == 0
            && status["draining"] == false,
        "PRUNE_REQUIRES_IDLE_DAEMON"
    );
    ensure!(
        regular_digest(&paths.state_dir.join("drain.json"))?.is_none(),
        "PRUNE_DRAIN_ALREADY_ACTIVE"
    );
    let auth_baseline = capture_auth_baseline(paths, Some(&current)).await?;
    checked_regular(&launch_agent(paths))?;
    let launch_agent_digest = state::digest(&fs::read(launch_agent(paths))?);
    prune_in_use(&targets).await?;
    let receipt_path = paths.state_dir.join("install-receipt.json");
    let receipt: Value = state::read_json(&receipt_path)?;
    ensure!(
        receipt["versionPath"] == current.to_string_lossy().as_ref()
            && receipt["version"] == current.file_name().unwrap().to_string_lossy().as_ref(),
        "PRUNE_RECEIPT_IDENTITY_MISMATCH"
    );
    let original: Value = state::read_json(&paths.state_dir.join("owned-versions.json"))?;
    let result = prune_inventory_without(&original, &targets)?;
    // The previous terminal journal may own two small LaunchAgent recovery
    // copies. Release only those exact files before superseding it.
    release_terminal_operation_resources_before_supersede(paths)?;
    let mut operation = Operation::new(OperationKind::Prune, "prepared", None);
    operation.schema = PRUNE_OPERATION_SCHEMA.into();
    operation.prune = Some(PruneIntent {
        targets,
        retain: retained,
        moved: Vec::new(),
        deleting_started: Vec::new(),
        current_target: current,
        original_inventory_digest: state::json_digest(&original),
        result_inventory_digest: state::json_digest(&result),
        receipt_digest: state::digest(&fs::read(receipt_path)?),
        drain_key: Uuid::new_v4(),
        launch_agent_digest,
        auth_baseline,
    });
    save_operation(paths, &operation)?;
    prune_fault("after_plan")?;
    reconcile_prune(paths, &mut operation).await
}

async fn reconcile_prune(paths: &Paths, operation: &mut Operation) -> Result<Value> {
    operation.validate()?;
    let plan = operation.prune.clone().context("prune plan missing")?;
    let current = current_target(paths)?.context("runner current target is absent")?;
    ensure!(
        current == plan.current_target
            && !plan.targets.contains(&current)
            && plan.retain.iter().all(|path| !plan.targets.contains(path)),
        "PRUNE_PROTECTED_VERSION"
    );
    let versions = paths.versions();
    for target in plan
        .targets
        .iter()
        .chain(&plan.retain)
        .chain(std::iter::once(&current))
    {
        let version = target
            .file_name()
            .and_then(|name| name.to_str())
            .context("invalid prune version")?;
        ensure!(
            prune_version_name(version) && target.parent() == Some(versions.as_path()),
            "unsafe prune version path"
        );
    }
    let receipt_path = paths.state_dir.join("install-receipt.json");
    ensure!(
        state::digest(&fs::read(&receipt_path)?) == plan.receipt_digest,
        "PRUNE_RECEIPT_IDENTITY_MISMATCH"
    );
    ensure!(
        regular_digest(&launch_agent(paths))?.as_deref() == Some(&plan.launch_agent_digest),
        "PRUNE_SERVICE_IDENTITY_MISMATCH"
    );
    if operation.phase == "prepared" {
        prune_acquire_drain(paths, &plan).await?;
        prune_fault("after_drain_before_checkpoint")?;
        operation.phase = "draining".into();
        save_operation(paths, operation)?;
        prune_fault("after_drain_checkpoint")?;
    }
    if !matches!(
        operation.phase.as_str(),
        "drain_release_pending" | "completed"
    ) {
        ensure!(
            prune_drain_marker(paths, &plan)?,
            "PRUNE_DRAIN_IDENTITY_MISMATCH"
        );
        let status = daemon_status(paths).await?;
        ensure!(
            status["version"] == current.file_name().unwrap().to_string_lossy().as_ref()
                && status["activeJobs"] == 0
                && status["draining"] == true,
            "PRUNE_REQUIRES_DRAINED_IDLE_DAEMON"
        );
    }
    prune_in_use(&plan.targets).await?;
    let inventory_path = paths.state_dir.join("owned-versions.json");
    let original: Value = state::read_json(&inventory_path)?;
    let inventory_digest = state::json_digest(&original);
    ensure!(
        inventory_digest == plan.original_inventory_digest
            || inventory_digest == plan.result_inventory_digest,
        "PRUNE_INVENTORY_IDENTITY_MISMATCH"
    );
    let metadata_done = inventory_digest == plan.result_inventory_digest;
    if !metadata_done {
        let result = prune_inventory_without(&original, &plan.targets)?;
        ensure!(
            state::json_digest(&result) == plan.result_inventory_digest,
            "PRUNE_INVENTORY_IDENTITY_MISMATCH"
        );
        for path in plan.retain.iter().chain(std::iter::once(&current)) {
            verify_owned_version_from_inventory(path, &original)?;
        }
        let quarantine_root = versions.join(format!(".prune-{}", operation.id));
        match fs::symlink_metadata(&quarantine_root) {
            Ok(meta) => ensure!(
                meta.is_dir() && !meta.file_type().is_symlink(),
                "unsafe prune quarantine"
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir(&quarantine_root)?;
                sync_directory(&versions)?;
            }
            Err(error) => return Err(error.into()),
        }
        for target in &plan.targets {
            let quarantine = prune_quarantine(paths, operation, target)?;
            let expected = original["inventories"]
                .as_array()
                .unwrap()
                .iter()
                .find(|entry| entry["path"] == target.to_string_lossy().as_ref())
                .and_then(|entry| entry["files"].as_array())
                .context("prune inventory entry missing")?;
            let latest_status = daemon_status(paths).await?;
            ensure!(
                latest_status["version"] == current.file_name().unwrap().to_string_lossy().as_ref()
                    && latest_status["activeJobs"] == 0
                    && latest_status["draining"] == true
                    && prune_drain_marker(paths, &plan)?,
                "PRUNE_REQUIRES_DRAINED_IDLE_DAEMON"
            );
            prune_in_use(&[target.clone(), quarantine.clone()]).await?;
            let source = fs::symlink_metadata(target);
            let quarantined = fs::symlink_metadata(&quarantine);
            let moved = operation.prune.as_ref().unwrap().moved.contains(target);
            match (source, quarantined, moved) {
                (Ok(source), Err(error), false) if error.kind() == std::io::ErrorKind::NotFound => {
                    ensure!(
                        source.is_dir() && !source.file_type().is_symlink(),
                        "unsafe prune target"
                    );
                    verify_owned_version_from_inventory(target, &original)?;
                    prune_in_use(std::slice::from_ref(target)).await?;
                    fs::rename(target, &quarantine)?;
                    sync_directory(&versions)?;
                    sync_directory(&quarantine_root)?;
                    prune_fault("after_move")?;
                    operation.prune.as_mut().unwrap().moved.push(target.clone());
                    operation.phase = "deleting".into();
                    save_operation(paths, operation)?;
                }
                (Err(error), Ok(meta), false) if error.kind() == std::io::ErrorKind::NotFound => {
                    ensure!(
                        meta.is_dir() && !meta.file_type().is_symlink(),
                        "unsafe prune quarantine"
                    );
                    verify_directory_against_files(&quarantine, expected)?;
                    operation.prune.as_mut().unwrap().moved.push(target.clone());
                    operation.phase = "deleting".into();
                    save_operation(paths, operation)?;
                }
                (Err(error), Ok(meta), true)
                    if error.kind() == std::io::ErrorKind::NotFound
                        && meta.is_dir()
                        && !meta.file_type().is_symlink() => {}
                (Err(source_error), Err(quarantine_error), true)
                    if source_error.kind() == std::io::ErrorKind::NotFound
                        && quarantine_error.kind() == std::io::ErrorKind::NotFound
                        && operation
                            .prune
                            .as_ref()
                            .unwrap()
                            .deleting_started
                            .contains(target) =>
                {
                    continue;
                }
                _ => bail!("PRUNE_TARGET_STATE_AMBIGUOUS"),
            }
            let deleting_started = operation
                .prune
                .as_ref()
                .unwrap()
                .deleting_started
                .contains(target);
            prune_quarantine_inventory(&quarantine, expected, deleting_started)?;
            if !deleting_started {
                operation
                    .prune
                    .as_mut()
                    .unwrap()
                    .deleting_started
                    .push(target.clone());
                save_operation(paths, operation)?;
            }
            prune_remove_quarantine_exact(&quarantine, expected)?;
            sync_directory(&quarantine_root)?;
            prune_fault("after_delete")?;
        }
        operation.phase = "metadata".into();
        save_operation(paths, operation)?;
        prune_fault("before_metadata")?;
        state::write_json(&inventory_path, &result)?;
        prune_fault("after_metadata")?;
    }
    let final_inventory: Value = state::read_json(&inventory_path)?;
    ensure!(
        state::json_digest(&final_inventory) == plan.result_inventory_digest,
        "PRUNE_INVENTORY_IDENTITY_MISMATCH"
    );
    for target in &plan.targets {
        match fs::symlink_metadata(target) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            _ => bail!("PRUNE_TARGET_STATE_AMBIGUOUS"),
        }
    }
    for target in plan.retain.iter().chain(std::iter::once(&current)) {
        verify_owned_version_from_inventory(target, &final_inventory)?;
    }
    let quarantine_root = versions.join(format!(".prune-{}", operation.id));
    match fs::symlink_metadata(&quarantine_root) {
        Ok(meta) => {
            ensure!(
                meta.is_dir()
                    && !meta.file_type().is_symlink()
                    && fs::read_dir(&quarantine_root)?.next().is_none(),
                "PRUNE_TARGET_STATE_AMBIGUOUS"
            );
            fs::remove_dir(&quarantine_root)?;
            sync_directory(&versions)?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    if operation.phase != "completed" {
        operation.phase = "drain_release_pending".into();
        save_operation(paths, operation)?;
        prune_fault("before_drain_release")?;
        prune_release_drain(paths, &plan).await?;
        operation.phase = "completed".into();
        save_operation(paths, operation)?;
    }
    prune_fault("before_journal_clear")?;
    fs::remove_file(paths.operation())?;
    sync_directory(&paths.state_dir)?;
    Ok(
        json!({"schema":"app.loomex.runner.lifecycle-prune/v1", "completed":true,
        "removed":plan.targets.iter().map(|path| path.file_name().unwrap().to_string_lossy().into_owned()).collect::<Vec<_>>(),
        "retained":plan.retain.iter().map(|path| path.file_name().unwrap().to_string_lossy().into_owned()).collect::<Vec<_>>(),
        "current":current.file_name().unwrap().to_string_lossy()}),
    )
}

fn bootstrap_configuration_digest(configuration: &Value) -> Result<String> {
    ensure!(
        configuration["schema"] == "app.loomex.runner.bootstrap-install/v1",
        "unsupported bootstrap configuration"
    );
    Ok(state::digest(&serde_json::to_vec(configuration)?))
}

fn abandonment_bootstrap_configuration(paths: &Paths, operation: &Operation) -> Result<Value> {
    let intent = operation
        .abandonment
        .as_ref()
        .context("abandonment missing")?;
    let journal: Value = state::read_json(&paths.state_dir.join("bootstrap-install.json"))?;
    let configuration = if journal["schema"] == "app.loomex.runner.bootstrap-install/v2" {
        ensure!(
            journal["phase"] == "aborted"
                && journal["operationId"] == operation.id.to_string()
                && journal["configurationDigest"] == intent.bootstrap_configuration_digest,
            "LIFECYCLE_ABANDONMENT_CONFIGURATION_MISMATCH"
        );
        journal["configuration"].clone()
    } else {
        journal
    };
    ensure!(
        bootstrap_configuration_digest(&configuration)? == intent.bootstrap_configuration_digest
            && configuration["version"] == intent.package.version
            && configuration["target"] == intent.package.target.to_string_lossy().as_ref()
            && configuration["manifestSha256"] == intent.package.manifest_sha256,
        "LIFECYCLE_ABANDONMENT_CONFIGURATION_MISMATCH"
    );
    Ok(configuration)
}

async fn reconcile_abandonment(paths: &Paths, operation: &mut Operation) -> Result<Value> {
    operation.validate()?;
    let intent = operation
        .abandonment
        .clone()
        .context("abandonment missing")?;
    let configuration = abandonment_bootstrap_configuration(paths, operation)?;
    ensure!(
        current_target(paths)?.as_ref() == Some(&intent.previous_target)
            && regular_digest(&launch_agent(paths))?.as_ref() == Some(&intent.plist_digest)
            && regular_digest(&paths.state_dir.join("install-receipt.json"))?.as_ref()
                == Some(&intent.receipt_digest)
            && regular_digest(&paths.state_dir.join("owned-versions.json"))?.as_ref()
                == Some(&intent.inventory_digest),
        "LIFECYCLE_ABANDONMENT_IDENTITY_MISMATCH"
    );
    if operation.phase != "rolled_back" {
        if operation.service_stops.is_empty() {
            ensure!(
                operation.phase == "abandonment_pending"
                    && regular_digest(&paths.state_dir.join("drain.json"))?.as_ref()
                        == Some(&intent.drain_digest),
                "LIFECYCLE_ABANDONMENT_PHASE_MISMATCH"
            );
            let version = intent
                .previous_target
                .file_name()
                .and_then(|v| v.to_str())
                .context("previous version missing")?;
            ensure!(
                candidate_drain_can_be_released(&daemon_status(paths).await?, version),
                "abandonment requires fresh drained zero managed work"
            );
            ensure!(
                matches!(observe_label(paths).await, LabelObservation::Loaded {pid, program}
                if pid == intent.process.pid && (program == paths.current().join("bin/loomex-runner") || program == intent.process.executable))
                    && observe_recorded_process(&intent.process)
                        == ProcessObservation::Present(intent.process.clone()),
                "LIFECYCLE_ABANDONMENT_PROCESS_MISMATCH"
            );
            if let Some(singleton) =
                stop_for_direction(paths, operation, StopDirection::RestorePrevious).await?
            {
                complete_stopped_transition(paths, operation, singleton).await?;
            }
        } else {
            if operation
                .service_stops
                .last()
                .is_some_and(|stop| stop.request == StopRequest::Prepared)
            {
                request_service_stop(paths, operation).await?;
            }
            reconcile_service_stop(paths, operation).await?;
        }
    }
    if operation.phase != "rolled_back" {
        return Ok(service_stop_pending(operation));
    }
    // A crash after service restoration must never make the original bootstrap
    // configuration executable again. Verify health before recording its tombstone.
    let version = verify_recovery_service(
        paths,
        operation,
        &intent.previous_target,
        &intent.plist_digest,
    )?;
    healthy_restored_previous(paths, &version, operation.auth_baseline.as_ref()).await?;
    ensure!(
        restarted_service_identity_matches(paths, &intent.previous_target).await,
        "LIFECYCLE_ABANDONMENT_RESTORATION_MISMATCH"
    );
    #[cfg(test)]
    recovery_fault("before_abandonment_tombstone")?;
    // An explicit retry of the original config revokes an unconsumed successor
    // intent before rewriting the tombstone, never authorizing its activation.
    operation.abandonment.as_mut().unwrap().successor = None;
    save_operation(paths, operation)?;
    state::write_json(
        &paths.state_dir.join("bootstrap-install.json"),
        &json!({
            "schema":"app.loomex.runner.bootstrap-install/v2", "phase":"aborted",
            "operationId":operation.id, "configurationDigest":intent.bootstrap_configuration_digest,
            "configuration":configuration
        }),
    )?;
    Ok(
        json!({"schema":"app.loomex.runner.lifecycle-rollback/v1", "rolledBack":true,
        "abandoned":true, "resumed":true, "operation":operation}),
    )
}

/// Called under the same lifecycle lock, before bootstrap preflight/staging.
/// Same-configuration retries settle the abort; a different configuration needs
/// explicit acknowledgement of that exact terminal transaction before a new intent.
fn configuration_package(configuration: &Value) -> Result<PackageIdentity> {
    bootstrap_configuration_digest(configuration)?;
    let package = PackageIdentity {
        version: configuration["version"]
            .as_str()
            .context("invalid bootstrap version")?
            .into(),
        target: PathBuf::from(
            configuration["target"]
                .as_str()
                .context("invalid bootstrap target")?,
        ),
        manifest_sha256: configuration["manifestSha256"]
            .as_str()
            .context("invalid bootstrap manifest")?
            .into(),
    };
    ensure!(
        package.target.is_absolute() && valid_digest(&package.manifest_sha256),
        "invalid bootstrap package"
    );
    Ok(package)
}

pub async fn reconcile_bootstrap_abandonment_locked(
    paths: &Paths,
    configuration: &Value,
    settled_abandonment: Option<Uuid>,
) -> Result<Option<Value>> {
    let operation = read_optional::<Operation>(&paths.operation())?;
    if let Some(mut operation) = operation {
        operation.validate()?;
        if let Some(intent) = &operation.abandonment {
            let digest = bootstrap_configuration_digest(configuration)?;
            if digest == intent.bootstrap_configuration_digest {
                return reconcile_abandonment(paths, &mut operation).await.map(Some);
            }
            ensure!(
                settled_abandonment == Some(operation.id) && operation.phase == "rolled_back",
                "LIFECYCLE_ABANDONMENT_ACKNOWLEDGEMENT_REQUIRED"
            );
            let original = abandonment_bootstrap_configuration(paths, &operation)?;
            let journal: Value = state::read_json(&paths.state_dir.join("bootstrap-install.json"))?;
            ensure!(
                journal["schema"] == "app.loomex.runner.bootstrap-install/v2"
                    && journal["phase"] == "aborted",
                "LIFECYCLE_ABANDONMENT_SETTLEMENT_REQUIRED"
            );
            let previous = intent.previous_target.clone();
            let plist = intent.plist_digest.clone();
            let version = verify_recovery_service(paths, &operation, &previous, &plist)?;
            healthy_restored_previous(paths, &version, operation.auth_baseline.as_ref()).await?;
            ensure!(
                restarted_service_identity_matches(paths, &previous).await,
                "LIFECYCLE_ABANDONMENT_RESTORATION_MISMATCH"
            );
            let package = configuration_package(configuration)?;
            operation.abandonment.as_mut().unwrap().successor = Some(BootstrapSuccessor {
                package,
                configuration_digest: digest.clone(),
            });
            save_operation(paths, &operation)?;
            #[cfg(test)]
            recovery_fault("after_abandonment_successor_intent")?;
            state::write_json(
                &paths.state_dir.join("bootstrap-install.json"),
                &json!({
                    "schema":"app.loomex.runner.bootstrap-install/v2", "phase":"aborted",
                    "operationId":operation.id, "configurationDigest":bootstrap_configuration_digest(&original)?,
                    "configuration":original, "successorConfiguration":configuration,
                    "successorConfigurationDigest":digest
                }),
            )?;
            return Ok(None);
        }
        // After successor activation writes its fresh Update UUID, the same
        // existing retry envelope still binds only the corrected configuration.
        if let Some(journal) =
            read_optional::<Value>(&paths.state_dir.join("bootstrap-install.json"))?
        {
            if journal["schema"] == "app.loomex.runner.bootstrap-install/v2" {
                ensure!(
                    journal["phase"] == "aborted"
                        && journal["operationId"]
                            .as_str()
                            .and_then(|id| Uuid::parse_str(id).ok())
                            .is_some()
                        && journal["configurationDigest"]
                            == bootstrap_configuration_digest(&journal["configuration"])?
                        && journal["successorConfigurationDigest"]
                            == bootstrap_configuration_digest(configuration)?
                        && journal["successorConfiguration"] == *configuration
                        && operation.kind == OperationKind::Update
                        && operation.package.as_ref()
                            == Some(&configuration_package(configuration)?),
                    "LIFECYCLE_ABANDONMENT_SUCCESSOR_MISMATCH"
                );
                return Ok(None);
            }
        }
    }
    ensure!(
        settled_abandonment.is_none(),
        "LIFECYCLE_ABANDONMENT_IDENTITY_MISMATCH"
    );
    if let Some(journal) = read_optional::<Value>(&paths.state_dir.join("bootstrap-install.json"))?
    {
        ensure!(
            journal["schema"] == "app.loomex.runner.bootstrap-install/v1",
            "LIFECYCLE_ABANDONMENT_IDENTITY_MISMATCH"
        );
    }
    Ok(None)
}

pub async fn rollback_with_expected(
    paths: &Paths,
    version: &str,
    expected_operation: Option<Uuid>,
) -> Result<Value> {
    {
        let _lock = LifecycleLock::acquire(paths)?;
        if let Some(mut operation) = read_optional::<Operation>(&paths.operation())? {
            operation.validate()?;
            if operation.abandonment.is_some() || !terminal(&operation.phase) {
                ensure!(
                    expected_operation == Some(operation.id),
                    "LIFECYCLE_EXPECTED_OPERATION_REQUIRED_OR_MISMATCH"
                );
                let previous = operation
                    .previous_target
                    .clone()
                    .context("LIFECYCLE_ABANDONMENT_TARGET_MISSING")?;
                ensure!(
                    previous.file_name().is_some_and(|v| v == version),
                    "LIFECYCLE_ABANDONMENT_TARGET_MISMATCH"
                );
                validate_abandonment_current_previous(paths, &operation, &previous, version)?;
                if operation.abandonment.is_none() {
                    ensure!(
                        operation.kind == OperationKind::Update
                            && operation.phase == "pending_active_work"
                            && operation.checkpoint.as_deref() == Some("daemon_has_active_work")
                            && operation.service_stops.is_empty(),
                        "LIFECYCLE_ABANDONMENT_PHASE_MISMATCH"
                    );
                    let resources = operation
                        .resources
                        .as_ref()
                        .context("LIFECYCLE_ABANDONMENT_RESOURCE_MISSING")?;
                    let plist = resources
                        .launch_agent_backup_sha256
                        .clone()
                        .context("LIFECYCLE_ABANDONMENT_PREVIOUS_CONFIGURATION_MISSING")?;
                    verify_recovery_service(paths, &operation, &previous, &plist)
                        .context("LIFECYCLE_ABANDONMENT_PREVIOUS_IDENTITY_MISMATCH")?;
                    ensure!(
                        candidate_drain_can_be_released(&daemon_status(paths).await?, version),
                        "LIFECYCLE_ABANDONMENT_REQUIRES_DRAINED_IDLE_DAEMON"
                    );
                    let receipt: Value =
                        state::read_json(&paths.state_dir.join("install-receipt.json"))
                            .context("LIFECYCLE_ABANDONMENT_RECEIPT_UNAVAILABLE")?;
                    ensure!(
                        receipt["version"] == version
                            && receipt["versionPath"] == previous.to_string_lossy().as_ref()
                            && receipt["launchAgent"]
                                == launch_agent(paths).to_string_lossy().as_ref(),
                        "LIFECYCLE_ABANDONMENT_RECEIPT_MISMATCH"
                    );
                    let process = match observe_label(paths).await {
                        LabelObservation::Loaded { pid, program }
                            if program == paths.current().join("bin/loomex-runner")
                                || program == previous.join("bin/loomex-runner") =>
                        {
                            if lifecycle_test_mode() {
                                ProcessIdentity {
                                    pid,
                                    uid: unsafe { libc::geteuid() },
                                    started_seconds: 1,
                                    started_micros: 0,
                                    executable: previous.join("bin/loomex-runner"),
                                }
                            } else {
                                match inspect_process(pid) {
                                    ProcessObservation::Present(process) => process,
                                    _ => bail!("LIFECYCLE_ABANDONMENT_PROCESS_UNAVAILABLE"),
                                }
                            }
                        }
                        _ => bail!("LIFECYCLE_ABANDONMENT_PROCESS_UNAVAILABLE"),
                    };
                    let configuration: Value =
                        state::read_json(&paths.state_dir.join("bootstrap-install.json"))
                            .context("LIFECYCLE_ABANDONMENT_CONFIGURATION_UNAVAILABLE")?;
                    let package = operation
                        .package
                        .clone()
                        .context("LIFECYCLE_ABANDONMENT_PACKAGE_MISSING")?;
                    verify_all_owned_versions(paths)
                        .context("LIFECYCLE_ABANDONMENT_OWNERSHIP_MISMATCH")?;
                    ensure!(
                        configuration["version"] == package.version
                            && configuration["target"] == package.target.to_string_lossy().as_ref()
                            && configuration["manifestSha256"] == package.manifest_sha256,
                        "LIFECYCLE_ABANDONMENT_CONFIGURATION_MISMATCH"
                    );
                    operation.abandonment = Some(PendingUpdateAbandonment {
                        operation_id: operation.id,
                        package,
                        previous_target: previous,
                        receipt_digest: regular_digest(
                            &paths.state_dir.join("install-receipt.json"),
                        )?
                        .context("receipt missing")?,
                        inventory_digest: regular_digest(
                            &paths.state_dir.join("owned-versions.json"),
                        )?
                        .context("inventory missing")?,
                        plist_digest: plist,
                        drain_digest: regular_digest(&paths.state_dir.join("drain.json"))?
                            .context("drain missing")?,
                        bootstrap_configuration_digest: bootstrap_configuration_digest(
                            &configuration,
                        )?,
                        process,
                        successor: None,
                    });
                    operation.schema = if operation.auth_baseline.is_some() {
                        ABANDONMENT_OPERATION_SCHEMA
                    } else {
                        PRE_AUTH_ABANDONMENT_SCHEMA
                    }
                    .into();
                    set_checkpoint(
                        paths,
                        &mut operation,
                        "abandonment_pending",
                        "pending_update_abandonment_intent",
                    )?;
                    #[cfg(test)]
                    recovery_fault("after_abandonment_intent")?;
                }
                return reconcile_abandonment(paths, &mut operation).await;
            }
            ensure!(
                expected_operation.is_none(),
                "LIFECYCLE_EXPECTED_OPERATION_MISMATCH"
            );
        } else {
            ensure!(
                expected_operation.is_none(),
                "LIFECYCLE_EXPECTED_OPERATION_MISMATCH"
            );
        }
    }
    rollback(paths, version).await
}

pub async fn rollback(paths: &Paths, version: &str) -> Result<Value> {
    let target = owned_versions(paths)?
        .into_iter()
        .find(|path| path.file_name().is_some_and(|v| v == version))
        .context("VERSION_NOT_OWNED")?;
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

    #[test]
    fn integrity_streams_large_files_and_rejects_fresh_mutation() {
        use std::io::Write;
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("payload");
        let chunk = [7u8; INTEGRITY_BUFFER_BYTES];
        let mut expected = Sha256::new();
        let mut file = File::create(&path).unwrap();
        for _ in 0..1024 {
            file.write_all(&chunk).unwrap();
            expected.update(chunk);
        }
        drop(file);
        let started = std::time::Instant::now();
        let (digest, metadata) = streaming_file_digest(&path).unwrap();
        assert_eq!(digest, hex::encode(expected.finalize()));
        assert_eq!(metadata.len(), 64 * 1024 * 1024);
        eprintln!(
            "integrity fixture: bytes={} passes=1 buffer={} elapsed_ms={}",
            metadata.len(),
            INTEGRITY_BUFFER_BYTES,
            started.elapsed().as_millis()
        );
        fs::write(&path, b"changed").unwrap();
        assert_ne!(streaming_file_digest(&path).unwrap().0, digest);
        for change in 0..3 {
            fs::write(&path, b"unchanged").unwrap();
            let result = streaming_file_digest_checked(&path, || match change {
                0 => fs::write(&path, b"different-size").unwrap(),
                1 => fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap(),
                _ => {
                    fs::remove_file(&path).unwrap();
                    fs::write(&path, b"unchanged").unwrap();
                }
            });
            assert!(result.is_err(), "mutation {change} must fail closed");
        }
        fs::remove_file(&path).unwrap();
        symlink(temp.path().join("absent"), &path).unwrap();
        assert!(streaming_file_digest(&path).is_err());
        assert!(streaming_file_digest(temp.path()).is_err());
    }

    #[test]
    fn rollback_preflight_reports_verified_contract_eligibility_without_writes() {
        let temp = tempfile::tempdir().unwrap();
        let paths = paths(temp.path());
        make_compatible_target(&paths);
        make_compatible_version(&paths, "1.2.4");
        let incompatible = paths
            .versions()
            .join("1.2.4/metadata/compatibility-manifest.json");
        fs::write(&incompatible, b"old contract").unwrap();
        let inventory_path = paths.state_dir.join("owned-versions.json");
        let mut inventory: Value = state::read_json(&inventory_path).unwrap();
        let files = inventory["inventories"][1]["files"].as_array_mut().unwrap();
        let entry = files
            .iter_mut()
            .find(|entry| entry["path"] == "metadata/compatibility-manifest.json")
            .unwrap();
        entry["sha256"] = json!(state::digest(b"old contract"));
        entry["size"] = json!(12);
        state::write_json(&inventory_path, &inventory).unwrap();
        let before = fs::read(&inventory_path).unwrap();
        let result = rollback_preflight(&paths).unwrap();
        assert_eq!(result["targets"][0]["eligible"], true);
        assert_eq!(result["targets"][1]["eligible"], false);
        assert_eq!(
            result["targets"][1]["reason"],
            "compatibility_manifest_mismatch"
        );
        assert_eq!(fs::read(&inventory_path).unwrap(), before);
        assert!(!paths.operation().exists());
        assert!(!paths.current().exists());
        assert!(validate_rollback_target(&paths.versions().join("1.2.4"), "1.2.4").is_err());
        fs::write(paths.versions().join("1.2.3/bin/loomex"), b"tamper").unwrap();
        assert_eq!(
            rollback_preflight(&paths).unwrap()["targets"][0]["reason"],
            "inventory_verification_failed"
        );
    }

    #[tokio::test]
    async fn unowned_rollback_is_typed_before_service_calls() {
        let temp = tempfile::tempdir().unwrap();
        let paths = paths(temp.path());
        make_compatible_target(&paths);
        assert_eq!(
            rollback(&paths, "9.9.9").await.unwrap_err().to_string(),
            "VERSION_NOT_OWNED"
        );
        assert!(!paths.operation().exists());
        assert!(!paths.current().exists());
    }

    #[tokio::test]
    async fn process_inspection_bounds_actual_pipes_and_rejects_late_observations() {
        let targets = vec![PathBuf::from("/fixture/retained")];
        for (script, limit, timeout, expected) in [
            ("printf 'n/unrelated\\n'; exit 0", 1024, 1000, None),
            ("exit 1", 1024, 1000, None),
            (
                "yes 'n/unrelated'",
                4096,
                1000,
                Some("PRUNE_PROCESS_OBSERVATION_UNAVAILABLE"),
            ),
            (
                "yes 'diagnostic' >&2",
                4096,
                1000,
                Some("PRUNE_PROCESS_OBSERVATION_UNAVAILABLE"),
            ),
            (
                "sleep 1",
                4096,
                30,
                Some("PRUNE_PROCESS_OBSERVATION_UNAVAILABLE"),
            ),
            (
                "printf 'n/unrelated\\n'; sleep 0.02; printf diagnostic >&2",
                4096,
                1000,
                Some("PRUNE_PROCESS_OBSERVATION_UNAVAILABLE"),
            ),
            (
                "printf 'n/unrelated\\n'; sleep 0.02; printf 'n/fixture/retained/bin/loomex\\n'",
                4096,
                1000,
                Some("PRUNE_VERSION_IN_USE"),
            ),
            (
                "printf 'n/fixture/retained/bin/loomex'",
                4096,
                1000,
                Some("PRUNE_VERSION_IN_USE"),
            ),
            (
                "printf 'n/fixture/retained-other/bin/loomex\\n'",
                4096,
                1000,
                None,
            ),
            (
                "exit 2",
                4096,
                1000,
                Some("PRUNE_PROCESS_OBSERVATION_UNAVAILABLE"),
            ),
        ] {
            let mut command = tokio::process::Command::new("/bin/sh");
            command.args(["-c", script]);
            let started = std::time::Instant::now();
            let result = inspect_prune_processes(
                &mut command,
                &targets,
                Duration::from_millis(timeout),
                limit,
            )
            .await;
            match expected {
                Some(code) => assert_eq!(result.unwrap_err().to_string(), code, "{script}"),
                None => result.unwrap(),
            }
            assert!(started.elapsed() < Duration::from_secs(2));
        }
    }

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
        operation.schema = PRE_AUTH_OPERATION_SCHEMA.into();
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

    fn previous_drained_recovery_fixture(paths: &Paths) -> Operation {
        make_compatible_target(paths);
        make_compatible_version(paths, "1.2.4");
        let candidate = paths.versions().join("1.2.3");
        let previous = paths.versions().join("1.2.4");
        std::os::unix::fs::symlink(&previous, paths.current()).unwrap();
        fs::write(launch_agent(paths), b"previous-plist").unwrap();
        let backup = paths.state_dir.join("previous-backup.plist");
        fs::write(&backup, b"previous-plist").unwrap();
        let mut operation = Operation::new(OperationKind::Update, "recovery_required", None);
        operation.schema = PRE_AUTH_OPERATION_SCHEMA.into();
        operation.package = Some(PackageIdentity {
            version: "1.2.3".into(),
            target: candidate.clone(),
            manifest_sha256: "a".repeat(64),
        });
        operation.previous_target = Some(previous.clone());
        operation.resources = Some(OperationResources {
            launch_agent: launch_agent(paths),
            staged_launch_agent: paths.state_dir.join("candidate-staged.plist"),
            staged_launch_agent_sha256: state::digest(b"candidate-plist"),
            launch_agent_backup: backup,
            launch_agent_backup_sha256: Some(state::digest(b"previous-plist")),
            owned_versions: vec![candidate, previous],
        });
        state::write_json(
            &paths.state_dir.join("drain.json"),
            &json!({"draining":true}),
        )
        .unwrap();
        save_operation(paths, &operation).unwrap();
        operation
    }

    #[tokio::test]
    async fn accepted_stop_at_observation_deadline_preserves_pending_activation() {
        let _serial = TEST_SERIAL.lock().await;
        let temp = tempfile::tempdir().unwrap();
        let paths = paths(temp.path());
        let original = previous_drained_recovery_fixture(&paths);
        fs::remove_file(paths.operation()).unwrap();
        let staged = temp.path().join("candidate.plist");
        fs::write(&staged, b"candidate-plist").unwrap();
        TEST_MODE.store(true, Ordering::SeqCst);
        TEST_DELAYED_SERVICE_STOP.store(true, Ordering::SeqCst);
        TEST_LABEL_PRESENT.store(true, Ordering::SeqCst);
        TEST_RESTART_COUNT.store(0, Ordering::SeqCst);
        *TEST_RECOVERY_STATUS.lock().unwrap() =
            Some(json!({"version":"1.2.4","activeJobs":0,"draining":true}));
        let result = activate(
            &paths,
            paths.versions().join("1.2.3"),
            "1.2.3".into(),
            "a".repeat(64),
            staged,
        )
        .await;
        let restarts = TEST_RESTART_COUNT.load(Ordering::SeqCst);
        TEST_DELAYED_SERVICE_STOP.store(false, Ordering::SeqCst);
        TEST_LABEL_PRESENT.store(false, Ordering::SeqCst);
        *TEST_RECOVERY_STATUS.lock().unwrap() = None;
        TEST_MODE.store(false, Ordering::SeqCst);
        let result = result.unwrap_or_else(|error| json!({"error":error.to_string()}));
        assert_eq!(result["pending"], true, "{result}");
        assert_eq!(result["reason"], "service_stop");
        let retained: Operation = state::read_json(&paths.operation()).unwrap();
        assert_eq!(retained.phase, "service_stop_pending");
        assert_eq!(
            fs::read_link(paths.current()).unwrap(),
            original.previous_target.unwrap()
        );
        assert_eq!(fs::read(launch_agent(&paths)).unwrap(), b"previous-plist");
        assert!(paths.state_dir.join("drain.json").exists());
        assert_eq!(restarts, 0);
    }

    struct StopTestScope;
    impl StopTestScope {
        fn start() -> Self {
            TEST_MODE.store(true, Ordering::SeqCst);
            TEST_LABEL_PRESENT.store(true, Ordering::SeqCst);
            TEST_DELAYED_SERVICE_STOP.store(true, Ordering::SeqCst);
            TEST_STOP_COUNT.store(0, Ordering::SeqCst);
            TEST_STATUS_COUNT.store(0, Ordering::SeqCst);
            TEST_RESTART_COUNT.store(0, Ordering::SeqCst);
            *TEST_RECOVERY_STATUS.lock().unwrap() =
                Some(json!({"version":"1.2.4","activeJobs":0,"draining":true}));
            Self
        }
    }
    impl Drop for StopTestScope {
        fn drop(&mut self) {
            TEST_MODE.store(false, Ordering::SeqCst);
            TEST_LABEL_PRESENT.store(false, Ordering::SeqCst);
            TEST_DELAYED_SERVICE_STOP.store(false, Ordering::SeqCst);
            *TEST_LABEL_OBSERVATION.lock().unwrap() = None;
            *TEST_PROCESS_OBSERVATION.lock().unwrap() = None;
            *TEST_RECOVERY_FAULT.lock().unwrap() = None;
            *TEST_RECOVERY_STATUS.lock().unwrap() = None;
            *TEST_AUTH_STATUS.lock().unwrap() = None;
            TEST_STATUS_UNAVAILABLE.store(false, Ordering::SeqCst);
            TEST_STOP_WAIT_UNCONFIRMED.store(false, Ordering::SeqCst);
            TEST_BOOTOUT_FAIL.store(false, Ordering::SeqCst);
        }
    }

    // Owner-only socket exercises the actual lifecycle negotiation/envelope;
    // no native credential store, service or lifecycle writer is involved.
    fn auth_health_socket(
        paths: &Paths,
        observations: Vec<Value>,
        reply_delay: Duration,
        shared_auth: Option<crate::auth::Auth>,
    ) -> (
        tokio::task::JoinHandle<()>,
        std::sync::Arc<std::sync::atomic::AtomicUsize>,
    ) {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        let socket = paths.state_dir.join("control.sock");
        fs::create_dir_all(&paths.state_dir).unwrap();
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).unwrap();
        let count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let observed = count.clone();
        let server = tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let (read, mut write) = stream.into_split();
                let mut read = BufReader::new(read);
                let mut line = String::new();
                read.read_line(&mut line).await.unwrap();
                let request: Value = serde_json::from_str(&line).unwrap();
                assert_eq!(request["method"], "protocol.negotiate");
                assert_eq!(
                    request["params"]["requiredCapabilities"],
                    json!(["method:auth.status"])
                );
                let reply = json!({"protocol":crate::control::PROTOCOL,"id":request["id"],"result":{
                    "selectedProtocol":crate::control::PROTOCOL,"serverVersion":"0.4.0",
                    "maxFrameBytes":crate::control::MAX_FRAME,"capabilities":["method:auth.status", "auth:startup-observation/v1"]}});
                write
                    .write_all(format!("{reply}\n").as_bytes())
                    .await
                    .unwrap();
                line.clear();
                read.read_line(&mut line).await.unwrap();
                let request: Value = serde_json::from_str(&line).unwrap();
                assert_eq!(request["method"], "auth.status");
                assert_eq!(request["params"], json!({"observation":"startup"}));
                let index = observed
                    .fetch_add(1, Ordering::SeqCst)
                    .min(observations.len() - 1);
                tokio::time::sleep(reply_delay).await;
                let status = match &shared_auth {
                    Some(auth) => auth.startup_status().await.unwrap(),
                    None => observations[index].clone(),
                };
                let reply =
                    json!({"protocol":crate::control::PROTOCOL,"id":request["id"],"result":status});
                write
                    .write_all(format!("{reply}\n").as_bytes())
                    .await
                    .unwrap();
            }
        });
        (server, count)
    }

    #[tokio::test]
    async fn startup_auth_health_reobserves_transient_store_read_before_scope_admission() {
        let _serial = TEST_SERIAL.lock().await;
        let _scope = StopTestScope::start();
        TEST_MODE.store(false, Ordering::SeqCst);
        let temp = tempfile::tempdir_in("/tmp").unwrap();
        let paths = paths(temp.path());
        let installation = Uuid::new_v4();
        let organization = Uuid::new_v4();
        let authenticated = json!({"authenticated":true,"code":"AUTHENTICATED","installationId":installation,"activeOrganization":organization,"loginPending":false});
        let baseline = parse_auth_baseline(&authenticated).unwrap();
        *TEST_RECOVERY_STATUS.lock().unwrap() =
            Some(json!({"version":"0.4.1","activeJobs":0,"draining":false}));
        let (server, count) = auth_health_socket(
            &paths,
            vec![
                json!({"authenticated":false,"code":"STORE_UNAVAILABLE","loginPending":false}),
                authenticated.clone(),
                json!({"authenticated":false,"code":"STORE_UNAVAILABLE","loginPending":false}),
                authenticated,
            ],
            Duration::ZERO,
            None,
        );
        let result = healthy_candidate(&paths, "0.4.1", Some(&baseline)).await;
        let restored = healthy_restored_previous(&paths, "0.4.1", Some(&baseline)).await;
        server.abort();
        assert!(result.is_ok(), "{result:?}");
        assert!(restored.is_ok(), "{restored:?}");
        assert_eq!(count.load(Ordering::SeqCst), 4);
    }

    #[tokio::test]
    async fn startup_auth_health_permanent_store_unavailable_stops_at_attempt_limit() {
        let _serial = TEST_SERIAL.lock().await;
        let _scope = StopTestScope::start();
        TEST_MODE.store(false, Ordering::SeqCst);
        let temp = tempfile::tempdir_in("/tmp").unwrap();
        let paths = paths(temp.path());
        *TEST_RECOVERY_STATUS.lock().unwrap() =
            Some(json!({"version":"0.4.1","activeJobs":0,"draining":false}));
        let (server, count) = auth_health_socket(
            &paths,
            vec![json!({"authenticated":false,"code":"STORE_UNAVAILABLE","loginPending":false})],
            Duration::ZERO,
            None,
        );
        let started = tokio::time::Instant::now();
        let result = healthy_candidate(&paths, "0.4.1", Some(&AuthBaseline::Initial)).await;
        server.abort();
        assert_eq!(
            result.unwrap_err().to_string(),
            "candidate authentication is unconfirmed: STORE_UNAVAILABLE"
        );
        assert_eq!(count.load(Ordering::SeqCst), 20);
        assert!(started.elapsed() >= Duration::from_secs(5));
        assert!(started.elapsed() < Duration::from_secs(6));
    }

    #[tokio::test]
    async fn startup_auth_health_definitive_refusals_do_not_retry() {
        let _serial = TEST_SERIAL.lock().await;
        let _scope = StopTestScope::start();
        TEST_MODE.store(false, Ordering::SeqCst);
        let installation = Uuid::new_v4();
        let organization = Uuid::new_v4();
        let authenticated = json!({"authenticated":true,"code":"AUTHENTICATED","installationId":installation,"activeOrganization":organization,"loginPending":false});
        let baseline = parse_auth_baseline(&authenticated).unwrap();
        let mut observations = vec![
            json!({"authenticated":false,"code":"AUTH_REQUIRED","installationId":installation,"loginPending":false}),
            json!({"authenticated":true,"code":"AUTHENTICATED","installationId":Uuid::new_v4(),"activeOrganization":organization,"loginPending":false}),
            json!({"authenticated":true,"code":"AUTHENTICATED","installationId":installation,"activeOrganization":Uuid::new_v4(),"loginPending":false}),
            json!({"authenticated":true,"code":"AUTHENTICATED","installationId":installation,"activeOrganization":organization,"loginPending":true}),
            json!({"authenticated":true,"code":"STORE_UNAVAILABLE","loginPending":false}),
            json!({"authenticated":false,"code":"STORE_UNAVAILABLE","loginPending":true}),
            json!({"authenticated":false,"code":"STORE_UNAVAILABLE"}),
        ];
        for code in [
            "AUTH_RECOVERY_PENDING",
            "LOGOUT_PENDING",
            "STORE_ACCESS_REQUIRED",
            "STORE_ACCESS_DENIED",
            "STORE_OPERATION_PENDING",
            "STORE_INVALID",
            "UNEXPECTED",
        ] {
            observations.push(json!({"authenticated":false,"code":code,"loginPending":false}));
        }
        for observation in observations {
            let temp = tempfile::tempdir_in("/tmp").unwrap();
            let paths = paths(temp.path());
            *TEST_RECOVERY_STATUS.lock().unwrap() =
                Some(json!({"version":"0.4.1","activeJobs":0,"draining":false}));
            let (server, count) = auth_health_socket(
                &paths,
                vec![observation.clone(), authenticated.clone()],
                Duration::ZERO,
                None,
            );
            let started = tokio::time::Instant::now();
            let result = healthy_candidate(&paths, "0.4.1", Some(&baseline)).await;
            server.abort();
            assert!(result.is_err(), "{observation}");
            assert_eq!(count.load(Ordering::SeqCst), 1, "{observation}");
            assert!(
                started.elapsed() < Duration::from_millis(250),
                "{observation}"
            );
        }
    }

    #[tokio::test]
    async fn startup_auth_health_stalled_read_cannot_extend_observation_deadline() {
        let _serial = TEST_SERIAL.lock().await;
        let _scope = StopTestScope::start();
        TEST_MODE.store(false, Ordering::SeqCst);
        let temp = tempfile::tempdir_in("/tmp").unwrap();
        let paths = paths(temp.path());
        *TEST_RECOVERY_STATUS.lock().unwrap() =
            Some(json!({"version":"0.4.1","activeJobs":0,"draining":false}));
        let (server, count) = auth_health_socket(
            &paths,
            vec![json!({"authenticated":false,"code":"AUTH_REQUIRED","loginPending":false})],
            Duration::from_secs(30),
            None,
        );
        let started = tokio::time::Instant::now();
        let result = healthy_candidate(&paths, "0.4.1", Some(&AuthBaseline::Initial)).await;
        server.abort();
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("observation deadline exceeded")
        );
        assert_eq!(count.load(Ordering::SeqCst), 1);
        assert_eq!(startup_health_budget(), Duration::from_secs(22));
        assert!(started.elapsed() >= startup_health_budget());
        assert!(started.elapsed() < startup_health_budget() + Duration::from_secs(1));
    }

    #[tokio::test]
    async fn startup_auth_health_observes_shared_mutex_after_legitimate_refresh() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let _serial = TEST_SERIAL.lock().await;
        let _scope = StopTestScope::start();
        TEST_MODE.store(false, Ordering::SeqCst);
        let temp = tempfile::tempdir_in("/tmp").unwrap();
        let paths = paths(temp.path());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let api =
            crate::api::Api::for_test_origin(&format!("http://{}", listener.local_addr().unwrap()))
                .unwrap();
        let org = Uuid::new_v4().to_string();
        let auth = crate::auth::Auth::test_enrolled(api, &org, &Uuid::new_v4().to_string());
        let baseline = parse_auth_baseline(&auth.status().await.unwrap()).unwrap();
        auth.test_fingerprint_access_near_expiry(&org)
            .await
            .unwrap();
        let (entered, awaiting_response) = tokio::sync::oneshot::channel();
        let backend = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut byte = [0u8; 1];
            while !request.ends_with(b"\r\n\r\n") {
                stream.read_exact(&mut byte).await.unwrap();
                request.push(byte[0]);
                assert!(request.len() < 8192);
            }
            let headers = std::str::from_utf8(&request).unwrap();
            assert!(headers.starts_with("POST "));
            assert!(
                headers
                    .lines()
                    .next()
                    .unwrap()
                    .contains("delegations/refresh/")
            );
            let length = headers
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().unwrap())
                })
                .unwrap();
            assert!(length < 8192);
            let mut body = vec![0; length];
            stream.read_exact(&mut body).await.unwrap();
            let request: Value = serde_json::from_slice(&body).unwrap();
            assert!(request["refreshToken"].is_string());
            assert!(request["proof"].is_string());
            entered.send(()).unwrap();
            tokio::time::sleep(Duration::from_secs(6)).await;
            let body = json!({"data":{"accessToken":"lmxr_fixture_access","refreshToken":"lmxrr_fixture_refresh","expiresInSeconds":3600}}).to_string();
            stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes()).await.unwrap();
        });
        let worker_auth = auth.clone();
        let refresh = tokio::spawn(async move { worker_auth.credential(&org).await });
        awaiting_response.await.unwrap();
        *TEST_RECOVERY_STATUS.lock().unwrap() =
            Some(json!({"version":"0.4.2","activeJobs":0,"draining":false}));
        assert_eq!(daemon_status(&paths).await.unwrap()["activeJobs"], 0);
        let (socket, count) = auth_health_socket(
            &paths,
            vec![Value::Null],
            Duration::ZERO,
            Some(auth.clone()),
        );
        let started = tokio::time::Instant::now();
        let result = healthy_candidate(&paths, "0.4.2", Some(&baseline)).await;
        refresh.await.unwrap().unwrap();
        backend.await.unwrap();
        socket.abort();
        assert_eq!(
            parse_auth_baseline(&auth.status().await.unwrap()).unwrap(),
            baseline
        );
        assert!(result.is_ok(), "{result:?}");
        assert_eq!(count.load(Ordering::SeqCst), 1);
        assert!(started.elapsed() >= Duration::from_secs(6));
        assert!(started.elapsed() < Duration::from_secs(8));
    }

    #[tokio::test]
    async fn candidate_health_preserves_captured_auth_scope_after_journal_reload() {
        let _serial = TEST_SERIAL.lock().await;
        let _scope = StopTestScope::start();
        let temp = tempfile::tempdir().unwrap();
        let paths = paths(temp.path());
        let installation = Uuid::new_v4();
        let organization = Uuid::new_v4();
        let prior = json!({"authenticated":true,"code":"AUTHENTICATED","installationId":installation,"activeOrganization":organization,"loginPending":false});
        *TEST_AUTH_STATUS.lock().unwrap() = Some(prior);
        let mut operation = previous_drained_recovery_fixture(&paths);
        operation.auth_baseline = Some(
            capture_auth_baseline(&paths, operation.previous_target.as_deref())
                .await
                .unwrap(),
        );
        operation.schema = OPERATION_SCHEMA.into();
        save_operation(&paths, &operation).unwrap();
        let saved = fs::read_to_string(paths.operation()).unwrap();
        assert!(saved.contains(&installation.to_string()));
        assert!(saved.contains(&organization.to_string()));
        assert!(!saved.contains("privateKey"));
        let recovered: Operation = state::read_json(&paths.operation()).unwrap();
        assert_eq!(recovered.schema, OPERATION_SCHEMA);
        assert_ne!(recovered.schema, PRE_AUTH_OPERATION_SCHEMA);
        assert!(recovered.validate().is_ok());
        let mut downgraded = recovered.clone();
        downgraded.schema = PRE_AUTH_OPERATION_SCHEMA.into();
        assert!(downgraded.validate().is_err());
        downgraded.schema = LEGACY_OPERATION_SCHEMA.into();
        assert!(downgraded.validate().is_err());
        downgraded = recovered.clone();
        downgraded.auth_baseline = None;
        assert!(downgraded.validate().is_err());
        *TEST_RECOVERY_STATUS.lock().unwrap() =
            Some(json!({"version":"1.2.3","activeJobs":0,"draining":false}));
        healthy_candidate(&paths, "1.2.3", recovered.auth_baseline.as_ref())
            .await
            .unwrap();
        *TEST_AUTH_STATUS.lock().unwrap() = Some(
            json!({"authenticated":true,"code":"AUTHENTICATED","installationId":Uuid::new_v4(),"activeOrganization":organization,"loginPending":false}),
        );
        assert!(
            healthy_candidate(&paths, "1.2.3", recovered.auth_baseline.as_ref())
                .await
                .is_err()
        );
        *TEST_AUTH_STATUS.lock().unwrap() = Some(
            json!({"authenticated":true,"code":"AUTHENTICATED","installationId":installation,"activeOrganization":Uuid::new_v4(),"loginPending":false}),
        );
        assert!(
            healthy_candidate(&paths, "1.2.3", recovered.auth_baseline.as_ref())
                .await
                .is_err()
        );
        *TEST_AUTH_STATUS.lock().unwrap() =
            Some(json!({"authenticated":false,"code":"STORE_UNAVAILABLE"}));
        assert!(
            healthy_candidate(&paths, "1.2.3", recovered.auth_baseline.as_ref())
                .await
                .is_err()
        );
        TEST_MODE.store(false, Ordering::SeqCst);
        assert!(healthy_candidate(&paths, "1.2.3", None).await.is_err());
        healthy_restored_previous(&paths, "1.2.3", None)
            .await
            .unwrap();
        TEST_MODE.store(true, Ordering::SeqCst);
    }

    #[tokio::test]
    async fn auth_baseline_distinguishes_signed_out_initial_and_pending() {
        let _serial = TEST_SERIAL.lock().await;
        let _scope = StopTestScope::start();
        let temp = tempfile::tempdir().unwrap();
        let paths = paths(temp.path());
        let previous = temp.path().join("previous");
        let installation = Uuid::new_v4();
        *TEST_AUTH_STATUS.lock().unwrap() = Some(
            json!({"authenticated":false,"code":"AUTH_REQUIRED","installationId":installation,"loginPending":false}),
        );
        assert_eq!(
            capture_auth_baseline(&paths, None).await.unwrap(),
            AuthBaseline::Initial
        );
        let signed_out = capture_auth_baseline(&paths, Some(&previous))
            .await
            .unwrap();
        assert_eq!(
            signed_out,
            AuthBaseline::SignedOut {
                installation_id: Some(installation)
            }
        );
        *TEST_RECOVERY_STATUS.lock().unwrap() =
            Some(json!({"version":"1.2.3","activeJobs":0,"draining":false}));
        healthy_candidate(&paths, "1.2.3", Some(&signed_out))
            .await
            .unwrap();
        healthy_candidate(&paths, "1.2.3", Some(&AuthBaseline::Initial))
            .await
            .unwrap();
        *TEST_AUTH_STATUS.lock().unwrap() = Some(
            json!({"authenticated":false,"code":"AUTH_REQUIRED","installationId":Uuid::new_v4(),"loginPending":false}),
        );
        assert!(
            healthy_candidate(&paths, "1.2.3", Some(&signed_out))
                .await
                .is_err()
        );
        for code in [
            "AUTH_RECOVERY_PENDING",
            "LOGOUT_PENDING",
            "STORE_UNAVAILABLE",
            "UNEXPECTED",
        ] {
            *TEST_AUTH_STATUS.lock().unwrap() = Some(json!({"authenticated":false,"code":code}));
            assert!(
                capture_auth_baseline(&paths, Some(&previous))
                    .await
                    .is_err(),
                "{code}"
            );
            assert!(
                healthy_candidate(&paths, "1.2.3", Some(&signed_out))
                    .await
                    .is_err(),
                "{code}"
            );
            assert!(
                healthy_candidate(&paths, "1.2.3", Some(&AuthBaseline::Initial))
                    .await
                    .is_err(),
                "{code}"
            );
        }
        *TEST_AUTH_STATUS.lock().unwrap() =
            Some(json!({"authenticated":false,"code":"AUTH_REQUIRED","loginPending":true}));
        assert!(
            capture_auth_baseline(&paths, Some(&previous))
                .await
                .is_err()
        );
        for login_pending in [Value::Null, json!("false"), json!(0)] {
            *TEST_AUTH_STATUS.lock().unwrap() = Some(
                json!({"authenticated":false,"code":"AUTH_REQUIRED","loginPending":login_pending}),
            );
            assert!(
                capture_auth_baseline(&paths, Some(&previous))
                    .await
                    .is_err()
            );
        }
    }
    async fn pending_stop_fixture(paths: &Paths) -> Operation {
        let mut operation = previous_drained_recovery_fixture(paths);
        fs::write(
            &operation.resources.as_ref().unwrap().staged_launch_agent,
            b"candidate-plist",
        )
        .unwrap();
        prepare_service_stop(paths, &mut operation, StopDirection::ActivateCandidate)
            .await
            .unwrap();
        request_service_stop(paths, &mut operation).await.unwrap();
        assert!(
            observe_service_stop(paths, &mut operation, true)
                .await
                .unwrap()
                .is_none()
        );
        operation
    }

    #[tokio::test]
    async fn pending_resume_health_failure_retains_its_categorical_checkpoint() {
        let _serial = TEST_SERIAL.lock().await;
        let _scope = StopTestScope::start();
        let temp = tempfile::tempdir().unwrap();
        let paths = paths(temp.path());
        let mut original = previous_drained_recovery_fixture(&paths);
        original.auth_baseline = Some(AuthBaseline::Authenticated {
            installation_id: Uuid::new_v4(),
            active_organization: Some(Uuid::new_v4()),
        });
        original.schema = OPERATION_SCHEMA.into();
        state::write_json(
            &paths.state_dir.join("install-receipt.json"),
            &json!({"version":"1.2.4","versionPath":original.previous_target}),
        )
        .unwrap();
        fs::write(
            &original.resources.as_ref().unwrap().staged_launch_agent,
            b"candidate-plist",
        )
        .unwrap();
        prepare_service_stop(&paths, &mut original, StopDirection::ActivateCandidate)
            .await
            .unwrap();
        request_service_stop(&paths, &mut original).await.unwrap();
        assert!(
            observe_service_stop(&paths, &mut original, true)
                .await
                .unwrap()
                .is_none()
        );
        TEST_LABEL_PRESENT.store(false, Ordering::SeqCst);
        TEST_CANDIDATE_HEALTH_FAIL.store(true, Ordering::SeqCst);
        let result = resume(&paths).await;
        TEST_CANDIDATE_HEALTH_FAIL.store(false, Ordering::SeqCst);
        let result = result.unwrap();
        assert_eq!(result["resumed"], false);
        assert_eq!(result["operation"]["phase"], "recovery_required");
        assert_eq!(
            result["operation"]["checkpoint"],
            "stopped_service_health_failed"
        );
        let saved: Operation = state::read_json(&paths.operation()).unwrap();
        assert_eq!(saved.id, original.id);
        assert_eq!(saved.auth_baseline, original.auth_baseline);
        assert_eq!(saved.package, original.package);
        assert_eq!(saved.previous_target, original.previous_target);
        assert_eq!(saved.service_stops.len(), 1);
        assert_eq!(saved.service_stops[0].request, StopRequest::ObservedStopped);
        assert_eq!(
            fs::read_link(paths.current()).unwrap(),
            original.package.unwrap().target
        );
    }

    async fn historical_failed_candidate_fixture(paths: &Paths) -> Operation {
        let mut operation = previous_drained_recovery_fixture(paths);
        replace_fixture_previous_catalog(paths);
        operation.auth_baseline = Some(AuthBaseline::Authenticated {
            installation_id: Uuid::new_v4(),
            active_organization: Some(Uuid::new_v4()),
        });
        operation.schema = OPERATION_SCHEMA.into();
        state::write_json(
            &paths.state_dir.join("install-receipt.json"),
            &json!({"version":"1.2.4","versionPath":operation.previous_target}),
        )
        .unwrap();
        fs::write(
            &operation.resources.as_ref().unwrap().staged_launch_agent,
            b"candidate-plist",
        )
        .unwrap();
        prepare_service_stop(paths, &mut operation, StopDirection::ActivateCandidate)
            .await
            .unwrap();
        request_service_stop(paths, &mut operation).await.unwrap();
        TEST_LABEL_PRESENT.store(false, Ordering::SeqCst);
        TEST_CANDIDATE_HEALTH_FAIL.store(true, Ordering::SeqCst);
        let failed = resume(paths).await;
        TEST_CANDIDATE_HEALTH_FAIL.store(false, Ordering::SeqCst);
        assert_eq!(
            failed.unwrap()["operation"]["checkpoint"],
            "stopped_service_health_failed"
        );
        let mut historical: Operation = state::read_json(&paths.operation()).unwrap();
        // Exact historical decoder fixture: the previous owner's catch erased
        // the established failure. This is disposable test data, never a live
        // journal edit or authorization inferred from this generic string.
        historical.checkpoint = Some("observed state could not be reconciled safely".into());
        save_operation(paths, &historical).unwrap();
        TEST_LABEL_PRESENT.store(true, Ordering::SeqCst);
        *TEST_LABEL_OBSERVATION.lock().unwrap() = Some(LabelObservation::Loaded {
            pid: 222222,
            program: paths.versions().join("1.2.3/bin/loomex-runner"),
        });
        *TEST_RECOVERY_STATUS.lock().unwrap() =
            Some(json!({"version":"1.2.3","activeJobs":0,"draining":true}));
        historical
    }

    #[tokio::test]
    async fn historical_generic_candidate_with_fresh_healthy_auth_completes_without_restoration() {
        let _serial = TEST_SERIAL.lock().await;
        let _scope = StopTestScope::start();
        let temp = tempfile::tempdir().unwrap();
        let paths = paths(temp.path());
        let original = historical_failed_candidate_fixture(&paths).await;
        let candidate = original.package.as_ref().unwrap().target.clone();
        let receipt = fs::read(paths.state_dir.join("install-receipt.json")).unwrap();
        let AuthBaseline::Authenticated {
            installation_id,
            active_organization,
        } = original.auth_baseline.clone().unwrap()
        else {
            panic!("fixture baseline")
        };
        *TEST_RECOVERY_STATUS.lock().unwrap() =
            Some(json!({"version":"1.2.3","activeJobs":0,"draining":false}));
        *TEST_AUTH_STATUS.lock().unwrap() = Some(
            json!({"authenticated":true,"code":"AUTHENTICATED","installationId":installation_id,"activeOrganization":active_organization,"loginPending":false}),
        );
        let result = resume(&paths).await.unwrap();
        assert_eq!(result["resumed"], true);
        assert_eq!(result["operation"]["phase"], "completed");
        assert_eq!(
            result["operation"]["checkpoint"],
            "stopped_service_healthy_after_reconciliation"
        );
        let saved: Operation = state::read_json(&paths.operation()).unwrap();
        assert_eq!(saved.id, original.id);
        assert_eq!(saved.auth_baseline, original.auth_baseline);
        assert_eq!(saved.package, original.package);
        assert_eq!(saved.resources, original.resources);
        assert_eq!(saved.service_stops, original.service_stops);
        assert_eq!(TEST_STOP_COUNT.load(Ordering::SeqCst), 1);
        assert_eq!(fs::read_link(paths.current()).unwrap(), candidate);
        assert_eq!(fs::read(launch_agent(&paths)).unwrap(), b"candidate-plist");
        assert_eq!(
            fs::read(paths.state_dir.join("install-receipt.json")).unwrap(),
            receipt
        );
    }

    #[tokio::test]
    async fn historical_candidate_health_failure_restores_same_operation_only_after_exit_and_singleton()
     {
        let _serial = TEST_SERIAL.lock().await;
        let _scope = StopTestScope::start();
        let temp = tempfile::tempdir().unwrap();
        let paths = paths(temp.path());
        let original = historical_failed_candidate_fixture(&paths).await;
        let previous = original.previous_target.clone().unwrap();
        let candidate = original.package.as_ref().unwrap().target.clone();
        assert!(validate_rollback_target(&previous, "1.2.4").is_err());
        let receipt = fs::read(paths.state_dir.join("install-receipt.json")).unwrap();
        TEST_CANDIDATE_HEALTH_FAIL.store(true, Ordering::SeqCst);
        let pending = resume(&paths).await;
        TEST_CANDIDATE_HEALTH_FAIL.store(false, Ordering::SeqCst);
        assert_eq!(pending.unwrap()["pending"], true);
        let stopping: Operation = state::read_json(&paths.operation()).unwrap();
        assert_eq!(stopping.id, original.id);
        assert_eq!(stopping.service_stops.len(), 2);
        assert_eq!(
            stopping.service_stops[1].direction,
            StopDirection::RestorePrevious
        );
        assert_eq!(TEST_STOP_COUNT.load(Ordering::SeqCst), 2);
        assert_eq!(fs::read_link(paths.current()).unwrap(), candidate);
        // Job/IO counters do not prove actual native ownership released. Hold
        // the real singleton while process/label absence is observed.
        TEST_LABEL_PRESENT.store(false, Ordering::SeqCst);
        *TEST_LABEL_OBSERVATION.lock().unwrap() = None;
        let native_owner = stopped_singleton(&paths, false).unwrap();
        assert_eq!(resume(&paths).await.unwrap()["pending"], true);
        assert_eq!(fs::read_link(paths.current()).unwrap(), candidate);
        assert_eq!(TEST_STOP_COUNT.load(Ordering::SeqCst), 2);
        drop(native_owner);
        *TEST_RECOVERY_FAULT.lock().unwrap() = Some("before_stop_bootstrap");
        assert_eq!(
            resume(&paths).await.unwrap()["operation"]["phase"],
            "recovery_required"
        );
        assert_eq!(fs::read_link(paths.current()).unwrap(), previous);
        *TEST_RECOVERY_FAULT.lock().unwrap() = None;
        *TEST_RECOVERY_STATUS.lock().unwrap() =
            Some(json!({"version":"1.2.4","activeJobs":0,"draining":false}));
        *TEST_LABEL_OBSERVATION.lock().unwrap() = Some(LabelObservation::Loaded {
            pid: 333333,
            program: previous.join("bin/loomex-runner"),
        });
        let AuthBaseline::Authenticated {
            installation_id,
            active_organization,
        } = original.auth_baseline.clone().unwrap()
        else {
            panic!("fixture baseline")
        };
        *TEST_AUTH_STATUS.lock().unwrap() = Some(
            json!({"authenticated":true,"code":"AUTHENTICATED","installationId":installation_id,"activeOrganization":Uuid::new_v4(),"loginPending":false}),
        );
        assert_ne!(
            resume(&paths).await.unwrap()["operation"]["phase"],
            "rolled_back"
        );
        assert_eq!(TEST_STOP_COUNT.load(Ordering::SeqCst), 2);
        *TEST_AUTH_STATUS.lock().unwrap() = Some(
            json!({"authenticated":true,"code":"AUTHENTICATED","installationId":installation_id,"activeOrganization":active_organization,"loginPending":false}),
        );
        let result = resume(&paths).await.unwrap();
        assert_eq!(result["operation"]["phase"], "rolled_back");
        let saved: Operation = state::read_json(&paths.operation()).unwrap();
        assert_eq!(saved.id, original.id);
        assert_eq!(saved.package, original.package);
        assert_eq!(saved.auth_baseline, original.auth_baseline);
        assert_eq!(saved.resources, original.resources);
        assert_eq!(saved.service_stops.len(), 2);
        assert_eq!(TEST_STOP_COUNT.load(Ordering::SeqCst), 2);
        assert_eq!(
            fs::read(paths.state_dir.join("install-receipt.json")).unwrap(),
            receipt
        );
        assert_eq!(fs::read(launch_agent(&paths)).unwrap(), b"previous-plist");
    }

    #[tokio::test]
    async fn historical_candidate_health_failure_refuses_missing_baseline_busy_identity_and_tamper()
    {
        let _serial = TEST_SERIAL.lock().await;
        for case in [
            "missing_baseline",
            "active_work",
            "wrong_process",
            "tampered_candidate",
            "tampered_previous",
            "tampered_backup",
            "changed_receipt",
        ] {
            let _scope = StopTestScope::start();
            let temp = tempfile::tempdir().unwrap();
            let paths = paths(temp.path());
            let mut original = historical_failed_candidate_fixture(&paths).await;
            let candidate = original.package.as_ref().unwrap().target.clone();
            match case {
                "missing_baseline" => {
                    original.auth_baseline = None;
                    original.schema = PRE_AUTH_OPERATION_SCHEMA.into();
                    save_operation(&paths, &original).unwrap();
                }
                "active_work" => TEST_DRAIN_HAS_ACTIVE_WORK.store(true, Ordering::SeqCst),
                "wrong_process" => {
                    *TEST_PROCESS_OBSERVATION.lock().unwrap() =
                        Some(ProcessObservation::Present(ProcessIdentity {
                            pid: 222222,
                            uid: unsafe { libc::geteuid() } + 1,
                            started_seconds: 1,
                            started_micros: 0,
                            executable: candidate.join("bin/loomex-runner"),
                        }))
                }
                "tampered_candidate" => fs::write(candidate.join("bin/loomex"), b"tamper").unwrap(),
                "tampered_previous" => fs::write(
                    original
                        .previous_target
                        .as_ref()
                        .unwrap()
                        .join("bin/loomex"),
                    b"tamper",
                )
                .unwrap(),
                "tampered_backup" => fs::write(
                    &original.resources.as_ref().unwrap().launch_agent_backup,
                    b"tamper",
                )
                .unwrap(),
                "changed_receipt" => {
                    fs::write(paths.state_dir.join("install-receipt.json"), b"changed").unwrap()
                }
                _ => unreachable!(),
            }
            TEST_CANDIDATE_HEALTH_FAIL.store(true, Ordering::SeqCst);
            let result = resume(&paths).await;
            TEST_CANDIDATE_HEALTH_FAIL.store(false, Ordering::SeqCst);
            TEST_DRAIN_HAS_ACTIVE_WORK.store(false, Ordering::SeqCst);
            assert_eq!(result.unwrap()["resumed"], false, "{case}");
            let saved: Operation = state::read_json(&paths.operation()).unwrap();
            assert_eq!(saved.id, original.id, "{case}");
            assert_eq!(saved.auth_baseline, original.auth_baseline, "{case}");
            assert_eq!(saved.service_stops.len(), 1, "{case}");
            assert_eq!(TEST_STOP_COUNT.load(Ordering::SeqCst), 1, "{case}");
            assert_eq!(fs::read_link(paths.current()).unwrap(), candidate, "{case}");
            assert_eq!(
                fs::read(launch_agent(&paths)).unwrap(),
                b"candidate-plist",
                "{case}"
            );
        }
    }

    #[tokio::test]
    async fn pending_stop_late_absence_resumes_exact_operation_without_reissuing_stop() {
        let _serial = TEST_SERIAL.lock().await;
        let _scope = StopTestScope::start();
        let temp = tempfile::tempdir().unwrap();
        let paths = paths(temp.path());
        let original = pending_stop_fixture(&paths).await;
        assert_eq!(resume(&paths).await.unwrap()["pending"], true);
        let preflight = preflight_package(&paths, original.kind, original.package.clone().unwrap())
            .await
            .unwrap();
        assert_eq!(preflight["reason"], "service_stop");
        assert_eq!(TEST_STOP_COUNT.load(Ordering::SeqCst), 1);
        TEST_LABEL_PRESENT.store(false, Ordering::SeqCst);
        let result = resume(&paths).await.unwrap();
        assert_eq!(result["operation"]["phase"], "completed", "{result}");
        let saved: Operation = state::read_json(&paths.operation()).unwrap();
        assert_eq!(saved.id, original.id);
        assert_eq!(saved.package, original.package);
        assert_eq!(
            saved.service_stops[0].process,
            original.service_stops[0].process
        );
        assert_eq!(TEST_STOP_COUNT.load(Ordering::SeqCst), 1);
        assert_eq!(
            fs::read_link(paths.current()).unwrap(),
            paths.versions().join("1.2.3")
        );
        assert_eq!(fs::read(launch_agent(&paths)).unwrap(), b"candidate-plist");
        assert!(!paths.state_dir.join("drain.json").exists());
        assert_eq!(resume(&paths).await.unwrap()["resumed"], false);
        assert_eq!(TEST_STOP_COUNT.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn pending_stop_other_state_singleton_does_not_block_bound_installation() {
        let _serial = TEST_SERIAL.lock().await;
        let _scope = StopTestScope::start();
        let temp = tempfile::tempdir().unwrap();
        let paths = paths(temp.path());
        let original = pending_stop_fixture(&paths).await;
        let outside = temp.path().join("different-state-directory");
        fs::create_dir(&outside).unwrap();
        let outside_lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(outside.join("daemon.lock"))
            .unwrap();
        outside_lock.try_lock_exclusive().unwrap();
        // This held namespace is outside the exact installed state directory.
        // Its process identity/path availability is not an absence claim and
        // does not grant or deny this installation's server admission lock.
        TEST_LABEL_PRESENT.store(false, Ordering::SeqCst);
        assert!(stopped_singleton(&paths, false).is_ok());
        let result = resume(&paths).await.unwrap();
        assert_eq!(result["operation"]["phase"], "completed", "{result}");
        let saved: Operation = state::read_json(&paths.operation()).unwrap();
        assert_eq!(saved.id, original.id);
        assert_eq!(saved.package, original.package);
        assert_eq!(TEST_STOP_COUNT.load(Ordering::SeqCst), 1);
        // A held lock for a different state namespace remains held; it is not
        // evidence that this exact installation has a second admitted server.
        let outside_contender = OpenOptions::new()
            .read(true)
            .write(true)
            .open(outside.join("daemon.lock"))
            .unwrap();
        assert!(outside_contender.try_lock_exclusive().is_err());
    }

    #[tokio::test]
    async fn stopped_singleton_fences_second_cooperative_owner_until_guard_is_dropped() {
        let _serial = TEST_SERIAL.lock().await;
        let temp = tempfile::tempdir().unwrap();
        let paths = paths(temp.path());
        let lock_path = paths.state_dir.join("daemon.lock");
        let contender = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&lock_path)
            .unwrap();
        // Exercise the production lock/file checks, not test-mode health.
        TEST_MODE.store(false, Ordering::SeqCst);
        let owner = stopped_singleton(&paths, false).unwrap();
        assert!(contender.try_lock_exclusive().is_err());
        assert!(!paths.current().exists());
        assert!(!paths.operation().exists());
        drop(owner);
        contender.try_lock_exclusive().unwrap();
        assert!(stopped_singleton(&paths, false).is_err());
        drop(contender);
        assert!(stopped_singleton(&paths, false).is_ok());
    }

    #[tokio::test]
    async fn stopped_singleton_production_file_safety_preserves_unsafe_namespace() {
        let _serial = TEST_SERIAL.lock().await;
        TEST_MODE.store(false, Ordering::SeqCst);
        for case in [
            "missing_upgrade_lock",
            "symlink",
            "directory",
            "unsafe_mode",
        ] {
            let temp = tempfile::tempdir().unwrap();
            let paths = paths(temp.path());
            let lock_path = paths.state_dir.join("daemon.lock");
            let other = temp.path().join("untouched");
            fs::write(&other, b"private unrelated fixture").unwrap();
            match case {
                "missing_upgrade_lock" => {}
                "symlink" => std::os::unix::fs::symlink(&other, &lock_path).unwrap(),
                "directory" => fs::create_dir(&lock_path).unwrap(),
                "unsafe_mode" => {
                    fs::write(&lock_path, b"unsafe fixture").unwrap();
                    fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o666)).unwrap();
                }
                _ => unreachable!(),
            }
            assert!(stopped_singleton(&paths, false).is_err(), "{case}");
            assert_eq!(fs::read(&other).unwrap(), b"private unrelated fixture");
            assert!(!paths.current().exists(), "{case}");
            assert!(!paths.operation().exists(), "{case}");
            assert!(!paths.state_dir.join("drain.json").exists(), "{case}");
            if case == "missing_upgrade_lock" {
                assert!(!lock_path.exists());
            }
            if case == "symlink" {
                assert!(lock_path.is_symlink());
            }
            if case == "directory" {
                assert!(lock_path.is_dir());
            }
            if case == "unsafe_mode" {
                assert_eq!(fs::read(&lock_path).unwrap(), b"unsafe fixture");
                assert_eq!(
                    fs::metadata(&lock_path).unwrap().permissions().mode() & 0o777,
                    0o666
                );
            }
        }
    }

    #[tokio::test]
    async fn pending_stop_unknown_live_reused_replacement_and_singleton_observations_fail_closed() {
        let _serial = TEST_SERIAL.lock().await;
        for case in [
            "label_unknown",
            "process_unknown",
            "old_still_live",
            "reused_pid",
            "replacement_label",
            "singleton_held",
        ] {
            let _scope = StopTestScope::start();
            let temp = tempfile::tempdir().unwrap();
            let paths = paths(temp.path());
            let original = pending_stop_fixture(&paths).await;
            let old = original.service_stops[0].process.clone().unwrap();
            TEST_LABEL_PRESENT.store(false, Ordering::SeqCst);
            let mut held = None;
            match case {
                "label_unknown" => {
                    *TEST_LABEL_OBSERVATION.lock().unwrap() = Some(LabelObservation::Unknown)
                }
                "process_unknown" => {
                    *TEST_PROCESS_OBSERVATION.lock().unwrap() = Some(ProcessObservation::Unknown)
                }
                "old_still_live" => {
                    *TEST_PROCESS_OBSERVATION.lock().unwrap() =
                        Some(ProcessObservation::Present(old.clone()))
                }
                "reused_pid" => {
                    let mut reused = old;
                    reused.started_seconds += 1;
                    *TEST_PROCESS_OBSERVATION.lock().unwrap() =
                        Some(ProcessObservation::Present(reused));
                }
                "replacement_label" => {
                    *TEST_LABEL_OBSERVATION.lock().unwrap() = Some(LabelObservation::Loaded {
                        pid: old.pid + 1,
                        program: old.executable,
                    })
                }
                "singleton_held" => held = Some(stopped_singleton(&paths, false).unwrap()),
                _ => unreachable!(),
            }
            let result = resume(&paths).await.unwrap();
            assert_ne!(
                result["operation"]["phase"], "completed",
                "{case}: {result}"
            );
            assert_eq!(
                fs::read_link(paths.current()).unwrap(),
                original.previous_target.unwrap(),
                "{case}"
            );
            assert_eq!(
                fs::read(launch_agent(&paths)).unwrap(),
                b"previous-plist",
                "{case}"
            );
            assert!(paths.state_dir.join("drain.json").exists(), "{case}");
            assert_eq!(TEST_STOP_COUNT.load(Ordering::SeqCst), 1, "{case}");
            assert_eq!(TEST_RESTART_COUNT.load(Ordering::SeqCst), 0, "{case}");
            drop(held);
        }
    }

    #[tokio::test]
    async fn pending_stop_tampered_configuration_receipt_inventory_and_unsafe_files_preserve_intent()
     {
        let _serial = TEST_SERIAL.lock().await;
        for case in [
            "plist",
            "receipt",
            "inventory",
            "pointer",
            "drain_symlink",
            "singleton_symlink",
            "staged",
        ] {
            let _scope = StopTestScope::start();
            let temp = tempfile::tempdir().unwrap();
            let paths = paths(temp.path());
            let original = pending_stop_fixture(&paths).await;
            TEST_LABEL_PRESENT.store(false, Ordering::SeqCst);
            match case {
                "plist" => fs::write(launch_agent(&paths), b"changed").unwrap(),
                "receipt" => {
                    fs::write(paths.state_dir.join("install-receipt.json"), b"{}").unwrap()
                }
                "inventory" => {
                    let path = paths.state_dir.join("owned-versions.json");
                    let mut owned: Value = state::read_json(&path).unwrap();
                    owned["extra"] = json!(true);
                    state::write_json(&path, &owned).unwrap();
                }
                "pointer" => {
                    fs::remove_file(paths.current()).unwrap();
                    std::os::unix::fs::symlink(paths.versions().join("1.2.3"), paths.current())
                        .unwrap();
                }
                "drain_symlink" => {
                    fs::remove_file(paths.state_dir.join("drain.json")).unwrap();
                    std::os::unix::fs::symlink(
                        temp.path().join("unrelated"),
                        paths.state_dir.join("drain.json"),
                    )
                    .unwrap();
                }
                "singleton_symlink" => std::os::unix::fs::symlink(
                    temp.path().join("unrelated"),
                    paths.state_dir.join("daemon.lock"),
                )
                .unwrap(),
                "staged" => fs::write(
                    &original.resources.as_ref().unwrap().staged_launch_agent,
                    b"changed",
                )
                .unwrap(),
                _ => unreachable!(),
            }
            let result = resume(&paths).await.unwrap();
            assert_ne!(
                result["operation"]["phase"], "completed",
                "{case}: {result}"
            );
            let saved: Operation = state::read_json(&paths.operation()).unwrap();
            assert_eq!(saved.service_stops, original.service_stops, "{case}");
            assert_eq!(TEST_STOP_COUNT.load(Ordering::SeqCst), 1, "{case}");
            assert_eq!(TEST_RESTART_COUNT.load(Ordering::SeqCst), 0, "{case}");
        }
    }

    #[tokio::test]
    async fn pending_stop_requires_exact_idle_fresh_status_before_dispatch() {
        let _serial = TEST_SERIAL.lock().await;
        for status in [
            json!({"version":"1.2.4","activeJobs":1,"draining":true}),
            json!({"version":"1.2.4","draining":true}),
            json!({"version":"1.2.4","activeJobs":0,"draining":false}),
            json!({"version":"different","activeJobs":0,"draining":true}),
        ] {
            let _scope = StopTestScope::start();
            let temp = tempfile::tempdir().unwrap();
            let paths = paths(temp.path());
            let mut original = previous_drained_recovery_fixture(&paths);
            fs::write(
                &original.resources.as_ref().unwrap().staged_launch_agent,
                b"candidate-plist",
            )
            .unwrap();
            prepare_service_stop(&paths, &mut original, StopDirection::ActivateCandidate)
                .await
                .unwrap();
            *TEST_RECOVERY_STATUS.lock().unwrap() = Some(status);
            assert!(request_service_stop(&paths, &mut original).await.is_err());
            assert_eq!(TEST_STOP_COUNT.load(Ordering::SeqCst), 0);
            assert!(paths.state_dir.join("drain.json").exists());
        }
    }

    #[tokio::test]
    async fn pending_stop_prepared_and_requested_interruptions_never_replay_uncertain_request() {
        let _serial = TEST_SERIAL.lock().await;
        for stage in ["after_stop_intent", "after_stop_request"] {
            let _scope = StopTestScope::start();
            let temp = tempfile::tempdir().unwrap();
            let paths = paths(temp.path());
            let mut original = previous_drained_recovery_fixture(&paths);
            fs::write(
                &original.resources.as_ref().unwrap().staged_launch_agent,
                b"candidate-plist",
            )
            .unwrap();
            prepare_service_stop(&paths, &mut original, StopDirection::ActivateCandidate)
                .await
                .unwrap();
            *TEST_RECOVERY_FAULT.lock().unwrap() = Some(stage);
            assert!(request_service_stop(&paths, &mut original).await.is_err());
            *TEST_RECOVERY_FAULT.lock().unwrap() = None;
            let count = TEST_STOP_COUNT.load(Ordering::SeqCst);
            assert_eq!(resume(&paths).await.unwrap()["pending"], true);
            assert_eq!(TEST_STOP_COUNT.load(Ordering::SeqCst), count);
            assert_eq!(
                fs::read_link(paths.current()).unwrap(),
                original.previous_target.clone().unwrap()
            );
            TEST_LABEL_PRESENT.store(false, Ordering::SeqCst);
            assert_eq!(
                resume(&paths).await.unwrap()["operation"]["phase"],
                "completed"
            );
            assert_eq!(TEST_STOP_COUNT.load(Ordering::SeqCst), count);
        }
    }

    #[tokio::test]
    async fn pending_stop_verified_transition_interruptions_resume_same_saved_resources() {
        let _serial = TEST_SERIAL.lock().await;
        for stage in [
            "after_stop_verified",
            "after_stop_pointer",
            "after_stop_configuration",
            "before_stop_bootstrap",
            "after_stop_bootstrap",
        ] {
            let _scope = StopTestScope::start();
            let temp = tempfile::tempdir().unwrap();
            let paths = paths(temp.path());
            let original = pending_stop_fixture(&paths).await;
            TEST_LABEL_PRESENT.store(false, Ordering::SeqCst);
            *TEST_RECOVERY_FAULT.lock().unwrap() = Some(stage);
            let interrupted = resume(&paths).await.unwrap();
            assert_eq!(
                interrupted["operation"]["phase"], "recovery_required",
                "{stage}: {interrupted}"
            );
            *TEST_RECOVERY_FAULT.lock().unwrap() = None;
            *TEST_RECOVERY_STATUS.lock().unwrap() =
                Some(json!({"version":"1.2.3","activeJobs":0,"draining":false}));
            if stage == "after_stop_bootstrap" {
                *TEST_LABEL_OBSERVATION.lock().unwrap() = Some(LabelObservation::Loaded {
                    pid: 222222,
                    program: paths.versions().join("1.2.3/bin/loomex-runner"),
                });
            }
            let result = resume(&paths).await.unwrap();
            assert_eq!(
                result["operation"]["phase"], "completed",
                "{stage}: {result}"
            );
            let saved: Operation = state::read_json(&paths.operation()).unwrap();
            assert_eq!(saved.id, original.id);
            assert_eq!(saved.package, original.package);
            assert_eq!(TEST_STOP_COUNT.load(Ordering::SeqCst), 1);
        }
    }

    #[tokio::test]
    async fn pending_stop_rollback_direction_preserves_history_and_resumes_only_previous_target() {
        let _serial = TEST_SERIAL.lock().await;
        let _scope = StopTestScope::start();
        let temp = tempfile::tempdir().unwrap();
        let paths = paths(temp.path());
        let mut original = pending_stop_fixture(&paths).await;
        TEST_LABEL_PRESENT.store(false, Ordering::SeqCst);
        let guard = observe_service_stop(&paths, &mut original, false)
            .await
            .unwrap()
            .unwrap();
        complete_stopped_transition(&paths, &mut original, guard)
            .await
            .unwrap();
        TEST_LABEL_PRESENT.store(true, Ordering::SeqCst);
        *TEST_RECOVERY_STATUS.lock().unwrap() =
            Some(json!({"version":"1.2.3","activeJobs":0,"draining":true}));
        state::write_json(
            &paths.state_dir.join("drain.json"),
            &json!({"draining":true}),
        )
        .unwrap();
        prepare_service_stop(&paths, &mut original, StopDirection::RestorePrevious)
            .await
            .unwrap();
        request_service_stop(&paths, &mut original).await.unwrap();
        assert!(
            observe_service_stop(&paths, &mut original, true)
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(original.service_stops.len(), 2);
        assert_eq!(resume(&paths).await.unwrap()["pending"], true);
        TEST_LABEL_PRESENT.store(false, Ordering::SeqCst);
        let result = resume(&paths).await.unwrap();
        assert_eq!(result["operation"]["phase"], "rolled_back", "{result}");
        assert_eq!(
            fs::read_link(paths.current()).unwrap(),
            paths.versions().join("1.2.4")
        );
        assert_eq!(TEST_STOP_COUNT.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn legitimate_persisted_v1_checkpoint_resumes_without_fabricating_stop_identity() {
        let _serial = TEST_SERIAL.lock().await;
        let _scope = StopTestScope::start();
        let temp = tempfile::tempdir().unwrap();
        let paths = paths(temp.path());
        let mut original = previous_drained_recovery_fixture(&paths);
        original.schema = LEGACY_OPERATION_SCHEMA.into();
        original.checkpoint = Some("previous_drain_release_pending".into());
        save_operation(&paths, &original).unwrap();
        let result = resume(&paths).await.unwrap();
        assert_eq!(result["operation"]["phase"], "rolled_back", "{result}");
        let saved: Operation = state::read_json(&paths.operation()).unwrap();
        assert_eq!(saved.id, original.id);
        assert_eq!(saved.schema, LEGACY_OPERATION_SCHEMA);
        assert_eq!(saved.package, original.package);
        assert_eq!(saved.previous_target, original.previous_target);
        assert_eq!(saved.resources, original.resources);
        assert!(saved.service_stops.is_empty());
        assert_eq!(TEST_STOP_COUNT.load(Ordering::SeqCst), 0);
        assert_eq!(TEST_RESTART_COUNT.load(Ordering::SeqCst), 1);
        assert!(!paths.state_dir.join("drain.json").exists());
        assert_eq!(resume(&paths).await.unwrap()["resumed"], false);
        assert_eq!(TEST_RESTART_COUNT.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn first_install_without_old_daemon_requires_absence_and_real_bound_singleton_proof() {
        let _serial = TEST_SERIAL.lock().await;
        for case in [
            "unknown_label",
            "singleton_held",
            "singleton_symlink",
            "healthy_absence",
        ] {
            let _scope = StopTestScope::start();
            let temp = tempfile::tempdir().unwrap();
            let paths = paths(temp.path());
            make_compatible_target(&paths);
            TEST_LABEL_PRESENT.store(false, Ordering::SeqCst);
            *TEST_RECOVERY_STATUS.lock().unwrap() = None;
            let staged = temp.path().join("first-install.plist");
            fs::write(&staged, b"candidate-plist").unwrap();
            let mut held = None;
            match case {
                "unknown_label" => {
                    *TEST_LABEL_OBSERVATION.lock().unwrap() = Some(LabelObservation::Unknown)
                }
                "singleton_held" => held = Some(stopped_singleton(&paths, true).unwrap()),
                "singleton_symlink" => std::os::unix::fs::symlink(
                    temp.path().join("unrelated"),
                    paths.state_dir.join("daemon.lock"),
                )
                .unwrap(),
                "healthy_absence" => {}
                _ => unreachable!(),
            }
            let result = activate_as(
                &paths,
                OperationKind::Install,
                paths.versions().join("1.2.3"),
                "1.2.3".into(),
                "a".repeat(64),
                staged,
            )
            .await;
            if case == "healthy_absence" {
                let value = result.unwrap();
                assert_eq!(value["activated"], true, "{value}");
                let operation: Operation = state::read_json(&paths.operation()).unwrap();
                assert_eq!(operation.kind, OperationKind::Install);
                assert_eq!(operation.phase, "completed");
                assert!(operation.previous_target.is_none());
                assert!(operation.service_stops[0].process.is_none());
                assert_eq!(
                    operation.service_stops[0].request,
                    StopRequest::ObservedStopped
                );
                assert_eq!(
                    fs::read_link(paths.current()).unwrap(),
                    paths.versions().join("1.2.3")
                );
                assert_eq!(fs::read(launch_agent(&paths)).unwrap(), b"candidate-plist");
                // Real file ownership is released for the exact bootstrap.
                assert!(stopped_singleton(&paths, false).is_ok());
            } else {
                assert!(result.is_err(), "{case}: {result:?}");
                assert!(!paths.current().exists(), "{case}");
                assert!(!launch_agent(&paths).exists(), "{case}");
            }
            assert_eq!(TEST_STOP_COUNT.load(Ordering::SeqCst), 0, "{case}");
            assert_eq!(TEST_RESTART_COUNT.load(Ordering::SeqCst), 0, "{case}");
            assert!(!paths.state_dir.join("install-receipt.json").exists());
            assert!(!paths.state_dir.join("bootstrap-uninstall.json").exists());
            drop(held);
        }
    }

    #[test]
    fn checkpoint_decoder_preserves_frozen_v1_and_rejects_residual_new_meanings() {
        let mut operation = Operation::new(OperationKind::Update, "recovery_required", None);
        operation.schema = LEGACY_OPERATION_SCHEMA.into();
        for checkpoint in LEGACY_CHECKPOINTS {
            operation.checkpoint = Some((*checkpoint).into());
            assert!(operation.validate().is_ok(), "{checkpoint}");
        }
        for schema in [LEGACY_OPERATION_SCHEMA, OPERATION_SCHEMA] {
            operation.schema = schema.into();
            for checkpoint in [
                "service_stop_intent_prepared",
                "service_stop_requested",
                "old_service_stop_unconfirmed",
                "old_service_stop_verified",
                "stopped_pointer_and_plist_switched",
                "stopped_service_bootstrapped",
                "stopped_service_healthy",
                "stopped_service_start_failed",
                "stopped_service_health_failed",
                "service_stop_reconciliation_required",
                "unknown_historic_meaning",
            ] {
                operation.checkpoint = Some(checkpoint.into());
                assert!(operation.validate().is_err(), "{schema}: {checkpoint}");
            }
        }
    }

    #[tokio::test]
    async fn residual_stop_checkpoint_rejects_legacy_reentry_before_effects() {
        let _serial = TEST_SERIAL.lock().await;
        let _scope = StopTestScope::start();
        let temp = tempfile::tempdir().unwrap();
        let paths = paths(temp.path());
        let mut operation = previous_drained_recovery_fixture(&paths);
        operation.schema = LEGACY_OPERATION_SCHEMA.into();
        operation.service_stops.clear();
        operation.checkpoint = Some("old_service_stop_unconfirmed".into());
        // Read-path fixture deliberately bypasses writer validation: decoder
        // rejection must precede legacy recovery even for persisted residuals.
        state::write_json(&paths.operation(), &operation).unwrap();
        let journal = fs::read(paths.operation()).unwrap();
        let drain = fs::read(paths.state_dir.join("drain.json")).unwrap();
        let result = resume(&paths).await;
        assert!(
            result.is_err(),
            "residual stop meaning admitted legacy recovery: {result:?}"
        );
        assert_eq!(fs::read(paths.operation()).unwrap(), journal);
        assert_eq!(fs::read(paths.state_dir.join("drain.json")).unwrap(), drain);
        assert_eq!(
            fs::read_link(paths.current()).unwrap(),
            operation.previous_target.unwrap()
        );
        assert_eq!(fs::read(launch_agent(&paths)).unwrap(), b"previous-plist");
        assert_eq!(TEST_RESTART_COUNT.load(Ordering::SeqCst), 0);
        assert_eq!(TEST_STOP_COUNT.load(Ordering::SeqCst), 0);
        assert_eq!(TEST_STATUS_COUNT.load(Ordering::SeqCst), 0);
        assert!(!paths.state_dir.join("bootstrap-uninstall.json").exists());
    }

    #[tokio::test]
    async fn pending_stop_private_v2_guard_rejects_downgrade_and_uninstall_before_mutation() {
        let _serial = TEST_SERIAL.lock().await;
        let _scope = StopTestScope::start();
        let temp = tempfile::tempdir().unwrap();
        let paths = paths(temp.path());
        let original = pending_stop_fixture(&paths).await;
        assert!(require_terminal_before_uninstall(&paths).is_err());
        let mut downgraded = original.clone();
        downgraded.schema = LEGACY_OPERATION_SCHEMA.into();
        assert!(save_operation(&paths, &downgraded).is_err());
        let mut unrelated = original.clone();
        unrelated.service_stops[0].operation_id = Uuid::new_v4();
        assert!(save_operation(&paths, &unrelated).is_err());
        let mut unresolved = original.clone();
        unresolved
            .service_stops
            .push(unresolved.service_stops[0].clone());
        assert!(save_operation(&paths, &unresolved).is_err());
        let mut legacy = original.clone();
        legacy.schema = LEGACY_OPERATION_SCHEMA.into();
        legacy.service_stops.clear();
        legacy.phase = "recovery_required".into();
        assert!(legacy.validate().is_err());
        legacy.checkpoint = Some("previous_drain_release_pending".into());
        assert!(legacy.validate().is_ok());
        assert_eq!(TEST_STOP_COUNT.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn pending_stop_restarted_identity_requires_typed_label_uid_pid_and_executable() {
        let _serial = TEST_SERIAL.lock().await;
        let _scope = StopTestScope::start();
        let temp = tempfile::tempdir().unwrap();
        let paths = paths(temp.path());
        let target = paths.versions().join("1.2.3");
        let mut actual = ProcessIdentity {
            pid: 222222,
            uid: unsafe { libc::geteuid() },
            started_seconds: 1,
            started_micros: 0,
            executable: target.join("bin/loomex-runner"),
        };
        *TEST_LABEL_OBSERVATION.lock().unwrap() = Some(LabelObservation::Loaded {
            pid: actual.pid,
            program: actual.executable.clone(),
        });
        *TEST_PROCESS_OBSERVATION.lock().unwrap() =
            Some(ProcessObservation::Present(actual.clone()));
        assert!(restarted_service_identity_matches(&paths, &target).await);
        actual.uid += 1;
        *TEST_PROCESS_OBSERVATION.lock().unwrap() = Some(ProcessObservation::Present(actual));
        assert!(!restarted_service_identity_matches(&paths, &target).await);
        *TEST_PROCESS_OBSERVATION.lock().unwrap() = Some(ProcessObservation::Unknown);
        assert!(!restarted_service_identity_matches(&paths, &target).await);
        *TEST_LABEL_OBSERVATION.lock().unwrap() = Some(LabelObservation::Absent);
        assert!(!restarted_service_identity_matches(&paths, &target).await);
    }

    #[test]
    fn pending_stop_label_classifier_never_infers_absence_from_generic_failure_or_nested_fields() {
        let uid = unsafe { libc::geteuid() };
        let missing = format!(
            "Bad request.\nCould not find service \"app.loomex.runner\" in domain for user gui: {uid}\n"
        );
        assert_eq!(
            classify_label_output(uid, Some(113), b"", missing.as_bytes()),
            LabelObservation::Absent
        );
        for code in [None, Some(1), Some(113)] {
            assert_eq!(
                classify_label_output(uid, code, b"", b"permission denied"),
                LabelObservation::Unknown
            );
        }
        let valid = format!(
            "gui/{uid}/app.loomex.runner = {{\n\tprogram = /owned/bin/loomex-runner\n\tpid = 123\n\tenvironment = {{\n\t\tpid = 999\n\t}}\n}}\n"
        );
        assert_eq!(
            classify_label_output(uid, Some(0), valid.as_bytes(), b""),
            LabelObservation::Loaded {
                pid: 123,
                program: PathBuf::from("/owned/bin/loomex-runner")
            }
        );
        assert_eq!(
            classify_label_output(uid, Some(0), b"malformed", b""),
            LabelObservation::Unknown
        );
    }

    async fn owned_idle_label_fixture(paths: &Paths) -> Operation {
        let mut operation = pending_stop_fixture(paths).await;
        operation.service_stops[0].request = StopRequest::ObservedStopped;
        operation.phase = "service_stop_pending".into();
        operation.checkpoint = Some("old_service_stop_unconfirmed".into());
        fs::remove_file(paths.current()).unwrap();
        symlink(&operation.package.as_ref().unwrap().target, paths.current()).unwrap();
        fs::write(launch_agent(paths), b"candidate-plist").unwrap();
        *TEST_PROCESS_OBSERVATION.lock().unwrap() = Some(ProcessObservation::Exited);
        TEST_STATUS_UNAVAILABLE.store(true, Ordering::SeqCst);
        TEST_DELAYED_SERVICE_STOP.store(false, Ordering::SeqCst);
        let uid = unsafe { libc::geteuid() };
        let label = format!(
            "gui/{uid}/app.loomex.runner = {{\n\tprogram = {}\n\tstate = not running\n}}\n",
            paths.current().join("bin/loomex-runner").display()
        );
        *TEST_LABEL_OBSERVATION.lock().unwrap() =
            Some(classify_label_output(uid, Some(0), label.as_bytes(), b""));
        save_operation(paths, &operation).unwrap();
        operation
    }

    #[tokio::test]
    async fn owned_idle_label_restores_same_operation_without_replacing_stop_history() {
        let _serial = TEST_SERIAL.lock().await;
        let _scope = StopTestScope::start();
        let temp = tempfile::tempdir().unwrap();
        let paths = paths(temp.path());
        let original = owned_idle_label_fixture(&paths).await;
        let result = resume(&paths).await.unwrap();
        TEST_STATUS_UNAVAILABLE.store(false, Ordering::SeqCst);
        assert_eq!(result["operation"]["phase"], "rolled_back", "{result}");
        let saved: Operation = state::read_json(&paths.operation()).unwrap();
        assert_eq!(saved.id, original.id);
        assert_eq!(saved.package, original.package);
        assert_eq!(saved.service_stops.len(), 2);
        assert_eq!(saved.service_stops[0], original.service_stops[0]);
        assert_eq!(
            saved.service_stops[1].direction,
            StopDirection::RestorePrevious
        );
        assert!(saved.service_stops[1].process.is_none());
        assert_eq!(saved.service_stops[1].request, StopRequest::ObservedStopped);
        assert_eq!(
            fs::read_link(paths.current()).unwrap(),
            original.previous_target.unwrap()
        );
        assert_eq!(fs::read(launch_agent(&paths)).unwrap(), b"previous-plist");
        assert_eq!(TEST_STOP_COUNT.load(Ordering::SeqCst), 2);
        assert_eq!(
            resume(&paths).await.unwrap()["reason"],
            "operation is terminal"
        );
        assert_eq!(TEST_STOP_COUNT.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn owned_idle_label_unknown_or_changed_ownership_never_unloads() {
        let _serial = TEST_SERIAL.lock().await;
        for case in [
            "unknown_label",
            "foreign_program",
            "pid_reused",
            "unknown_process",
            "singleton",
            "singleton_symlink",
            "socket",
            "plist",
            "inventory",
        ] {
            let _scope = StopTestScope::start();
            let temp = tempfile::tempdir().unwrap();
            let paths = paths(temp.path());
            let original = owned_idle_label_fixture(&paths).await;
            let mut singleton = None;
            match case {
                "unknown_label" => {
                    *TEST_LABEL_OBSERVATION.lock().unwrap() = Some(LabelObservation::Unknown)
                }
                "foreign_program" => {
                    *TEST_LABEL_OBSERVATION.lock().unwrap() = Some(LabelObservation::LoadedIdle {
                        program: PathBuf::from("/foreign/bin/loomex-runner"),
                    })
                }
                "pid_reused" => {
                    let mut process = original.service_stops[0].process.clone().unwrap();
                    process.started_seconds += 1;
                    *TEST_PROCESS_OBSERVATION.lock().unwrap() =
                        Some(ProcessObservation::Present(process));
                }
                "unknown_process" => {
                    *TEST_PROCESS_OBSERVATION.lock().unwrap() = Some(ProcessObservation::Unknown)
                }
                "singleton" => singleton = Some(stopped_singleton(&paths, false).unwrap()),
                "singleton_symlink" => symlink(
                    temp.path().join("unrelated"),
                    paths.state_dir.join("daemon.lock"),
                )
                .unwrap(),
                "socket" => {
                    fs::write(paths.state_dir.join("control.sock"), b"unconfirmed").unwrap()
                }
                "plist" => fs::write(launch_agent(&paths), b"changed").unwrap(),
                "inventory" => {
                    fs::write(paths.state_dir.join("owned-versions.json"), b"{}").unwrap()
                }
                _ => unreachable!(),
            }
            let result = resume(&paths).await.unwrap();
            assert_ne!(result["operation"]["phase"], "rolled_back", "{case}");
            let saved: Operation = state::read_json(&paths.operation()).unwrap();
            assert_eq!(saved.id, original.id, "{case}");
            assert_eq!(saved.service_stops, original.service_stops, "{case}");
            assert_eq!(TEST_STOP_COUNT.load(Ordering::SeqCst), 1, "{case}");
            drop(singleton);
        }
    }

    #[tokio::test]
    async fn owned_idle_label_dispatch_uncertainty_never_replays_or_adds_intents() {
        let _serial = TEST_SERIAL.lock().await;
        for case in [
            "prepared_interruption",
            "dispatch_interruption",
            "wait_uncertain",
            "spawn_failure",
            "spawn_reset_failure",
        ] {
            let _scope = StopTestScope::start();
            let temp = tempfile::tempdir().unwrap();
            let paths = paths(temp.path());
            let original = owned_idle_label_fixture(&paths).await;
            match case {
                "prepared_interruption" => {
                    *TEST_RECOVERY_FAULT.lock().unwrap() = Some("after_stop_intent")
                }
                "dispatch_interruption" => {
                    *TEST_RECOVERY_FAULT.lock().unwrap() =
                        Some("after_abandonment_stop_dispatch_intent")
                }
                "wait_uncertain" => TEST_STOP_WAIT_UNCONFIRMED.store(true, Ordering::SeqCst),
                "spawn_failure" => TEST_BOOTOUT_FAIL.store(true, Ordering::SeqCst),
                "spawn_reset_failure" => {
                    TEST_BOOTOUT_FAIL.store(true, Ordering::SeqCst);
                    *TEST_RECOVERY_FAULT.lock().unwrap() =
                        Some("before_stop_not_dispatched_checkpoint");
                }
                _ => unreachable!(),
            }
            let _ = resume(&paths).await.unwrap();
            let saved: Operation = state::read_json(&paths.operation()).unwrap();
            assert_eq!(saved.service_stops.len(), 2, "{case}");
            assert_eq!(saved.service_stops[0], original.service_stops[0], "{case}");
            let prepared = matches!(case, "prepared_interruption" | "spawn_failure");
            assert_eq!(
                saved.service_stops[1].request,
                if prepared {
                    StopRequest::Prepared
                } else {
                    StopRequest::Unconfirmed
                },
                "{case}"
            );
            *TEST_RECOVERY_FAULT.lock().unwrap() = None;
            TEST_BOOTOUT_FAIL.store(false, Ordering::SeqCst);
            TEST_STOP_WAIT_UNCONFIRMED.store(false, Ordering::SeqCst);
            let count = TEST_STOP_COUNT.load(Ordering::SeqCst);
            let result = resume(&paths).await.unwrap();
            if prepared {
                assert_eq!(
                    result["operation"]["phase"], "rolled_back",
                    "{case}: {result}"
                );
                assert_eq!(TEST_STOP_COUNT.load(Ordering::SeqCst), count + 1, "{case}");
            } else {
                assert_eq!(result["pending"], true, "{case}: {result}");
                assert_eq!(TEST_STOP_COUNT.load(Ordering::SeqCst), count, "{case}");
                *TEST_LABEL_OBSERVATION.lock().unwrap() = Some(LabelObservation::Absent);
                TEST_LABEL_PRESENT.store(false, Ordering::SeqCst);
                assert_eq!(
                    resume(&paths).await.unwrap()["operation"]["phase"],
                    "rolled_back",
                    "{case}"
                );
                assert_eq!(TEST_STOP_COUNT.load(Ordering::SeqCst), count, "{case}");
            }
            let final_operation: Operation = state::read_json(&paths.operation()).unwrap();
            assert_eq!(final_operation.id, original.id, "{case}");
            assert_eq!(final_operation.service_stops.len(), 2, "{case}");
            assert_eq!(
                final_operation.service_stops[0], original.service_stops[0],
                "{case}"
            );
            assert_eq!(
                resume(&paths).await.unwrap()["reason"],
                "operation is terminal",
                "{case}"
            );
        }
    }

    #[test]
    fn owned_idle_label_classification_never_implies_absence() {
        let uid = unsafe { libc::geteuid() };
        let idle =
            format!("gui/{uid}/app.loomex.runner = {{\n\tprogram = /owned/bin/loomex-runner\n}}\n");
        assert_eq!(
            classify_label_output(uid, Some(0), idle.as_bytes(), b""),
            LabelObservation::LoadedIdle {
                program: PathBuf::from("/owned/bin/loomex-runner")
            }
        );
        for output in [
            idle.trim_end_matches("}\n").to_string(),
            idle.replace("\tprogram = /owned/bin/loomex-runner\n", ""),
            idle.replace("}\n", "\tpid = 0\n}\n"),
        ] {
            assert_eq!(
                classify_label_output(uid, Some(0), output.as_bytes(), b""),
                LabelObservation::Unknown
            );
        }
        assert_eq!(
            classify_label_output(uid, Some(0), idle.as_bytes(), b"unconfirmed"),
            LabelObservation::Unknown
        );
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn pending_stop_native_process_inspection_reads_only_this_disposable_test_process_identity() {
        let pid = std::process::id() as i32;
        let ProcessObservation::Present(actual) = inspect_process(pid) else {
            panic!("native self-process metadata unavailable");
        };
        assert_eq!(actual.pid, pid);
        assert_eq!(actual.uid, unsafe { libc::geteuid() });
        assert!(actual.started_seconds > 0);
        assert_eq!(
            actual.executable,
            fs::canonicalize(std::env::current_exe().unwrap()).unwrap()
        );
        assert_eq!(inspect_process(-1), ProcessObservation::Unknown);
    }

    #[tokio::test]
    async fn previous_drained_resume_settles_same_operation_without_restarting_twice() {
        let _serial = TEST_SERIAL.lock().await;
        let temp = tempfile::tempdir().unwrap();
        let paths = paths(temp.path());
        let original = previous_drained_recovery_fixture(&paths);
        TEST_MODE.store(true, Ordering::SeqCst);
        TEST_RESTART_COUNT.store(0, Ordering::SeqCst);
        *TEST_RECOVERY_STATUS.lock().unwrap() =
            Some(json!({"version":"1.2.4","activeJobs":0,"draining":true}));
        let result = resume(&paths).await;
        let repeated = resume(&paths).await;
        let restarts = TEST_RESTART_COUNT.load(Ordering::SeqCst);
        *TEST_RECOVERY_STATUS.lock().unwrap() = None;
        TEST_MODE.store(false, Ordering::SeqCst);
        assert_eq!(result.unwrap()["resumed"], true);
        assert_eq!(repeated.unwrap()["reason"], "operation is terminal");
        let saved: Operation = state::read_json(&paths.operation()).unwrap();
        assert_eq!(saved.id, original.id);
        assert_eq!(saved.phase, "rolled_back");
        assert_eq!(
            fs::read_link(paths.current()).unwrap(),
            original.previous_target.unwrap()
        );
        assert_eq!(fs::read(launch_agent(&paths)).unwrap(), b"previous-plist");
        assert!(!paths.state_dir.join("drain.json").exists());
        assert_eq!(restarts, 1);
    }

    #[tokio::test]
    async fn interrupted_previous_drain_resume_preserves_intent_and_single_restart() {
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
            let original = previous_drained_recovery_fixture(&paths);
            TEST_MODE.store(true, Ordering::SeqCst);
            TEST_RESTART_COUNT.store(0, Ordering::SeqCst);
            *TEST_RECOVERY_STATUS.lock().unwrap() =
                Some(json!({"version":"1.2.4","activeJobs":0,"draining":true}));
            *TEST_RECOVERY_FAULT.lock().unwrap() = Some(stage);
            let failed = resume(&paths).await.unwrap();
            *TEST_RECOVERY_FAULT.lock().unwrap() = None;
            let retained: Operation = state::read_json(&paths.operation()).unwrap();
            let resumed = resume(&paths).await;
            let repeated = resume(&paths).await;
            let restarts = TEST_RESTART_COUNT.load(Ordering::SeqCst);
            *TEST_RECOVERY_STATUS.lock().unwrap() = None;
            TEST_MODE.store(false, Ordering::SeqCst);
            assert_eq!(failed["resumed"], false, "{stage}");
            assert_eq!(retained.id, original.id, "{stage}");
            assert_eq!(retained.phase, "recovery_required", "{stage}");
            assert_eq!(
                retained.checkpoint.as_deref(),
                Some("previous_drain_release_pending"),
                "{stage}"
            );
            assert_eq!(resumed.unwrap()["resumed"], true, "{stage}");
            assert_eq!(
                repeated.unwrap()["reason"],
                "operation is terminal",
                "{stage}"
            );
            assert_eq!(restarts, 1, "{stage}");
            let saved: Operation = state::read_json(&paths.operation()).unwrap();
            assert_eq!(saved.id, original.id);
            assert_eq!(saved.phase, "rolled_back");
            assert!(!paths.state_dir.join("drain.json").exists());
        }
    }

    #[tokio::test]
    async fn previous_drain_recovery_rejects_invalid_proof_before_removal() {
        let _serial = TEST_SERIAL.lock().await;
        for case in [
            "active",
            "wrong_version",
            "missing_count",
            "missing_drain_state",
            "unavailable",
            "tampered",
            "unowned",
            "plist_mismatch",
            "pointer_mismatch",
            "symlink",
            "missing_without_intent",
        ] {
            let temp = tempfile::tempdir().unwrap();
            let paths = paths(temp.path());
            let mut operation = previous_drained_recovery_fixture(&paths);
            let previous = operation.previous_target.clone().unwrap();
            let drain = paths.state_dir.join("drain.json");
            let mut status = json!({"version":"1.2.4","activeJobs":0,"draining":true});
            match case {
                "active" => status["activeJobs"] = json!(1),
                "wrong_version" => status["version"] = json!("1.2.3"),
                "missing_count" => {
                    status.as_object_mut().unwrap().remove("activeJobs");
                }
                "missing_drain_state" => {
                    status.as_object_mut().unwrap().remove("draining");
                }
                "unavailable" => TEST_STATUS_UNAVAILABLE.store(true, Ordering::SeqCst),
                "tampered" => fs::write(previous.join("bin/loomex"), b"tampered").unwrap(),
                "unowned" => operation
                    .resources
                    .as_mut()
                    .unwrap()
                    .owned_versions
                    .retain(|path| path != &previous),
                "plist_mismatch" => fs::write(launch_agent(&paths), b"different").unwrap(),
                "pointer_mismatch" => {
                    fs::remove_file(paths.current()).unwrap();
                    std::os::unix::fs::symlink(paths.versions().join("1.2.3"), paths.current())
                        .unwrap();
                }
                "symlink" => {
                    fs::remove_file(&drain).unwrap();
                    fs::write(temp.path().join("protected"), b"protected").unwrap();
                    std::os::unix::fs::symlink(temp.path().join("protected"), &drain).unwrap();
                }
                "missing_without_intent" => fs::remove_file(&drain).unwrap(),
                _ => unreachable!(),
            }
            let before = fs::symlink_metadata(&drain).is_ok();
            TEST_MODE.store(true, Ordering::SeqCst);
            TEST_RESTART_COUNT.store(0, Ordering::SeqCst);
            *TEST_RECOVERY_STATUS.lock().unwrap() = Some(status);
            let result = release_service_drain(
                &paths,
                &mut operation,
                &previous,
                &state::digest(b"previous-plist"),
                "previous_drain_release_pending",
            )
            .await;
            let restarts = TEST_RESTART_COUNT.load(Ordering::SeqCst);
            *TEST_RECOVERY_STATUS.lock().unwrap() = None;
            TEST_STATUS_UNAVAILABLE.store(false, Ordering::SeqCst);
            TEST_MODE.store(false, Ordering::SeqCst);
            assert!(result.is_err(), "{case}");
            assert_eq!(fs::symlink_metadata(&drain).is_ok(), before, "{case}");
            assert_eq!(restarts, 0, "{case}");
            assert_ne!(
                operation.checkpoint.as_deref(),
                Some("previous_drain_release_pending"),
                "{case}"
            );
            if case == "symlink" {
                assert_eq!(
                    fs::read(temp.path().join("protected")).unwrap(),
                    b"protected"
                );
            }
        }
    }

    #[tokio::test]
    async fn removal_intent_does_not_replace_fresh_daemon_proof() {
        let _serial = TEST_SERIAL.lock().await;
        for case in ["active", "wrong_version", "unavailable"] {
            let temp = tempfile::tempdir().unwrap();
            let paths = paths(temp.path());
            let original = previous_drained_recovery_fixture(&paths);
            TEST_MODE.store(true, Ordering::SeqCst);
            TEST_RESTART_COUNT.store(0, Ordering::SeqCst);
            *TEST_RECOVERY_STATUS.lock().unwrap() =
                Some(json!({"version":"1.2.4","activeJobs":0,"draining":true}));
            *TEST_RECOVERY_FAULT.lock().unwrap() = Some("after_drain_removal");
            let failed = resume(&paths).await.unwrap();
            *TEST_RECOVERY_FAULT.lock().unwrap() = None;
            assert_eq!(failed["resumed"], false);
            assert!(!paths.state_dir.join("drain.json").exists());
            match case {
                "active" => {
                    *TEST_RECOVERY_STATUS.lock().unwrap() =
                        Some(json!({"version":"1.2.4","activeJobs":1,"draining":true}))
                }
                "wrong_version" => {
                    *TEST_RECOVERY_STATUS.lock().unwrap() =
                        Some(json!({"version":"1.2.3","activeJobs":0,"draining":true}))
                }
                "unavailable" => {
                    TEST_STATUS_UNAVAILABLE.store(true, Ordering::SeqCst);
                    TEST_LABEL_PRESENT.store(true, Ordering::SeqCst);
                }
                _ => unreachable!(),
            }
            let resumed = resume(&paths).await;
            let restarts = TEST_RESTART_COUNT.load(Ordering::SeqCst);
            *TEST_RECOVERY_STATUS.lock().unwrap() = None;
            TEST_STATUS_UNAVAILABLE.store(false, Ordering::SeqCst);
            TEST_LABEL_PRESENT.store(false, Ordering::SeqCst);
            TEST_MODE.store(false, Ordering::SeqCst);
            assert_eq!(resumed.unwrap()["resumed"], false, "{case}");
            assert_eq!(restarts, 0, "{case}");
            let saved: Operation = state::read_json(&paths.operation()).unwrap();
            assert_eq!(saved.id, original.id);
            assert_eq!(saved.phase, "recovery_required");
            assert_eq!(
                saved.checkpoint.as_deref(),
                Some("previous_drain_release_pending")
            );
        }
    }

    #[tokio::test]
    async fn unavailable_previous_loaded_service_remains_protected() {
        let _serial = TEST_SERIAL.lock().await;
        let temp = tempfile::tempdir().unwrap();
        let paths = paths(temp.path());
        let original = previous_drained_recovery_fixture(&paths);
        TEST_MODE.store(true, Ordering::SeqCst);
        TEST_STATUS_UNAVAILABLE.store(true, Ordering::SeqCst);
        TEST_LABEL_PRESENT.store(true, Ordering::SeqCst);
        TEST_RESTART_COUNT.store(0, Ordering::SeqCst);
        let result = resume(&paths).await;
        let restarts = TEST_RESTART_COUNT.load(Ordering::SeqCst);
        TEST_STATUS_UNAVAILABLE.store(false, Ordering::SeqCst);
        TEST_LABEL_PRESENT.store(false, Ordering::SeqCst);
        TEST_MODE.store(false, Ordering::SeqCst);
        assert_eq!(result.unwrap()["resumed"], false);
        assert!(paths.state_dir.join("drain.json").exists());
        assert_eq!(restarts, 0);
        let saved: Operation = state::read_json(&paths.operation()).unwrap();
        assert_eq!(saved.id, original.id);
        assert_eq!(saved.phase, "recovery_required");
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
            operation.schema = PRE_AUTH_OPERATION_SCHEMA.into();
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

    fn abandonment_fixture(paths: &Paths) -> (Operation, Value) {
        let mut operation = previous_drained_recovery_fixture(paths);
        operation.phase = "pending_active_work".into();
        operation.checkpoint = Some("daemon_has_active_work".into());
        let resources = operation.resources.as_mut().unwrap();
        let backup = paths
            .state_dir
            .join(format!("lifecycle-agent-{}.plist", operation.id));
        fs::rename(&resources.launch_agent_backup, &backup).unwrap();
        resources.launch_agent_backup = backup;
        resources.staged_launch_agent = paths
            .state_dir
            .join(format!("lifecycle-staged-{}.plist", operation.id));
        fs::write(
            &operation.resources.as_ref().unwrap().staged_launch_agent,
            b"candidate-plist",
        )
        .unwrap();
        save_operation(paths, &operation).unwrap();
        state::write_json(
            &paths.state_dir.join("install-receipt.json"),
            &json!({
                "schema":"app.loomex.runner.install-receipt/v2", "version":"1.2.4",
                "versionPath":paths.versions().join("1.2.4"), "launchAgent":launch_agent(paths)
            }),
        )
        .unwrap();
        let configuration = json!({"schema":"app.loomex.runner.bootstrap-install/v1",
            "version":"1.2.3", "target":paths.versions().join("1.2.3"),
            "manifestSha256":"a".repeat(64), "developmentApiOrigin":"http://127.0.0.1:8001/",
            "providerExecutables":{}});
        state::write_json(
            &paths.state_dir.join("bootstrap-install.json"),
            &configuration,
        )
        .unwrap();
        (operation, configuration)
    }

    #[tokio::test]
    async fn auth_bound_abandonment_keeps_its_private_schema() {
        let _serial = TEST_SERIAL.lock().await;
        let _scope = AbandonmentTestScope::start();
        let temp = tempfile::tempdir().unwrap();
        let paths = paths(temp.path());
        let (mut operation, _) = abandonment_fixture(&paths);
        operation.schema = OPERATION_SCHEMA.into();
        operation.auth_baseline = Some(AuthBaseline::SignedOut {
            installation_id: None,
        });
        save_operation(&paths, &operation).unwrap();
        rollback_with_expected(&paths, "1.2.4", Some(operation.id))
            .await
            .unwrap();
        let saved: Operation = state::read_json(&paths.operation()).unwrap();
        assert_eq!(saved.schema, ABANDONMENT_OPERATION_SCHEMA);
        assert_eq!(saved.auth_baseline, operation.auth_baseline);
        let mut downgraded = saved.clone();
        downgraded.schema = PRE_AUTH_ABANDONMENT_SCHEMA.into();
        assert!(downgraded.validate().is_err());
    }

    struct AbandonmentTestScope;
    impl AbandonmentTestScope {
        fn start() -> Self {
            TEST_ABANDONMENT_RESTART.store(true, Ordering::SeqCst);
            TEST_MODE.store(true, Ordering::SeqCst);
            TEST_LABEL_PRESENT.store(true, Ordering::SeqCst);
            TEST_STOP_COUNT.store(0, Ordering::SeqCst);
            TEST_RESTART_COUNT.store(0, Ordering::SeqCst);
            *TEST_RECOVERY_STATUS.lock().unwrap() =
                Some(json!({"version":"1.2.4","activeJobs":0,"draining":true}));
            Self
        }
    }
    impl Drop for AbandonmentTestScope {
        fn drop(&mut self) {
            TEST_ABANDONMENT_RESTART.store(false, Ordering::SeqCst);
            TEST_BOOTOUT_FAIL.store(false, Ordering::SeqCst);
            TEST_STOP_WAIT_UNCONFIRMED.store(false, Ordering::SeqCst);
            TEST_MODE.store(false, Ordering::SeqCst);
            TEST_LABEL_PRESENT.store(false, Ordering::SeqCst);
            TEST_DELAYED_SERVICE_STOP.store(false, Ordering::SeqCst);
            *TEST_RECOVERY_STATUS.lock().unwrap() = None;
            *TEST_RECOVERY_FAULT.lock().unwrap() = None;
            *TEST_PROCESS_OBSERVATION.lock().unwrap() = None;
        }
    }

    #[tokio::test]
    async fn abandonment_interruption_resumes_same_previous_service_and_tombstone() {
        let _serial = TEST_SERIAL.lock().await;
        for fault in [
            "after_abandonment_intent",
            "after_stop_intent",
            "after_stop_request",
            "after_stop_verified",
            "after_stop_pointer",
            "after_stop_configuration",
            "before_stop_bootstrap",
            "after_stop_bootstrap",
            "before_abandonment_tombstone",
        ] {
            let _scope = AbandonmentTestScope::start();
            let temp = tempfile::tempdir().unwrap();
            let paths = paths(temp.path());
            let (operation, configuration) = abandonment_fixture(&paths);
            let preserved = paths.state_dir.join("unrelated-job-journal-fixture");
            fs::write(&preserved, b"unchanged").unwrap();
            *TEST_RECOVERY_FAULT.lock().unwrap() = Some(fault);
            assert!(
                rollback_with_expected(&paths, "1.2.4", Some(operation.id))
                    .await
                    .is_err(),
                "{fault}"
            );
            let retained: Operation = state::read_json(&paths.operation()).unwrap();
            assert_eq!(retained.id, operation.id);
            assert!(retained.abandonment.is_some());
            *TEST_RECOVERY_FAULT.lock().unwrap() = None;
            let result = resume(&paths).await.unwrap();
            assert_eq!(result["abandoned"], true, "{fault}: {result}");
            let result = resume(&paths).await.unwrap();
            assert_eq!(result["abandoned"], true, "{fault}: {result}");
            assert_eq!(TEST_STOP_COUNT.load(Ordering::SeqCst), 1, "{fault}");
            assert_eq!(TEST_RESTART_COUNT.load(Ordering::SeqCst), 1, "{fault}");
            assert_eq!(
                fs::read_link(paths.current()).unwrap(),
                operation.previous_target.unwrap()
            );
            assert_eq!(fs::read(&preserved).unwrap(), b"unchanged");
            let tombstone: Value =
                state::read_json(&paths.state_dir.join("bootstrap-install.json")).unwrap();
            assert_eq!(tombstone["configuration"], configuration);
            assert_eq!(tombstone["operationId"], operation.id.to_string());
        }
    }

    #[tokio::test]
    async fn abandonment_exact_identity_phase_and_managed_work_fences_have_no_effects() {
        let _serial = TEST_SERIAL.lock().await;
        for case in [
            "missing_uuid",
            "different_uuid",
            "different_previous",
            "advanced_phase",
            "stop_exists",
            "receipt",
            "plist",
            "candidate",
            "inventory",
            "active_work",
            "not_drained",
            "process",
        ] {
            let _scope = AbandonmentTestScope::start();
            let temp = tempfile::tempdir().unwrap();
            let paths = paths(temp.path());
            let (mut operation, _) = abandonment_fixture(&paths);
            let mut expected = Some(operation.id);
            let mut version = "1.2.4";
            match case {
                "missing_uuid" => expected = None,
                "different_uuid" => expected = Some(Uuid::new_v4()),
                "different_previous" => version = "1.2.3",
                "advanced_phase" => {
                    operation.phase = "pointer_switched".into();
                    save_operation(&paths, &operation).unwrap();
                }
                "stop_exists" => {
                    prepare_service_stop(&paths, &mut operation, StopDirection::ActivateCandidate)
                        .await
                        .unwrap();
                }
                "receipt" => state::write_json(
                    &paths.state_dir.join("install-receipt.json"),
                    &json!({"version":"1.2.3"}),
                )
                .unwrap(),
                "plist" => fs::write(launch_agent(&paths), b"changed").unwrap(),
                "candidate" => {
                    fs::write(paths.versions().join("1.2.3/bin/loomex"), b"changed").unwrap()
                }
                "inventory" => {
                    fs::remove_file(paths.state_dir.join("owned-versions.json")).unwrap()
                }
                "active_work" => {
                    TEST_RECOVERY_STATUS.lock().unwrap().as_mut().unwrap()["activeJobs"] = json!(1)
                }
                "not_drained" => {
                    TEST_RECOVERY_STATUS.lock().unwrap().as_mut().unwrap()["draining"] =
                        json!(false)
                }
                "process" => {
                    *TEST_PROCESS_OBSERVATION.lock().unwrap() = Some(ProcessObservation::Unknown)
                }
                _ => unreachable!(),
            }
            let before = fs::read(paths.operation()).unwrap();
            assert!(
                rollback_with_expected(&paths, version, expected)
                    .await
                    .is_err(),
                "{case}"
            );
            // Process proof is checked again after durable intent; all other
            // rejected initial bindings leave the original journal untouched.
            if case != "process" {
                assert_eq!(fs::read(paths.operation()).unwrap(), before, "{case}");
            }
            assert_eq!(TEST_STOP_COUNT.load(Ordering::SeqCst), 0, "{case}");
            assert_eq!(TEST_RESTART_COUNT.load(Ordering::SeqCst), 0, "{case}");
            assert_eq!(
                fs::read_link(paths.current()).unwrap(),
                paths.versions().join("1.2.4")
            );
        }
    }

    #[tokio::test]
    async fn abandonment_bootstrap_retry_is_tombstoned_and_corrected_intent_requires_exact_ack() {
        let _serial = TEST_SERIAL.lock().await;
        let _scope = AbandonmentTestScope::start();
        let temp = tempfile::tempdir().unwrap();
        let paths = paths(temp.path());
        let (operation, configuration) = abandonment_fixture(&paths);
        rollback_with_expected(&paths, "1.2.4", Some(operation.id))
            .await
            .unwrap();
        let _lock = LifecycleLock::acquire(&paths).unwrap();
        for ack in [None, Some(operation.id)] {
            let receipt = reconcile_bootstrap_abandonment_locked(&paths, &configuration, ack)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(receipt["abandoned"], true);
        }
        let mut corrected = configuration.clone();
        corrected["developmentApiOrigin"] = json!("http://127.0.0.1:28080/");
        assert!(
            reconcile_bootstrap_abandonment_locked(&paths, &corrected, None)
                .await
                .is_err()
        );
        assert!(
            reconcile_bootstrap_abandonment_locked(&paths, &corrected, Some(Uuid::new_v4()))
                .await
                .is_err()
        );
        assert!(
            reconcile_bootstrap_abandonment_locked(&paths, &corrected, Some(operation.id))
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(
            preflight_package_locked(
                &paths,
                OperationKind::Update,
                operation.package.clone().unwrap()
            )
            .await
            .unwrap()["reconciled"],
            false
        );
        assert!(
            reconcile_bootstrap_abandonment_locked(&paths, &configuration, None)
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            preflight_package_locked(
                &paths,
                OperationKind::Update,
                operation.package.clone().unwrap()
            )
            .await
            .is_err()
        );
        assert_eq!(TEST_STOP_COUNT.load(Ordering::SeqCst), 1);
        assert_eq!(TEST_RESTART_COUNT.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn abandonment_corrected_same_package_stages_fresh_uuid_without_replaying_old_update() {
        let _serial = TEST_SERIAL.lock().await;
        let _scope = AbandonmentTestScope::start();
        let temp = tempfile::tempdir().unwrap();
        let paths = paths(temp.path());
        let (operation, configuration) = abandonment_fixture(&paths);
        rollback_with_expected(&paths, "1.2.4", Some(operation.id))
            .await
            .unwrap();
        let _lock = LifecycleLock::acquire(&paths).unwrap();
        let mut corrected = configuration.clone();
        corrected["developmentApiOrigin"] = json!("http://127.0.0.1:28080/");
        assert!(
            reconcile_bootstrap_abandonment_locked(&paths, &corrected, Some(operation.id))
                .await
                .unwrap()
                .is_none()
        );
        let staged = paths.state_dir.join("new-corrected-config.plist");
        fs::write(&staged, b"corrected-candidate-plist").unwrap();
        TEST_DRAIN_HAS_ACTIVE_WORK.store(true, Ordering::SeqCst);
        let package = operation.package.unwrap();
        let result = activate_locked(
            &paths,
            package.target,
            package.version,
            package.manifest_sha256,
            staged,
        )
        .await;
        TEST_DRAIN_HAS_ACTIVE_WORK.store(false, Ordering::SeqCst);
        assert_eq!(result.unwrap()["pending"], true);
        let fresh: Operation = state::read_json(&paths.operation()).unwrap();
        assert_ne!(fresh.id, operation.id);
        assert_eq!(fresh.kind, OperationKind::Update);
        assert_eq!(fresh.phase, "pending_active_work");
        assert!(fresh.abandonment.is_none());
        assert!(
            reconcile_bootstrap_abandonment_locked(&paths, &corrected, Some(operation.id))
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            reconcile_bootstrap_abandonment_locked(&paths, &configuration, None)
                .await
                .is_err()
        );
        assert_eq!(
            fs::read_link(paths.current()).unwrap(),
            paths.versions().join("1.2.4")
        );
        assert_eq!(TEST_STOP_COUNT.load(Ordering::SeqCst), 1);
    }

    fn replace_fixture_previous_catalog(paths: &Paths) {
        let target = paths.versions().join("1.2.4");
        let relative = "metadata/compatibility-manifest.json";
        let manifest =
            include_bytes!("../tests/fixtures/lifecycle-retained-0.3.64-compatibility.json");
        fs::write(target.join(relative), manifest).unwrap();
        let inventory_path = paths.state_dir.join("owned-versions.json");
        let mut inventory: Value = state::read_json(&inventory_path).unwrap();
        let entry = inventory["inventories"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|entry| entry["path"] == json!(target))
            .unwrap();
        let file = entry["files"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|file| file["path"] == relative)
            .unwrap();
        file["sha256"] = json!(state::digest(manifest));
        file["size"] = json!(manifest.len());
        state::write_json(&inventory_path, &inventory).unwrap();
    }

    #[test]
    fn abandonment_catalog_exception_is_production_scoped_to_current_captured_immutable_package() {
        let temp = tempfile::tempdir().unwrap();
        let paths = paths(temp.path());
        let (operation, _) = abandonment_fixture(&paths);
        let previous = paths.versions().join("1.2.4");
        replace_fixture_previous_catalog(&paths);
        // These pure production predicates do not use TEST_MODE or fake daemon
        // observations. The differing manifest is the real retained .64 export.
        validate_abandonment_current_previous(&paths, &operation, &previous, "1.2.4").unwrap();
        let ordinary = validate_rollback_target(&previous, "1.2.4").unwrap_err();
        assert_eq!(
            crate::control::public_error(&ordinary).0,
            "LIFECYCLE_ROLLBACK_COMPATIBILITY_MISMATCH"
        );
        fs::write(
            previous.join("metadata/compatibility-manifest.json"),
            b"tampered",
        )
        .unwrap();
        let tampered =
            validate_abandonment_current_previous(&paths, &operation, &previous, "1.2.4")
                .unwrap_err();
        assert_eq!(
            crate::control::public_error(&tampered).0,
            "LIFECYCLE_ABANDONMENT_PREVIOUS_INVENTORY_MISMATCH"
        );
        replace_fixture_previous_catalog(&paths);
        fs::remove_file(paths.current()).unwrap();
        std::os::unix::fs::symlink(paths.versions().join("1.2.3"), paths.current()).unwrap();
        let noncurrent =
            validate_abandonment_current_previous(&paths, &operation, &previous, "1.2.4")
                .unwrap_err();
        assert_eq!(
            crate::control::public_error(&noncurrent).0,
            "LIFECYCLE_ABANDONMENT_CURRENT_TARGET_MISMATCH"
        );
        assert_eq!(operation.phase, "pending_active_work");
        assert!(
            state::read_json::<Operation>(&paths.operation())
                .unwrap()
                .abandonment
                .is_none()
        );
    }

    #[tokio::test]
    async fn abandonment_current_captured_previous_with_different_real_catalog_is_restored() {
        let _serial = TEST_SERIAL.lock().await;
        let _scope = AbandonmentTestScope::start();
        let temp = tempfile::tempdir().unwrap();
        let paths = paths(temp.path());
        let (operation, _) = abandonment_fixture(&paths);
        replace_fixture_previous_catalog(&paths);
        assert!(validate_rollback_target(&paths.versions().join("1.2.4"), "1.2.4").is_err());
        let result = rollback_with_expected(&paths, "1.2.4", Some(operation.id)).await;
        assert!(
            result.is_ok(),
            "exact already-current retained package must restore despite newer catalog: {result:?}"
        );
        assert_eq!(result.unwrap()["abandoned"], true);
        assert_eq!(
            fs::read_link(paths.current()).unwrap(),
            paths.versions().join("1.2.4")
        );
        assert_eq!(TEST_STOP_COUNT.load(Ordering::SeqCst), 1);
        assert_eq!(TEST_RESTART_COUNT.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn abandonment_definitive_spawn_failure_resets_exact_stop_and_retries_safely() {
        let _serial = TEST_SERIAL.lock().await;
        let _scope = AbandonmentTestScope::start();
        let temp = tempfile::tempdir().unwrap();
        let paths = paths(temp.path());
        let (operation, _) = abandonment_fixture(&paths);
        TEST_BOOTOUT_FAIL.store(true, Ordering::SeqCst);
        assert!(
            rollback_with_expected(&paths, "1.2.4", Some(operation.id))
                .await
                .is_err()
        );
        let failed: Operation = state::read_json(&paths.operation()).unwrap();
        assert_eq!(failed.id, operation.id);
        assert_eq!(failed.service_stops.len(), 1);
        assert_eq!(failed.service_stops[0].request, StopRequest::Prepared);
        assert_eq!(
            failed.checkpoint.as_deref(),
            Some("service_stop_intent_prepared")
        );
        assert_eq!(TEST_RESTART_COUNT.load(Ordering::SeqCst), 0);
        assert!(TEST_LABEL_PRESENT.load(Ordering::SeqCst));
        TEST_BOOTOUT_FAIL.store(false, Ordering::SeqCst);
        assert_eq!(resume(&paths).await.unwrap()["abandoned"], true);
        assert_eq!(resume(&paths).await.unwrap()["abandoned"], true);
        assert_eq!(TEST_STOP_COUNT.load(Ordering::SeqCst), 2); // one undispatched attempt, one accepted stop
        assert_eq!(TEST_RESTART_COUNT.load(Ordering::SeqCst), 1);
        let completed: Operation = state::read_json(&paths.operation()).unwrap();
        assert_eq!(completed.service_stops.len(), 1);
        assert_eq!(
            completed.service_stops[0].process,
            failed.service_stops[0].process
        );
    }

    #[tokio::test]
    async fn abandonment_failed_spawn_reset_and_postspawn_wait_uncertainty_never_redispatch() {
        let _serial = TEST_SERIAL.lock().await;
        for case in ["reset_interrupted", "postspawn_wait"] {
            let _scope = AbandonmentTestScope::start();
            let temp = tempfile::tempdir().unwrap();
            let paths = paths(temp.path());
            let (operation, _) = abandonment_fixture(&paths);
            if case == "reset_interrupted" {
                TEST_BOOTOUT_FAIL.store(true, Ordering::SeqCst);
                *TEST_RECOVERY_FAULT.lock().unwrap() =
                    Some("before_stop_not_dispatched_checkpoint");
                assert!(
                    rollback_with_expected(&paths, "1.2.4", Some(operation.id))
                        .await
                        .is_err()
                );
            } else {
                TEST_STOP_WAIT_UNCONFIRMED.store(true, Ordering::SeqCst);
                assert_eq!(
                    rollback_with_expected(&paths, "1.2.4", Some(operation.id))
                        .await
                        .unwrap()["pending"],
                    true
                );
            }
            TEST_BOOTOUT_FAIL.store(false, Ordering::SeqCst);
            TEST_STOP_WAIT_UNCONFIRMED.store(false, Ordering::SeqCst);
            *TEST_RECOVERY_FAULT.lock().unwrap() = None;
            let retained: Operation = state::read_json(&paths.operation()).unwrap();
            assert_eq!(retained.service_stops[0].request, StopRequest::Unconfirmed);
            for _ in 0..2 {
                assert_eq!(resume(&paths).await.unwrap()["pending"], true);
            }
            assert_eq!(TEST_STOP_COUNT.load(Ordering::SeqCst), 1, "{case}");
            assert_eq!(TEST_RESTART_COUNT.load(Ordering::SeqCst), 0, "{case}");
            assert_eq!(
                fs::read_link(paths.current()).unwrap(),
                paths.versions().join("1.2.4")
            );
        }
    }

    #[tokio::test]
    async fn abandonment_ambiguous_stop_dispatch_is_observation_only_and_new_work_blocks_stop() {
        let _serial = TEST_SERIAL.lock().await;
        let _scope = AbandonmentTestScope::start();
        let temp = tempfile::tempdir().unwrap();
        let paths = paths(temp.path());
        let (operation, _) = abandonment_fixture(&paths);
        *TEST_RECOVERY_FAULT.lock().unwrap() = Some("after_abandonment_intent");
        assert!(
            rollback_with_expected(&paths, "1.2.4", Some(operation.id))
                .await
                .is_err()
        );
        *TEST_RECOVERY_FAULT.lock().unwrap() = None;
        TEST_RECOVERY_STATUS.lock().unwrap().as_mut().unwrap()["activeJobs"] = json!(1);
        assert!(resume(&paths).await.is_err());
        assert_eq!(TEST_STOP_COUNT.load(Ordering::SeqCst), 0);
        TEST_RECOVERY_STATUS.lock().unwrap().as_mut().unwrap()["activeJobs"] = json!(0);
        *TEST_RECOVERY_FAULT.lock().unwrap() = Some("after_abandonment_stop_dispatch_intent");
        assert!(resume(&paths).await.is_err());
        *TEST_RECOVERY_FAULT.lock().unwrap() = None;
        let pending = resume(&paths).await.unwrap();
        assert_eq!(pending["pending"], true);
        assert_eq!(TEST_STOP_COUNT.load(Ordering::SeqCst), 0);
        assert_eq!(TEST_RESTART_COUNT.load(Ordering::SeqCst), 0);
        TEST_LABEL_PRESENT.store(false, Ordering::SeqCst);
        assert_eq!(resume(&paths).await.unwrap()["abandoned"], true);
        assert_eq!(TEST_STOP_COUNT.load(Ordering::SeqCst), 0);
        assert_eq!(TEST_RESTART_COUNT.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn abandonment_successor_intent_interruption_requires_explicit_ack_and_exact_config() {
        let _serial = TEST_SERIAL.lock().await;
        let _scope = AbandonmentTestScope::start();
        let temp = tempfile::tempdir().unwrap();
        let paths = paths(temp.path());
        let (operation, configuration) = abandonment_fixture(&paths);
        rollback_with_expected(&paths, "1.2.4", Some(operation.id))
            .await
            .unwrap();
        let _lock = LifecycleLock::acquire(&paths).unwrap();
        let mut corrected = configuration.clone();
        corrected["developmentApiOrigin"] = json!("http://127.0.0.1:28080/");
        *TEST_RECOVERY_FAULT.lock().unwrap() = Some("after_abandonment_successor_intent");
        assert!(
            reconcile_bootstrap_abandonment_locked(&paths, &corrected, Some(operation.id))
                .await
                .is_err()
        );
        *TEST_RECOVERY_FAULT.lock().unwrap() = None;
        assert!(
            preflight_package_locked(
                &paths,
                OperationKind::Update,
                operation.package.clone().unwrap()
            )
            .await
            .is_err()
        );
        assert!(
            reconcile_bootstrap_abandonment_locked(&paths, &corrected, None)
                .await
                .is_err()
        );
        assert!(
            reconcile_bootstrap_abandonment_locked(&paths, &corrected, Some(operation.id))
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(
            preflight_package_locked(
                &paths,
                OperationKind::Update,
                operation.package.clone().unwrap()
            )
            .await
            .unwrap()["reconciled"],
            false
        );
        // The original configuration can revoke a not-yet-consumed corrected
        // intent; it cannot regain activation authority itself.
        assert!(
            reconcile_bootstrap_abandonment_locked(&paths, &configuration, None)
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            preflight_package_locked(&paths, OperationKind::Update, operation.package.unwrap())
                .await
                .is_err()
        );
        assert_eq!(TEST_STOP_COUNT.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn abandonment_changed_operation_and_native_identity_cannot_resume_or_activate() {
        let _serial = TEST_SERIAL.lock().await;
        for case in [
            "uuid",
            "package",
            "receipt",
            "process",
            "v2_downgrade",
            "missing_intent",
            "lock",
        ] {
            let _scope = AbandonmentTestScope::start();
            let temp = tempfile::tempdir().unwrap();
            let paths = paths(temp.path());
            let (operation, _) = abandonment_fixture(&paths);
            *TEST_RECOVERY_FAULT.lock().unwrap() = Some("after_abandonment_intent");
            assert!(
                rollback_with_expected(&paths, "1.2.4", Some(operation.id))
                    .await
                    .is_err()
            );
            *TEST_RECOVERY_FAULT.lock().unwrap() = None;
            let mut retained: Operation = state::read_json(&paths.operation()).unwrap();
            let mut lock = None;
            match case {
                "uuid" => retained.id = Uuid::new_v4(),
                "package" => retained.package.as_mut().unwrap().manifest_sha256 = "b".repeat(64),
                "receipt" => {
                    fs::write(paths.state_dir.join("install-receipt.json"), b"changed").unwrap()
                }
                "process" => {
                    let mut process = retained.abandonment.as_ref().unwrap().process.clone();
                    process.started_seconds += 1;
                    *TEST_PROCESS_OBSERVATION.lock().unwrap() =
                        Some(ProcessObservation::Present(process));
                }
                "v2_downgrade" => retained.schema = PRE_AUTH_OPERATION_SCHEMA.into(),
                "missing_intent" => retained.abandonment = None,
                "lock" => lock = Some(LifecycleLock::acquire(&paths).unwrap()),
                _ => unreachable!(),
            }
            if matches!(case, "uuid" | "package" | "v2_downgrade" | "missing_intent") {
                state::write_json(&paths.operation(), &retained).unwrap();
            }
            assert!(resume(&paths).await.is_err(), "{case}");
            assert_eq!(TEST_STOP_COUNT.load(Ordering::SeqCst), 0);
            assert_eq!(TEST_RESTART_COUNT.load(Ordering::SeqCst), 0);
            assert_eq!(
                fs::read_link(paths.current()).unwrap(),
                paths.versions().join("1.2.4")
            );
            drop(lock);
        }
    }

    #[tokio::test]
    async fn explicit_pending_update_abandonment_restores_previous_without_candidate_activation() {
        let _serial = TEST_SERIAL.lock().await;
        let temp = tempfile::tempdir().unwrap();
        let paths = paths(temp.path());
        let mut operation = previous_drained_recovery_fixture(&paths);
        operation.phase = "pending_active_work".into();
        operation.checkpoint = Some("daemon_has_active_work".into());
        fs::write(
            &operation.resources.as_ref().unwrap().staged_launch_agent,
            b"candidate-plist",
        )
        .unwrap();
        save_operation(&paths, &operation).unwrap();
        state::write_json(
            &paths.state_dir.join("install-receipt.json"),
            &json!({
                "schema":"app.loomex.runner.install-receipt/v2", "version":"1.2.4",
                "versionPath":paths.versions().join("1.2.4"), "launchAgent":launch_agent(&paths)
            }),
        )
        .unwrap();
        let configuration = json!({"schema":"app.loomex.runner.bootstrap-install/v1",
            "version":"1.2.3", "target":paths.versions().join("1.2.3"),
            "manifestSha256":"a".repeat(64), "developmentApiOrigin":"http://127.0.0.1:8001/",
            "providerExecutables":{}});
        state::write_json(
            &paths.state_dir.join("bootstrap-install.json"),
            &configuration,
        )
        .unwrap();
        TEST_ABANDONMENT_RESTART.store(true, Ordering::SeqCst);
        TEST_MODE.store(true, Ordering::SeqCst);
        TEST_LABEL_PRESENT.store(true, Ordering::SeqCst);
        *TEST_RECOVERY_STATUS.lock().unwrap() =
            Some(json!({"version":"1.2.4","activeJobs":0,"draining":true}));
        let result = rollback_with_expected(&paths, "1.2.4", Some(operation.id)).await;
        TEST_ABANDONMENT_RESTART.store(false, Ordering::SeqCst);
        TEST_MODE.store(false, Ordering::SeqCst);
        TEST_LABEL_PRESENT.store(false, Ordering::SeqCst);
        *TEST_RECOVERY_STATUS.lock().unwrap() = None;
        assert!(
            result.is_ok(),
            "explicit abandonment must be supported: {result:?}"
        );
        assert_eq!(
            fs::read_link(paths.current()).unwrap(),
            paths.versions().join("1.2.4")
        );
        let saved: Operation = state::read_json(&paths.operation()).unwrap();
        assert_eq!(saved.id, operation.id);
        assert_eq!(saved.phase, "rolled_back");
        assert!(
            saved
                .service_stops
                .iter()
                .all(|stop| stop.direction == StopDirection::RestorePrevious)
        );
        let tombstone: Value =
            state::read_json(&paths.state_dir.join("bootstrap-install.json")).unwrap();
        assert_eq!(tombstone["phase"], "aborted");
        assert_eq!(tombstone["operationId"], operation.id.to_string());
        assert_eq!(tombstone["configuration"], configuration);
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
        operation.schema = PRE_AUTH_OPERATION_SCHEMA.into();
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
        assert_eq!(NATIVE_EXECUTABLES, ["/bin/launchctl"]);
        let paths = paths(temp.path());
        let _scope = StopTestScope::start();
        let previous = previous_drained_recovery_fixture(&paths)
            .previous_target
            .unwrap();
        fs::remove_file(paths.operation()).unwrap();
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
        assert_eq!(fs::read_link(paths.current()).unwrap(), previous);
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
        std::os::unix::fs::symlink(&previous, paths.current()).unwrap();
        let agent = launch_agent(&paths);
        fs::write(&agent, b"old-plist").unwrap();
        let backup = paths.state_dir.join("agent-before.plist");
        state::atomic_write(&backup, b"old-plist").unwrap();
        let staged = temp.path().join("candidate.plist");
        fs::write(&staged, b"candidate-plist").unwrap();
        let mut operation = Operation::new(OperationKind::Update, "service_stopped", None);
        operation.schema = PRE_AUTH_OPERATION_SCHEMA.into();
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
    async fn persona_records_survive_feature_floor_lifecycle_and_pending_recovery_refuses() {
        use crate::{api::Api, auth::Auth, control::Daemon};
        use base64::Engine;
        let _serial = TEST_SERIAL.lock().await;
        struct TestScope;
        impl Drop for TestScope {
            fn drop(&mut self) {
                TEST_MODE.store(false, Ordering::SeqCst);
                *TEST_AUTH_STATUS.lock().unwrap() = None;
                *TEST_RECOVERY_STATUS.lock().unwrap() = None;
            }
        }
        let _scope = TestScope;
        let temp = tempfile::tempdir().unwrap();
        let paths = paths(temp.path());
        make_compatible_version(&paths, "0.3.78");
        make_compatible_version(&paths, "0.4.0");
        symlink(paths.versions().join("0.3.78"), paths.current()).unwrap();
        fs::write(launch_agent(&paths), b"persona-floor-plist").unwrap();
        let org = "10000000-0000-4000-8000-000000000001";
        let runner = "10000000-0000-4000-8000-000000000002";
        let api = Api::for_test_origin("http://127.0.0.1:9").unwrap();
        let auth = Auth::test_persona_lifecycle_fixture(api.clone(), org, runner, false);
        let protected = auth.test_persona_lifecycle_fingerprint(org);
        assert_eq!(
            protected["grantPhases"],
            json!(["grant_pending", "refresh_pending"])
        );
        let daemon = Daemon::new(paths.state_dir.clone(), api.clone(), auth.clone()).unwrap();
        daemon.public.lock().await.active_organization = Some(org.into());
        let person = Uuid::new_v4();
        let conversation = Uuid::new_v4();
        let chat = Uuid::new_v4();
        let context = json!({"personId":person,"organizationId":org,"conversationId":conversation,"chatId":chat,"configDigest":"a".repeat(64)});
        let session = daemon.presentation.dispatch(org, runner, "presentation.sessions.create", &json!({"kind":"personas","entityType":"catalog","entityId":Uuid::nil(),"state":{"personas":{"personId":person,"organizationId":org,"context":context}},"idempotencyKey":Uuid::new_v4()})).unwrap();
        let session_params = json!({"viewSessionId":session["viewSessionId"]});
        let session_before = daemon
            .presentation
            .dispatch(org, runner, "presentation.sessions.get", &session_params)
            .unwrap();
        let identity = format!("persona:{conversation}");
        let mut continuation = context.clone();
        continuation["kind"] = json!("persona_chat");
        let delivery_before = daemon
            .presentation
            .register_delivery(org, runner, &identity, &continuation)
            .unwrap();
        let response_id = Uuid::new_v4();
        let response_path = paths
            .state_dir
            .join("responses")
            .join(format!("{response_id}.json"));
        let response_bytes = serde_json::to_vec(
            &json!({"result":{"content":"synthetic English memory ".repeat(50_000)}}),
        )
        .unwrap();
        state::atomic_write(&response_path, &response_bytes).unwrap();
        let response_digest = state::digest(&response_bytes);
        state::atomic_write(
            &response_path.with_extension("sha256"),
            response_digest.as_bytes(),
        )
        .unwrap();
        let owner = json!({"organizationId":org,"accountSubject":runner});
        state::write_json(
            &response_path.with_extension("meta.json"),
            &json!({"executionId":null,"lastAccessAt":state::now(),"ownerScope":owner}),
        )
        .unwrap();
        let workspace = temp.path().join("workspace");
        fs::create_dir(&workspace).unwrap();
        daemon
            .dispatch(
                "workspaces.grant",
                json!({"workspacePath":workspace,"idempotencyKey":Uuid::new_v4()}),
            )
            .await
            .unwrap();
        let preparation = Uuid::new_v4();
        let version = Uuid::new_v4();
        let confirmation = Uuid::new_v4();
        let providers = crate::control::provider_snapshot().unwrap();
        let binding = json!({"workflowId":Uuid::new_v4(),"versionId":version,"organizationId":org,"runnerId":runner,"installationId":protected["installationId"],"workspacePath":workspace,"personaMemoryContract":"ai.persona-memory/v1","workflowClosure":[{"workflowVersionId":version,"nodeDependencies":{"person":{"node":{"type":"person","config":{"_memoryContext":{"enabled":true,"bridge":{"schemaVersion":"ai.persona-memory/v1","required":true}}}},"modelResolution":{"provider":"codex"},"personId":person,"configDigest":"a".repeat(64)}}}]});
        let binding_digest = state::json_digest(&binding);
        let review = json!({"preparationId":preparation,"bindingDigest":binding_digest,"binding":binding,"limits":{},"expiresAt":null,"confirmationKey":confirmation});
        let prep_path = paths
            .state_dir
            .join("preparations")
            .join(format!("{preparation}.json"));
        state::write_json(&prep_path, &json!({"operation":"runs.prepare","organizationId":org,"accountSubject":runner,"installationId":protected["installationId"],"workspacePath":workspace,"bindingDigest":binding_digest,"binding":binding,"confirmationKey":confirmation,"providers":providers,"review":review})).unwrap();
        let key = Uuid::new_v4();
        let params = json!({"personId":person,"idempotencyKey":key});
        let account_subject = auth.credential(org).await.unwrap().subject;
        assert_eq!(account_subject, runner);
        // Match the account-scoped dispatch journal identity and pending shape.
        let journal_key = state::json_digest(
            &json!({"organizationId":org,"accountSubject":account_subject,"idempotencyKey":key}),
        );
        let pending_digest = state::json_digest(
            &json!({"method":"personas.chat_context.create","params":params,"organizationId":org,"accountSubject":account_subject}),
        );
        let pending_receipt = json!({"digest":pending_digest,"method":"personas.chat_context.create","status":"pending"});
        let pending_path = paths
            .state_dir
            .join("operations")
            .join(format!("{journal_key}.json"));
        assert_ne!(journal_key, key.to_string());
        for (scoped_org, scoped_subject) in [("another-org", runner), (org, "another-account")] {
            assert_ne!(
                journal_key,
                state::json_digest(
                    &json!({"organizationId":scoped_org,"accountSubject":scoped_subject,"idempotencyKey":key})
                )
            );
        }
        state::write_json(&pending_path, &pending_receipt).unwrap();
        assert_eq!(
            state::read_json::<Value>(&pending_path).unwrap(),
            pending_receipt
        );
        let memory_job = Uuid::new_v4();
        let memory_call = Uuid::new_v4();
        let memory_digest = state::json_digest(
            &json!({"jobId":memory_job,"operation":"write","arguments":{"content":"synthetic English fact"},"callId":memory_call}),
        );
        let memory_path = paths
            .state_dir
            .join("jobs")
            .join(memory_job.to_string())
            .join(format!("memory-call-{memory_call}.json"));
        state::write_json(
            &memory_path,
            &json!({"digest":memory_digest,"status":"pending"}),
        )
        .unwrap();
        let preserved = [&response_path, &prep_path, &pending_path, &memory_path]
            .map(|path| (path.clone(), state::digest(&fs::read(path).unwrap())));
        TEST_MODE.store(true, Ordering::SeqCst);
        *TEST_AUTH_STATUS.lock().unwrap() = Some(auth.status().await.unwrap());
        for (step, target) in [
            ("activate", "0.4.0"),
            ("rollback", "0.3.78"),
            ("forward", "0.4.0"),
        ] {
            if step == "rollback" {
                assert_eq!(rollback(&paths, target).await.unwrap()["rolledBack"], true);
            } else {
                let staged = temp.path().join(format!("{step}.plist"));
                fs::write(&staged, b"persona-floor-plist").unwrap();
                activate(
                    &paths,
                    paths.versions().join(target),
                    target.into(),
                    installed_tree_digest(&paths.versions().join(target)).unwrap(),
                    staged,
                )
                .await
                .unwrap();
            }
            assert_eq!(
                fs::read_link(paths.current()).unwrap(),
                paths.versions().join(target)
            );
            assert_eq!(
                resume(&paths).await.unwrap()["operation"]["phase"],
                "completed"
            );
            assert_eq!(auth.test_persona_lifecycle_fingerprint(org), protected);
            for (path, digest) in &preserved {
                assert_eq!(&state::digest(&fs::read(path).unwrap()), digest);
            }
            assert_eq!(
                daemon
                    .presentation
                    .dispatch(org, runner, "presentation.sessions.get", &session_params)
                    .unwrap(),
                session_before
            );
            assert_eq!(
                daemon
                    .presentation
                    .dispatch(
                        org,
                        runner,
                        "presentation.delivery.get",
                        &json!({"identity":identity})
                    )
                    .unwrap(),
                delivery_before
            );
            let page = daemon
                .dispatch(
                    "responses.read",
                    json!({"responseRef":response_id,"offset":0,"limit":123}),
                )
                .await
                .unwrap();
            assert_eq!(page["checksumSha256"], response_digest);
            assert_eq!(page["sizeBytes"], response_bytes.len());
            assert_eq!(
                base64::engine::general_purpose::STANDARD
                    .decode(page["dataBase64"].as_str().unwrap())
                    .unwrap(),
                response_bytes[..123]
            );
            assert_eq!(
                state::read_json::<Value>(&response_path.with_extension("meta.json")).unwrap()["ownerScope"],
                owner
            );
            let prepared = daemon
                .dispatch("preparations.get", json!({"preparationId":preparation}))
                .await
                .unwrap();
            assert_eq!(prepared["status"], "valid");
            assert_eq!(
                state::read_json::<Value>(&prep_path).unwrap()["binding"],
                binding
            );
            assert_eq!(
                state::read_json::<Value>(&pending_path).unwrap(),
                pending_receipt
            );
            assert_eq!(
                state::read_json::<Value>(&memory_path).unwrap()["status"],
                "pending"
            );
        }
        // Underlying proof-bound refresh recovery fences another transition;
        // Persona journal state itself remains intact and is never serialized
        // into evidence or sent through the native credential store.
        let recovery = Auth::test_persona_lifecycle_fixture(api, org, runner, true);
        let recovery_before = recovery.test_persona_lifecycle_fingerprint(org);
        *TEST_AUTH_STATUS.lock().unwrap() = Some(recovery.status().await.unwrap());
        let pointer_before = fs::read_link(paths.current()).unwrap();
        assert!(
            rollback(&paths, "0.3.78")
                .await
                .unwrap_err()
                .to_string()
                .contains("prior authentication recovery is pending")
        );
        assert_eq!(fs::read_link(paths.current()).unwrap(), pointer_before);
        assert_eq!(
            recovery.test_persona_lifecycle_fingerprint(org),
            recovery_before
        );
        for (path, digest) in &preserved {
            assert_eq!(&state::digest(&fs::read(path).unwrap()), digest);
        }
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

    fn prune_fixture() -> (tempfile::TempDir, Paths) {
        let temp = tempfile::tempdir().unwrap();
        let paths = paths(temp.path());
        for version in ["1.2.3", "1.2.4", "1.2.5"] {
            make_compatible_version(&paths, version);
        }
        symlink(paths.versions().join("1.2.3"), paths.current()).unwrap();
        fs::write(launch_agent(&paths), b"prune-fixture-plist").unwrap();
        state::write_json(
            &paths.state_dir.join("install-receipt.json"),
            &json!({"version":"1.2.3","versionPath":paths.versions().join("1.2.3")}),
        )
        .unwrap();
        *TEST_RECOVERY_STATUS.lock().unwrap() =
            Some(json!({"version":"1.2.3","activeJobs":0,"draining":false}));
        TEST_MODE.store(true, Ordering::SeqCst);
        TEST_RESTART_COUNT.store(0, Ordering::SeqCst);
        (temp, paths)
    }

    fn reset_prune_fixture() {
        TEST_MODE.store(false, Ordering::SeqCst);
        *TEST_RECOVERY_STATUS.lock().unwrap() = None;
        TEST_PRUNE_IN_USE.lock().unwrap().clear();
        *TEST_PRUNE_FAULT.lock().unwrap() = None;
    }

    #[tokio::test]
    async fn prune_is_resumable_at_every_destructive_boundary() {
        let _serial = TEST_SERIAL.lock().await;
        for fault in [
            "after_plan",
            "after_drain_before_checkpoint",
            "after_drain_checkpoint",
            "after_move",
            "during_delete",
            "after_delete",
            "before_metadata",
            "after_metadata",
            "before_drain_release",
            "after_drain_removal",
            "after_restart",
            "before_journal_clear",
        ] {
            let (_temp, paths) = prune_fixture();
            *TEST_PRUNE_FAULT.lock().unwrap() = Some(fault);
            let first = prune(&paths, &["1.2.5".into()], &["1.2.4".into()]).await;
            assert!(first.is_err(), "fault {fault} should interrupt");
            assert!(
                paths.operation().exists(),
                "fault {fault} lost recovery journal"
            );
            *TEST_PRUNE_FAULT.lock().unwrap() = None;
            let result = resume(&paths).await.unwrap();
            assert_eq!(result["completed"], true, "fault {fault}");
            assert!(
                !paths.operation().exists(),
                "fault {fault} retained new-schema journal"
            );
            assert!(
                !paths.state_dir.join("drain.json").exists(),
                "fault {fault} retained drain"
            );
            assert_eq!(
                TEST_RECOVERY_STATUS.lock().unwrap().as_ref().unwrap()["draining"],
                false
            );
            assert_eq!(
                TEST_RESTART_COUNT.load(Ordering::SeqCst),
                1,
                "fault {fault} repeated or skipped service restart"
            );
            assert!(!paths.versions().join("1.2.5").exists());
            assert!(paths.versions().join("1.2.3").exists());
            assert!(paths.versions().join("1.2.4").exists());
            assert_eq!(owned_versions(&paths).unwrap().len(), 2);
            verify_all_owned_versions(&paths).unwrap();
            reset_prune_fixture();
        }
    }

    #[tokio::test]
    async fn prune_rejects_active_work_in_use_and_protected_versions() {
        let _serial = TEST_SERIAL.lock().await;
        let (_temp, paths) = prune_fixture();
        *TEST_RECOVERY_STATUS.lock().unwrap() =
            Some(json!({"version":"1.2.3","activeJobs":1,"draining":false}));
        assert!(
            prune(&paths, &["1.2.5".into()], &["1.2.4".into()])
                .await
                .is_err()
        );
        *TEST_RECOVERY_STATUS.lock().unwrap() =
            Some(json!({"version":"1.2.3","activeJobs":0,"draining":false}));
        TEST_PRUNE_IN_USE
            .lock()
            .unwrap()
            .push(paths.versions().join("1.2.5/bin/loomex"));
        assert!(
            prune(&paths, &["1.2.5".into()], &["1.2.4".into()])
                .await
                .is_err()
        );
        TEST_PRUNE_IN_USE.lock().unwrap().clear();
        assert!(
            prune(&paths, &["1.2.3".into()], &["1.2.4".into()])
                .await
                .is_err()
        );
        assert!(
            prune(&paths, &["1.2.4".into()], &["1.2.4".into()])
                .await
                .is_err()
        );
        assert!(paths.versions().join("1.2.5").exists());
        assert!(!paths.operation().exists());
        reset_prune_fixture();
    }

    #[tokio::test]
    async fn prune_pauses_when_quarantined_files_are_in_use_or_drain_loses_idle_proof() {
        let _serial = TEST_SERIAL.lock().await;
        let (_temp, paths) = prune_fixture();
        *TEST_PRUNE_FAULT.lock().unwrap() = Some("after_move");
        assert!(
            prune(&paths, &["1.2.5".into()], &["1.2.4".into()])
                .await
                .is_err()
        );
        *TEST_PRUNE_FAULT.lock().unwrap() = None;
        let operation: Operation = state::read_json(&paths.operation()).unwrap();
        let quarantine =
            prune_quarantine(&paths, &operation, &paths.versions().join("1.2.5")).unwrap();
        TEST_PRUNE_IN_USE
            .lock()
            .unwrap()
            .push(quarantine.join("bin/loomex"));
        assert!(resume(&paths).await.is_err());
        assert!(quarantine.exists());
        TEST_PRUNE_IN_USE.lock().unwrap().clear();
        TEST_RECOVERY_STATUS.lock().unwrap().as_mut().unwrap()["activeJobs"] = json!(1);
        assert!(resume(&paths).await.is_err());
        assert!(quarantine.exists());
        TEST_RECOVERY_STATUS.lock().unwrap().as_mut().unwrap()["activeJobs"] = json!(0);
        assert_eq!(resume(&paths).await.unwrap()["completed"], true);
        reset_prune_fixture();
    }

    #[tokio::test]
    async fn prune_rejects_post_checkpoint_quarantine_tampering() {
        let _serial = TEST_SERIAL.lock().await;
        let (_temp, paths) = prune_fixture();
        *TEST_PRUNE_FAULT.lock().unwrap() = Some("during_delete");
        assert!(
            prune(&paths, &["1.2.5".into()], &["1.2.4".into()])
                .await
                .is_err()
        );
        *TEST_PRUNE_FAULT.lock().unwrap() = None;
        let operation: Operation = state::read_json(&paths.operation()).unwrap();
        let target = paths.versions().join("1.2.5");
        assert!(
            operation
                .prune
                .as_ref()
                .unwrap()
                .deleting_started
                .contains(&target)
        );
        let quarantine = prune_quarantine(&paths, &operation, &target).unwrap();
        let unexpected = quarantine.join("unowned.txt");
        fs::write(&unexpected, b"not part of installed inventory").unwrap();
        assert!(resume(&paths).await.is_err());
        assert!(unexpected.exists());
        assert!(paths.operation().exists());
        fs::remove_file(unexpected).unwrap();
        let extra_dir = quarantine.join("unowned-empty-directory");
        fs::create_dir(&extra_dir).unwrap();
        assert!(resume(&paths).await.is_err());
        assert!(extra_dir.exists());
        fs::remove_dir(extra_dir).unwrap();
        let remaining = [
            "bin/loomex",
            "metadata/project.json",
            "metadata/compatibility-manifest.json",
        ]
        .into_iter()
        .map(|relative| quarantine.join(relative))
        .find(|path| path.exists())
        .unwrap();
        let original_bytes = fs::read(&remaining).unwrap();
        fs::write(&remaining, b"tampered").unwrap();
        assert!(resume(&paths).await.is_err());
        assert!(remaining.exists());
        fs::write(&remaining, original_bytes).unwrap();
        assert_eq!(resume(&paths).await.unwrap()["completed"], true);
        reset_prune_fixture();
    }

    #[tokio::test]
    async fn prune_requires_delete_intent_for_missing_file_and_original_receipt_index() {
        let _serial = TEST_SERIAL.lock().await;
        let (_temp, paths) = prune_fixture();
        *TEST_PRUNE_FAULT.lock().unwrap() = Some("after_move");
        assert!(
            prune(&paths, &["1.2.5".into()], &["1.2.4".into()])
                .await
                .is_err()
        );
        *TEST_PRUNE_FAULT.lock().unwrap() = None;
        let mut operation: Operation = state::read_json(&paths.operation()).unwrap();
        let target = paths.versions().join("1.2.5");
        let quarantine = prune_quarantine(&paths, &operation, &target).unwrap();
        operation.prune.as_mut().unwrap().moved.push(target);
        operation.phase = "deleting".into();
        save_operation(&paths, &operation).unwrap();
        let owned_file = quarantine.join("metadata/project.json");
        let original_bytes = fs::read(&owned_file).unwrap();
        let original_mode = fs::metadata(&owned_file).unwrap().permissions();
        fs::remove_file(&owned_file).unwrap();
        assert!(resume(&paths).await.is_err());
        assert!(paths.operation().exists());
        fs::write(&owned_file, original_bytes).unwrap();
        fs::set_permissions(&owned_file, original_mode).unwrap();

        let receipt_path = paths.state_dir.join("install-receipt.json");
        let receipt_bytes = fs::read(&receipt_path).unwrap();
        state::write_json(&receipt_path, &json!({"version":"1.2.9"})).unwrap();
        assert!(resume(&paths).await.is_err());
        fs::write(&receipt_path, receipt_bytes).unwrap();
        let index_path = paths.state_dir.join("owned-versions.json");
        let index_bytes = fs::read(&index_path).unwrap();
        state::write_json(
            &index_path,
            &json!({"schema":"app.loomex.runner.owned-versions/v1","paths":[],"inventories":[]}),
        )
        .unwrap();
        assert!(resume(&paths).await.is_err());
        fs::write(&index_path, index_bytes).unwrap();
        assert_eq!(resume(&paths).await.unwrap()["completed"], true);
        reset_prune_fixture();
    }

    #[tokio::test]
    async fn prune_metadata_checkpoint_rejects_reappearing_source_path() {
        let _serial = TEST_SERIAL.lock().await;
        let (_temp, paths) = prune_fixture();
        *TEST_PRUNE_FAULT.lock().unwrap() = Some("after_metadata");
        assert!(
            prune(&paths, &["1.2.5".into()], &["1.2.4".into()])
                .await
                .is_err()
        );
        *TEST_PRUNE_FAULT.lock().unwrap() = None;
        let target = paths.versions().join("1.2.5");
        fs::create_dir(&target).unwrap();
        assert!(resume(&paths).await.is_err());
        assert!(target.exists());
        assert!(paths.operation().exists());
        fs::remove_dir(&target).unwrap();
        assert_eq!(resume(&paths).await.unwrap()["completed"], true);
        reset_prune_fixture();
    }

    #[test]
    fn prune_journal_uses_new_schema_and_old_operation_decoding_is_preserved() {
        let mut prune = Operation::new(OperationKind::Prune, "prepared", None);
        prune.prune = Some(PruneIntent {
            targets: vec![PathBuf::from("/owned/versions/1.2.5")],
            retain: vec![PathBuf::from("/owned/versions/1.2.4")],
            moved: Vec::new(),
            deleting_started: Vec::new(),
            current_target: PathBuf::from("/owned/versions/1.2.3"),
            original_inventory_digest: "a".repeat(64),
            result_inventory_digest: "b".repeat(64),
            receipt_digest: "c".repeat(64),
            drain_key: Uuid::new_v4(),
            launch_agent_digest: "d".repeat(64),
            auth_baseline: AuthBaseline::SignedOut {
                installation_id: None,
            },
        });
        assert!(prune.validate().is_err());
        prune.schema = PRUNE_OPERATION_SCHEMA.into();
        prune.validate().unwrap();
        let encoded = serde_json::to_vec(&prune).unwrap();
        let decoded: Operation = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded, prune);
        let legacy = Operation::new(OperationKind::Repair, "completed", None);
        legacy.validate().unwrap();
        assert_eq!(legacy.schema, OPERATION_SCHEMA);
    }

    #[tokio::test]
    async fn prune_fails_closed_for_unowned_symlink_and_pending_operation() {
        let _serial = TEST_SERIAL.lock().await;
        let (_temp, paths) = prune_fixture();
        assert!(
            prune(&paths, &["1.2.6".into()], &["1.2.4".into()])
                .await
                .is_err()
        );
        let outside = paths.install_base.parent().unwrap().join("outside");
        fs::create_dir(&outside).unwrap();
        fs::rename(paths.versions().join("1.2.5"), outside.join("1.2.5")).unwrap();
        symlink(outside.join("1.2.5"), paths.versions().join("1.2.5")).unwrap();
        assert!(
            prune(&paths, &["1.2.5".into()], &["1.2.4".into()])
                .await
                .is_err()
        );
        fs::remove_file(paths.versions().join("1.2.5")).unwrap();
        fs::rename(outside.join("1.2.5"), paths.versions().join("1.2.5")).unwrap();
        let operation = Operation::new(OperationKind::Repair, "protected_repair_required", None);
        save_operation(&paths, &operation).unwrap();
        assert!(
            prune(&paths, &["1.2.5".into()], &["1.2.4".into()])
                .await
                .is_err()
        );
        assert!(paths.versions().join("1.2.5").exists());
        reset_prune_fixture();
    }
}
