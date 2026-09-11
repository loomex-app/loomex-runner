use anyhow::Result;
use loomex_runner::executor::{
    ExecutionObserver, ExecutionOutcome, ExecutionRequest, ProcessIdentity, execute_with_supervisor,
};
use std::{
    collections::BTreeMap,
    fs,
    io::{Read, Seek, SeekFrom},
    os::unix::fs::{PermissionsExt, symlink},
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::task::JoinHandle;

const CHILD_PID: &str = "fixture-child.pid";
const READINESS_TIMEOUT: Duration = Duration::from_secs(3);
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_DIAGNOSTIC_BYTES: usize = 4096;

#[derive(Default)]
struct Observer {
    intent: AtomicBool,
    spawned: AtomicBool,
}
impl ExecutionObserver for Observer {
    fn before_spawn(&self, _: &ExecutionRequest) -> Result<()> {
        self.intent.store(true, Ordering::SeqCst);
        Ok(())
    }
    fn spawned(&self, _: &ProcessIdentity) -> Result<()> {
        assert!(self.intent.load(Ordering::SeqCst));
        self.spawned.store(true, Ordering::SeqCst);
        Ok(())
    }
}

fn request(root: &Path, script: &str) -> ExecutionRequest {
    ExecutionRequest {
        job_id: "executor-test".into(),
        workspace: root.canonicalize().unwrap(),
        cwd: None,
        argv: vec!["/bin/sh".into(), "-c".into(), script.into()],
        env: BTreeMap::new(),
        output_dir: root.join("spool"),
        policy: "host_user/v1".into(),
        observer: Arc::new(Observer::default()),
    }
}

async fn run(request: ExecutionRequest, cancel: Arc<AtomicBool>) -> Result<ExecutionOutcome> {
    execute_with_supervisor(
        request,
        cancel,
        Path::new(env!("CARGO_BIN_EXE_loomex-runner")),
    )
    .await
}

fn fixture_request(root: &Path, fixture_name: &str) -> ExecutionRequest {
    let mut request = request(root, "unused");
    request.argv = vec![
        std::env::current_exe()
            .unwrap()
            .into_os_string()
            .into_string()
            .expect("test executable path must be UTF-8"),
        "--exact".into(),
        fixture_name.into(),
        "--nocapture".into(),
        "--test-threads=1".into(),
        "--ignored".into(),
    ];
    request
}

#[tokio::test]
async fn output_exceeds_legacy_caps_without_truncation() {
    let root = tempfile::tempdir().unwrap();
    let result = run(
        request(
            root.path(),
            "dd if=/dev/zero bs=1048576 count=12 2>/dev/null; printf stderr >&2",
        ),
        Arc::new(AtomicBool::new(false)),
    )
    .await
    .unwrap();
    assert_eq!(result.exit_code, Some(0));
    assert!(!result.indeterminate, "{:?}", result.error);
    assert_eq!(
        fs::metadata(&result.stdout_path).unwrap().len(),
        12 * 1024 * 1024
    );
    assert_eq!(fs::read(&result.stderr_path).unwrap(), b"stderr");
    assert_eq!(
        fs::metadata(&result.stdout_path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
}

#[tokio::test]
async fn explicit_environment_does_not_inherit_daemon_environment() {
    let root = tempfile::tempdir().unwrap();
    let mut req = request(root.path(), "env");
    req.env
        .insert("PROVIDER_CONFIGURED".into(), "available".into());
    let result = run(req, Arc::new(AtomicBool::new(false))).await.unwrap();
    let output = fs::read_to_string(result.stdout_path).unwrap();
    assert!(output.contains("PROVIDER_CONFIGURED=available"));
    assert!(!output.contains("HOME="));
    assert!(!output.contains("CODEX_HOME="));
    assert!(!output.contains("CARGO="));
}

#[tokio::test]
async fn argv_is_passed_literally_and_target_stdin_is_null() {
    let root = tempfile::tempdir().unwrap();
    let mut req = request(root.path(), "unused");
    req.argv = vec![
        "/usr/bin/printf".into(),
        "%s".into(),
        "$(touch unwanted); *".into(),
    ];
    let result = run(req, Arc::new(AtomicBool::new(false))).await.unwrap();
    assert_eq!(
        fs::read_to_string(result.stdout_path).unwrap(),
        "$(touch unwanted); *"
    );
    assert!(!root.path().join("unwanted").exists());
    let root = tempfile::tempdir().unwrap();
    let mut req = request(root.path(), "unused");
    req.argv = vec!["/bin/cat".into()];
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        run(req, Arc::new(AtomicBool::new(false))),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(result.exit_code, Some(0));
    assert_eq!(fs::metadata(result.stdout_path).unwrap().len(), 0);
}

#[tokio::test]
async fn cwd_symlink_escape_is_rejected_before_intent() {
    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    symlink(outside.path(), root.path().join("escape")).unwrap();
    let observer = Arc::new(Observer::default());
    let mut req = request(root.path(), "true");
    req.cwd = Some("escape".into());
    req.observer = observer.clone();
    assert!(
        run(req, Arc::new(AtomicBool::new(false)))
            .await
            .unwrap_err()
            .to_string()
            .contains("escapes")
    );
    assert!(!observer.intent.load(Ordering::SeqCst));
}

fn ready(path: &Path) -> bool {
    fs::read_to_string(path).is_ok_and(|value| !value.trim().is_empty())
}

fn bounded_contents(path: &Path) -> String {
    match fs::File::open(path) {
        Ok(mut file) => {
            let total = match file.metadata() {
                Ok(metadata) => metadata.len(),
                Err(error) => return format!("{}: {error}", path.display()),
            };
            let start = total.saturating_sub(MAX_DIAGNOSTIC_BYTES as u64);
            if let Err(error) = file.seek(SeekFrom::Start(start)) {
                return format!("{}: {error}", path.display());
            }
            let mut contents = Vec::with_capacity(MAX_DIAGNOSTIC_BYTES);
            if let Err(error) = file
                .take(MAX_DIAGNOSTIC_BYTES as u64)
                .read_to_end(&mut contents)
            {
                return format!("{}: {error}", path.display());
            }
            format!(
                "{} ({} bytes, last {}): {:?}",
                path.display(),
                total,
                contents.len(),
                String::from_utf8_lossy(&contents)
            )
        }
        Err(error) => format!("{}: {error}", path.display()),
    }
}

fn readiness_diagnostics(root: &Path) -> String {
    format!(
        "stdout {}; stderr {}",
        bounded_contents(&root.join("spool/stdout")),
        bounded_contents(&root.join("spool/stderr")),
    )
}

async fn cancel_and_reap(
    task: &mut JoinHandle<Result<ExecutionOutcome>>,
    cancel: &AtomicBool,
) -> String {
    cancel.store(true, Ordering::SeqCst);
    match tokio::time::timeout(CLEANUP_TIMEOUT, task).await {
        Ok(Ok(Ok(outcome))) => format!(
            "cleanup outcome canceled={}, group_stopped={}, error={:?}",
            outcome.canceled, outcome.managed_group_stopped, outcome.error
        ),
        Ok(Ok(Err(error))) => format!("cleanup execution error: {error:#}"),
        Ok(Err(error)) => format!("cleanup task join error: {error}"),
        Err(_) => "cleanup timed out".into(),
    }
}

async fn wait_for_readiness(
    task: &mut JoinHandle<Result<ExecutionOutcome>>,
    cancel: &AtomicBool,
    root: &Path,
    paths: &[&Path],
) -> Result<()> {
    let started = Instant::now();
    loop {
        if paths.iter().all(|path| ready(path)) {
            return Ok(());
        }
        if task.is_finished() {
            let outcome = match task.await {
                Ok(Ok(outcome)) => format!(
                    "exit_code={:?}, canceled={}, group_stopped={}, error={:?}",
                    outcome.exit_code,
                    outcome.canceled,
                    outcome.managed_group_stopped,
                    outcome.error
                ),
                Ok(Err(error)) => format!("execution error: {error:#}"),
                Err(error) => format!("execution task join error: {error}"),
            };
            anyhow::bail!(
                "execution ended before readiness [{}]: {outcome}; {}",
                paths
                    .iter()
                    .map(|path| path.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", "),
                readiness_diagnostics(root),
            );
        }
        if started.elapsed() >= READINESS_TIMEOUT {
            let cleanup = cancel_and_reap(task, cancel).await;
            anyhow::bail!(
                "timed out waiting for readiness [{}]; {cleanup}; {}",
                paths
                    .iter()
                    .map(|path| path.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", "),
                readiness_diagnostics(root),
            );
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

#[tokio::test]
async fn readiness_reports_early_execution_failure() {
    let root = tempfile::tempdir().unwrap();
    let cancel = Arc::new(AtomicBool::new(false));
    let mut task = tokio::spawn(run(request(root.path(), "exit 47"), cancel.clone()));
    let error = wait_for_readiness(
        &mut task,
        &cancel,
        root.path(),
        &[&root.path().join("never-ready")],
    )
    .await
    .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("execution ended before readiness")
    );
    assert!(error.to_string().contains("exit_code=Some(47)"));
}

#[test]
#[ignore = "execution fixture invoked by cancellation tests"]
fn execution_fixture_child_survives_parent() {
    fixture_child_survives_parent(Path::new("fixture-ready"));
}

#[test]
#[ignore = "execution fixture invoked by cancellation tests"]
fn execution_fixture_ignores_term() {
    fixture_ignores_term(Path::new("fixture-ready"));
}

fn fixture_child_survives_parent(ready_path: &Path) {
    let mut pipe = [-1; 2];
    assert_eq!(
        unsafe { libc::pipe(pipe.as_mut_ptr()) },
        0,
        "create fixture pipe"
    );
    let child = unsafe { libc::fork() };
    assert!(child >= 0, "fork fixture child");
    if child == 0 {
        unsafe {
            libc::close(pipe[0]);
        }
        fs::write(ready_path, "ready\n").expect("write fixture readiness");
        let signal = b"R";
        assert_eq!(
            unsafe { libc::write(pipe[1], signal.as_ptr().cast(), signal.len()) },
            signal.len() as isize,
            "notify fixture parent"
        );
        unsafe {
            libc::close(pipe[1]);
        }
        loop {
            unsafe {
                libc::pause();
            }
        }
    }
    unsafe {
        libc::close(pipe[1]);
    }
    fs::write(ready_path.with_file_name(CHILD_PID), child.to_string())
        .expect("write fixture child identity");
    let mut signal = [0_u8; 1];
    assert_eq!(
        unsafe { libc::read(pipe[0], signal.as_mut_ptr().cast(), signal.len()) },
        1,
        "wait for fixture child readiness"
    );
    unsafe {
        libc::close(pipe[0]);
    }
}

fn fixture_ignores_term(ready_path: &Path) {
    unsafe {
        libc::signal(libc::SIGTERM, libc::SIG_IGN);
    }
    fs::write(ready_path, "ready\n").expect("write fixture readiness");
    loop {
        unsafe {
            libc::pause();
        }
    }
}

#[tokio::test]
async fn cancellation_reaches_child_after_target_leader_exits() {
    let root = tempfile::tempdir().unwrap();
    let cancel = Arc::new(AtomicBool::new(false));
    let mut task = tokio::spawn(run(
        fixture_request(root.path(), "execution_fixture_child_survives_parent"),
        cancel.clone(),
    ));
    let child_pid = root.path().join(CHILD_PID);
    let child_ready = root.path().join("fixture-ready");
    let target_status = root.path().join("spool/target-status.json");
    wait_for_readiness(
        &mut task,
        &cancel,
        root.path(),
        &[&child_pid, &child_ready, &target_status],
    )
    .await
    .unwrap();
    assert!(
        !task.is_finished(),
        "target exit must not imply process group completion"
    );
    cancel.store(true, Ordering::SeqCst);
    let result = task.await.unwrap().unwrap();
    assert!(result.canceled);
    assert!(result.managed_group_stopped);
    assert!(result.descendant_cleanup.contains("indeterminate"));
    let pid = fs::read_to_string(&child_pid).unwrap();
    let status = std::process::Command::new("/bin/ps")
        .args(["-p", pid.trim(), "-o", "stat="])
        .output()
        .unwrap();
    assert!(
        status.stdout.is_empty()
            || String::from_utf8_lossy(&status.stdout)
                .trim()
                .starts_with('Z')
    );
}

#[tokio::test]
async fn term_ignoring_group_is_killed_after_cancellation_grace() {
    let root = tempfile::tempdir().unwrap();
    let cancel = Arc::new(AtomicBool::new(false));
    let mut task = tokio::spawn(run(
        fixture_request(root.path(), "execution_fixture_ignores_term"),
        cancel.clone(),
    ));
    let ready_path = root.path().join("fixture-ready");
    wait_for_readiness(&mut task, &cancel, root.path(), &[&ready_path])
        .await
        .unwrap();
    cancel.store(true, Ordering::SeqCst);
    let result = tokio::time::timeout(std::time::Duration::from_secs(6), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(result.canceled);
    assert!(result.managed_group_stopped);
}

#[tokio::test]
async fn cancellation_racing_completion_has_one_outcome() {
    for _ in 0..4 {
        let root = tempfile::tempdir().unwrap();
        let cancel = Arc::new(AtomicBool::new(false));
        let task = tokio::spawn(run(request(root.path(), "printf done"), cancel.clone()));
        tokio::task::yield_now().await;
        cancel.store(true, Ordering::SeqCst);
        let result = task.await.unwrap().unwrap();
        assert!(result.canceled || result.exit_code == Some(0));
    }
}

#[tokio::test]
async fn spool_creation_error_prevents_execution_and_preserves_existing_evidence() {
    let root = tempfile::tempdir().unwrap();
    fs::create_dir(root.path().join("spool")).unwrap();
    fs::write(root.path().join("spool/stdout"), b"prior evidence").unwrap();
    let observer = Arc::new(Observer::default());
    let mut req = request(root.path(), "touch should-not-exist");
    req.observer = observer.clone();
    assert!(run(req, Arc::new(AtomicBool::new(false))).await.is_err());
    assert!(!observer.intent.load(Ordering::SeqCst));
    assert!(!root.path().join("should-not-exist").exists());
    assert_eq!(
        fs::read(root.path().join("spool/stdout")).unwrap(),
        b"prior evidence"
    );
}

struct RejectIdentity;
impl ExecutionObserver for RejectIdentity {
    fn before_spawn(&self, _: &ExecutionRequest) -> Result<()> {
        Ok(())
    }
    fn spawned(&self, _: &ProcessIdentity) -> Result<()> {
        anyhow::bail!("journal unavailable")
    }
}

#[tokio::test]
async fn failed_identity_journal_does_not_authorize_target_spawn() {
    let root = tempfile::tempdir().unwrap();
    let mut req = request(root.path(), "touch should-not-exist");
    req.observer = Arc::new(RejectIdentity);
    assert!(run(req, Arc::new(AtomicBool::new(false))).await.is_err());
    assert!(!root.path().join("should-not-exist").exists());
}

#[tokio::test]
async fn detached_child_is_reported_as_indeterminate_effects() {
    let root = tempfile::tempdir().unwrap();
    let mut req = request(root.path(), "unused");
    req.argv = vec!["/usr/bin/python3".into(), "-c".into(),
        "import os,time; p=os.fork();\nif p == 0:\n os.setsid(); open('detached.pid','w').write(str(os.getpid())); time.sleep(10)\nelse:\n time.sleep(0.1)".into()];
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(4),
        run(req, Arc::new(AtomicBool::new(false))),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(result.exit_code, Some(0));
    assert!(result.descendant_cleanup.contains("indeterminate"));
    let pid: i32 = fs::read_to_string(root.path().join("detached.pid"))
        .unwrap()
        .parse()
        .unwrap();
    unsafe {
        libc::kill(pid, libc::SIGKILL);
    }
}
