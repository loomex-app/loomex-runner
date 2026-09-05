use anyhow::Result;
use loomex_runner::executor::{
    ExecutionObserver, ExecutionOutcome, ExecutionRequest, ProcessIdentity, execute_with_supervisor,
};
use std::{
    collections::BTreeMap,
    fs,
    os::unix::fs::{PermissionsExt, symlink},
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

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

async fn wait_file(path: &Path) {
    for _ in 0..200 {
        if fs::read_to_string(path).is_ok_and(|value| !value.trim().is_empty()) {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    panic!("fixture did not start: {}", path.display());
}

#[tokio::test]
async fn cancellation_reaches_child_after_target_leader_exits() {
    let root = tempfile::tempdir().unwrap();
    let cancel = Arc::new(AtomicBool::new(false));
    let task = tokio::spawn(run(
        request(root.path(), "sleep 1000 & echo $! > child.pid; exit 0"),
        cancel.clone(),
    ));
    wait_file(&root.path().join("child.pid")).await;
    wait_file(&root.path().join("spool/target-status.json")).await;
    assert!(
        !task.is_finished(),
        "target exit must not imply process group completion"
    );
    cancel.store(true, Ordering::SeqCst);
    let result = task.await.unwrap().unwrap();
    assert!(result.canceled);
    assert!(result.managed_group_stopped);
    assert!(result.descendant_cleanup.contains("indeterminate"));
    let pid = fs::read_to_string(root.path().join("child.pid")).unwrap();
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
    let task = tokio::spawn(run(
        request(
            root.path(),
            "trap '' TERM; echo ready > ready; while :; do sleep 1; done",
        ),
        cancel.clone(),
    ));
    wait_file(&root.path().join("ready")).await;
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
