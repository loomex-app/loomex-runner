//! Explicit argv execution with full OS-user authority. This is not a sandbox.
//!
//! A guardian reserves the process-group ID until the caller finishes signaling.
//! Journal identities are evidence, never authority to signal a PID after restart.
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::{File, OpenOptions},
    io::{Read, Write},
    os::unix::{
        fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
        io::AsRawFd,
        process::CommandExt,
    },
    path::{Path, PathBuf},
    process::Stdio,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    sync::watch,
};

const SUPERVISOR: &str = "__loomex_execution_supervisor";
const TERM_GRACE: Duration = Duration::from_secs(2);
const POLL: Duration = Duration::from_millis(50);

pub trait ExecutionObserver: Send + Sync {
    /// Persist and sync execution intent before any process is created.
    fn before_spawn(&self, request: &ExecutionRequest) -> Result<()>;
    /// Persist and sync guardian identity before authorizing the target to start.
    fn spawned(&self, identity: &ProcessIdentity) -> Result<()>;
}

pub struct ExecutionRequest {
    pub job_id: String,
    pub workspace: PathBuf,
    pub cwd: Option<PathBuf>,
    pub argv: Vec<String>,
    pub env: BTreeMap<String, String>,
    pub output_dir: PathBuf,
    pub policy: String,
    pub observer: Arc<dyn ExecutionObserver>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessIdentity {
    pub pid: u32,
    pub pgid: i32,
    /// This nonce identifies retained Child ownership, not a recoverable PID lease.
    pub start_identity: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionOutcome {
    pub exit_code: Option<i32>,
    pub stdout_path: PathBuf,
    pub stderr_path: PathBuf,
    pub canceled: bool,
    pub managed_group_stopped: bool,
    pub indeterminate: bool,
    pub identity: ProcessIdentity,
    /// Full-host descendants can detach or create external effects. Always explicit.
    pub descendant_cleanup: String,
    pub error: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct TargetStatus {
    exit_code: Option<i32>,
    error: Option<String>,
}

fn checked_cwd(request: &ExecutionRequest) -> Result<PathBuf> {
    if request.policy != "host_user/v1" {
        bail!("unsupported execution policy");
    }
    if request.argv.is_empty() || request.argv[0].is_empty() {
        bail!("argv must contain an executable");
    }
    if request.argv.iter().any(|arg| arg.contains('\0')) {
        bail!("argv contains NUL");
    }
    if request
        .env
        .iter()
        .any(|(key, value)| key.is_empty() || key.contains(['=', '\0']) || value.contains('\0'))
    {
        bail!("invalid explicit environment");
    }
    let workspace = request
        .workspace
        .canonicalize()
        .context("canonical workspace")?;
    if workspace != request.workspace || !workspace.is_dir() {
        bail!("workspace must be a canonical directory");
    }
    let relative = request.cwd.as_deref().unwrap_or(Path::new("."));
    if relative.is_absolute() {
        bail!("cwd must be relative to workspace");
    }
    let cwd = workspace
        .join(relative)
        .canonicalize()
        .context("canonical cwd")?;
    if !cwd.starts_with(&workspace) || !cwd.is_dir() {
        bail!("cwd escapes workspace or is not a directory");
    }
    Ok(cwd)
}

fn private_file(path: &Path) -> Result<File> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .with_context(|| format!("create spool {}", path.display()))
}

fn prepare_output(path: &Path) -> Result<()> {
    match std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)
    {
        Ok(()) => (),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => (),
        Err(error) => return Err(error.into()),
    }
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        bail!("output directory must not be a symlink");
    }
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    Ok(())
}

pub async fn execute(
    request: ExecutionRequest,
    cancel: Arc<AtomicBool>,
) -> Result<ExecutionOutcome> {
    execute_with_supervisor(request, cancel, &std::env::current_exe()?).await
}

/// Allows integration tests and version-pinned installations to select a guardian binary.
#[doc(hidden)]
pub async fn execute_with_supervisor(
    request: ExecutionRequest,
    cancel: Arc<AtomicBool>,
    program: &Path,
) -> Result<ExecutionOutcome> {
    let cwd = checked_cwd(&request)?;
    prepare_output(&request.output_dir)?;
    let output_dir = request.output_dir.canonicalize()?;
    let stdout_path = output_dir.join("stdout");
    let stderr_path = output_dir.join("stderr");
    let status_path = output_dir.join("target-status.json");
    let stdout_file = private_file(&stdout_path)?;
    let stderr_file = private_file(&stderr_path)?;
    private_file(&status_path)?.sync_all()?;
    File::open(&request.output_dir)?.sync_all()?;
    request.observer.before_spawn(&request)?;

    let mut command = tokio::process::Command::new(program);
    command
        .arg(SUPERVISOR)
        .arg(&status_path)
        .args(&request.argv)
        .current_dir(cwd)
        .env_clear()
        .env("PATH", "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin")
        .envs(&request.env)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command.as_std_mut().process_group(0);
    let mut child = command.spawn().context("spawn execution guardian")?;
    let pid = child.id().context("guardian has no PID")?;
    let identity = ProcessIdentity {
        pid,
        pgid: pid as i32,
        start_identity: format!(
            "owned-unreaped-child:{}:{}",
            std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
        ),
    };
    let mut control = child.stdin.take().context("guardian control pipe")?;
    // Until this durable write succeeds, the guardian cannot spawn the target.
    if let Err(error) = request.observer.spawned(&identity) {
        signal_owned_group(&identity, libc::SIGKILL)?;
        let _ = child.wait().await;
        return Err(error.context("persist guardian identity; target not authorized"));
    }
    let (drain, stop) = watch::channel(false);
    let mut stdout_task = tokio::spawn(pump(
        child.stdout.take().unwrap(),
        stdout_file,
        stop.clone(),
    ));
    let mut stderr_task = tokio::spawn(pump(child.stderr.take().unwrap(), stderr_file, stop));
    let mut canceled = cancel.load(Ordering::SeqCst);
    let mut error = None;
    let mut target = None;
    let mut terminate_at = None;
    let mut kill_sent = false;
    let managed_group_stopped;
    let mut stdout_result = None;
    let mut stderr_result = None;
    if !canceled {
        if let Err(problem) = control.write_all(b"S").await {
            error = Some(format!("authorize guardian: {problem}"));
        }
    }

    loop {
        canceled |= cancel.load(Ordering::SeqCst);
        if stdout_result.is_none() && stdout_task.is_finished() {
            stdout_result = Some((&mut stdout_task).await.context("stdout spool task")?);
        }
        if stderr_result.is_none() && stderr_task.is_finished() {
            stderr_result = Some((&mut stderr_task).await.context("stderr spool task")?);
        }
        for result in [&stdout_result, &stderr_result].into_iter().flatten() {
            if let Err(problem) = result {
                error.get_or_insert_with(|| format!("output spool failed: {problem}"));
            }
        }
        if target.is_none() {
            match tokio::fs::read(&status_path).await {
                Ok(bytes) if !bytes.is_empty() => {
                    target = serde_json::from_slice::<TargetStatus>(&bytes).ok();
                }
                Ok(_) => (),
                Err(problem) => {
                    error.get_or_insert_with(|| format!("read target status: {problem}"));
                }
            }
        }
        let group = group_members(identity.pgid).await;
        let observation_failed = group.is_err();
        let (guardian_alive, others_alive) = match group {
            Ok(members) => (
                members.contains(&identity.pid),
                members.iter().any(|pid| *pid != identity.pid),
            ),
            Err(problem) => {
                error.get_or_insert_with(|| format!("observe process group: {problem}"));
                (true, true)
            }
        };
        if !guardian_alive && target.is_none() && !canceled {
            error.get_or_insert_with(|| {
                "guardian exited without a durable target status".to_owned()
            });
        }
        if (canceled || error.is_some()) && !observation_failed && !guardian_alive && !others_alive
        {
            // The owned group has no live members. Signaling it now races the
            // guardian's exit and can fail even though cleanup is complete.
            managed_group_stopped = true;
            break;
        }
        if (canceled || error.is_some()) && terminate_at.is_none() {
            signal_owned_group(&identity, libc::SIGTERM)?;
            terminate_at = Some(Instant::now());
        }
        if kill_sent && (observation_failed || (!guardian_alive && !others_alive)) {
            managed_group_stopped = !observation_failed;
            break;
        }
        if let Some(started) = terminate_at {
            if !kill_sent && (!others_alive || started.elapsed() >= TERM_GRACE) {
                signal_owned_group(&identity, libc::SIGKILL)?;
                kill_sent = true;
            }
        } else if target.is_some() && !others_alive {
            // Guardian stays unreaped until the final group signal is no longer needed.
            control
                .write_all(b"Q")
                .await
                .context("release execution guardian")?;
            drop(control);
            managed_group_stopped = true;
            break;
        }
        tokio::time::sleep(POLL).await;
    }
    // Only now reap the guardian, releasing its PID/PGID reservation.
    let guardian_status = child.wait().await.context("reap execution guardian")?;
    let _ = drain.send(true);
    if stdout_result.is_none() {
        stdout_result = Some(stdout_task.await.context("stdout spool task")?);
    }
    if stderr_result.is_none() {
        stderr_result = Some(stderr_task.await.context("stderr spool task")?);
    }
    for result in [stdout_result, stderr_result].into_iter().flatten() {
        if let Err(problem) = result {
            error.get_or_insert_with(|| format!("output spool failed: {problem}"));
        }
    }
    if let Some(status) = &target {
        if let Some(problem) = &status.error {
            error.get_or_insert_with(|| problem.clone());
        }
    }
    if !canceled && !guardian_status.success() {
        error.get_or_insert_with(|| format!("guardian exited unexpectedly: {guardian_status}"));
    }
    Ok(ExecutionOutcome {
        exit_code: target.and_then(|status| status.exit_code),
        stdout_path,
        stderr_path,
        canceled,
        managed_group_stopped,
        indeterminate: error.is_some(),
        identity,
        descendant_cleanup:
            "indeterminate: full-host processes may detach; only the owned process group is managed"
                .into(),
        error,
    })
}

async fn pump<R: AsyncRead + AsRawFd + Unpin>(
    mut input: R,
    file: File,
    mut stop: watch::Receiver<bool>,
) -> std::io::Result<bool> {
    let mut output = tokio::fs::File::from_std(file);
    // A fixed transfer buffer does not cap cumulative output.
    let mut buffer = [0_u8; 64 * 1024];
    let eof = loop {
        tokio::select! {
            biased;
            result = input.read(&mut buffer) => {
                let count = result?;
                if count == 0 { break true; }
                output.write_all(&buffer[..count]).await?;
            }
            _ = stop.changed() => {
                // Reactor readiness may lag behind the final process exit. Drain
                // the nonblocking descriptor itself so queued bytes are retained,
                // without waiting forever for detached processes holding a pipe.
                loop {
                    let count = unsafe { libc::read(input.as_raw_fd(), buffer.as_mut_ptr().cast(), buffer.len()) };
                    if count > 0 { output.write_all(&buffer[..count as usize]).await?; continue; }
                    if count == 0 { break; }
                    let error = std::io::Error::last_os_error();
                    if error.kind() == std::io::ErrorKind::Interrupted { continue; }
                    if error.kind() != std::io::ErrorKind::WouldBlock { return Err(error); }
                    break;
                }
                break false;
            }
        }
    };
    output.flush().await?;
    output.sync_all().await?;
    Ok(eof)
}

fn signal_owned_group(identity: &ProcessIdentity, signal: i32) -> Result<()> {
    // Caller owns an unreaped direct child with this PID. Never use this with a
    // recovered journal identity: there is no PID/PGID reservation after restart.
    let result = unsafe { libc::kill(-identity.pgid, signal) };
    if result != 0 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::ESRCH) {
            return Err(error.into());
        }
    }
    Ok(())
}

async fn group_members(pgid: i32) -> Result<Vec<u32>> {
    let output = tokio::process::Command::new("/bin/ps")
        .args(["-axo", "pid=,pgid=,stat="])
        .env_clear()
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .output()
        .await?;
    if !output.status.success() {
        bail!("ps failed while observing owned process group");
    }
    Ok(String::from_utf8(output.stdout)?
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let pid = fields.next()?.parse::<u32>().ok()?;
            let group = fields.next()?.parse::<i32>().ok()?;
            let state = fields.next()?;
            (group == pgid && !state.starts_with('Z')).then_some(pid)
        })
        .collect())
}

/// Call before constructing the daemon runtime or parsing public CLI commands.
pub fn maybe_run_supervisor() -> Result<bool> {
    let args: Vec<_> = std::env::args_os().collect();
    if args.get(1).and_then(|arg| arg.to_str()) != Some(SUPERVISOR) {
        return Ok(false);
    }
    if args.len() < 4 {
        bail!("invalid execution guardian invocation");
    }
    let status_path = Path::new(&args[2]);
    // The guardian alone ignores TERM; the target resets it before exec.
    unsafe {
        libc::signal(libc::SIGTERM, libc::SIG_IGN);
    }
    let mut control = std::io::stdin();
    let mut start = [0_u8; 1];
    if control.read(&mut start)? == 0 || start[0] != b'S' {
        return Ok(true);
    }
    let flags = unsafe { libc::fcntl(libc::STDIN_FILENO, libc::F_GETFL) };
    if flags < 0
        || unsafe { libc::fcntl(libc::STDIN_FILENO, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    let mut command = std::process::Command::new(&args[3]);
    command.args(&args[4..]).stdin(Stdio::null());
    unsafe {
        command.pre_exec(|| {
            libc::signal(libc::SIGTERM, libc::SIG_DFL);
            Ok(())
        });
    }
    let mut target = match command.spawn() {
        Ok(target) => Some(target),
        Err(problem) => {
            write_target_status(
                status_path,
                &TargetStatus {
                    exit_code: None,
                    error: Some(format!("spawn target: {problem}")),
                },
            )?;
            None
        }
    };
    let mut shutting_down = None;
    loop {
        if let Some(process) = target.as_mut() {
            if let Some(status) = process.try_wait()? {
                use std::os::unix::process::ExitStatusExt;
                write_target_status(
                    status_path,
                    &TargetStatus {
                        exit_code: status
                            .code()
                            .or_else(|| status.signal().map(|signal| 128 + signal)),
                        error: None,
                    },
                )?;
                target = None;
            }
        }
        match control.read(&mut start) {
            Ok(0) => {
                if shutting_down.is_none() {
                    unsafe {
                        libc::kill(-libc::getpgrp(), libc::SIGTERM);
                    }
                    shutting_down = Some(Instant::now());
                }
            }
            Ok(_) if start[0] == b'Q' && target.is_none() => return Ok(true),
            Ok(_) => (),
            Err(error)
                if error.kind() == std::io::ErrorKind::WouldBlock
                    || error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error.into()),
        }
        if shutting_down.is_some_and(|started| started.elapsed() >= TERM_GRACE) {
            unsafe {
                libc::kill(-libc::getpgrp(), libc::SIGKILL);
            }
        }
        std::thread::sleep(POLL);
    }
}

fn write_target_status(path: &Path, status: &TargetStatus) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    serde_json::to_writer(&mut file, status)?;
    file.flush()?;
    file.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn spool_write_failure_preserves_existing_evidence() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("evidence");
        std::fs::write(&path, b"previous bytes").unwrap();
        let file = File::open(&path).unwrap(); // read-only descriptor fails writes.
        let (_tx, rx) = watch::channel(false);
        let (input, mut writer) = tokio::net::UnixStream::pair().unwrap();
        writer.write_all(b"new output").await.unwrap();
        drop(writer);
        assert!(pump(input, file, rx).await.is_err());
        assert_eq!(std::fs::read(path).unwrap(), b"previous bytes");
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn enospc_is_an_error_without_truncation_or_success() {
        let file = OpenOptions::new().write(true).open("/dev/full").unwrap();
        let (_tx, rx) = watch::channel(false);
        let (input, mut writer) = tokio::net::UnixStream::pair().unwrap();
        writer
            .write_all(b"unlimited does not mean disk errors are ignored")
            .await
            .unwrap();
        drop(writer);
        let error = pump(input, file, rx).await.unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::ENOSPC));
    }
}
