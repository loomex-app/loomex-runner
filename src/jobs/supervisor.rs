//! One owner for admission accounting, cancellation registration and recovery tasks.
use super::*;

pub struct ExecutionSupervisor {
    draining: AtomicBool,
    logout_requested: AtomicBool,
    active: std::sync::atomic::AtomicUsize,
    quiescence: std::sync::atomic::AtomicUsize,
    managed: std::sync::atomic::AtomicUsize,
    admission: Mutex<()>,
    cancellations: Mutex<HashMap<String, Arc<AtomicBool>>>,
    recovery_tasks: Mutex<tokio::task::JoinSet<()>>,
    owned_jobs: Mutex<HashSet<String>>,
    shutdown: AtomicBool,
    lease_polls: LeasePollCounters,
}

#[derive(Default)]
struct LeasePollCounters {
    requests: std::sync::atomic::AtomicU64,
    empty_responses: std::sync::atomic::AtomicU64,
    fast_empty_responses: std::sync::atomic::AtomicU64,
    paced_waits: std::sync::atomic::AtomicU64,
    interrupted_waits: std::sync::atomic::AtomicU64,
    protocol_errors: std::sync::atomic::AtomicU64,
}

impl ExecutionSupervisor {
    pub fn new(draining: bool) -> Self {
        Self {
            draining: AtomicBool::new(draining),
            logout_requested: AtomicBool::new(false),
            active: Default::default(),
            quiescence: Default::default(),
            managed: Default::default(),
            admission: Mutex::new(()),
            cancellations: Default::default(),
            recovery_tasks: Mutex::new(tokio::task::JoinSet::new()),
            owned_jobs: Default::default(),
            shutdown: AtomicBool::new(false),
            lease_polls: Default::default(),
        }
    }
    pub fn is_draining(&self) -> bool {
        self.draining.load(Ordering::SeqCst)
    }
    pub fn set_draining(&self, value: bool) {
        self.draining.store(value, Ordering::SeqCst);
    }
    pub fn logout_requested(&self) -> bool {
        self.logout_requested.load(Ordering::SeqCst)
    }
    pub fn set_logout_requested(&self, value: bool) {
        self.logout_requested.store(value, Ordering::SeqCst);
    }
    pub fn managed_work(&self) -> usize {
        self.managed.load(Ordering::SeqCst)
    }
    pub fn execution_work(&self) -> usize {
        self.active
            .load(Ordering::SeqCst)
            .saturating_add(self.quiescence.load(Ordering::SeqCst))
    }
    pub fn active_work(&self) -> usize {
        self.active.load(Ordering::SeqCst)
    }
    /// Aggregate local counters only; no session, organization or backend data.
    pub fn lease_poll_diagnostics(&self) -> Value {
        let counters = &self.lease_polls;
        json!({
            "requests": counters.requests.load(Ordering::Relaxed),
            "emptyResponses": counters.empty_responses.load(Ordering::Relaxed),
            "fastEmptyResponses": counters.fast_empty_responses.load(Ordering::Relaxed),
            "pacedWaits": counters.paced_waits.load(Ordering::Relaxed),
            "interruptedWaits": counters.interrupted_waits.load(Ordering::Relaxed),
            "protocolErrors": counters.protocol_errors.load(Ordering::Relaxed),
        })
    }
    pub fn admission_lock(&self) -> Result<std::sync::MutexGuard<'_, ()>> {
        self.admission
            .lock()
            .map_err(|_| anyhow::anyhow!("INTERNAL"))
    }
    pub fn begin_active(&self) {
        self.managed.fetch_add(1, Ordering::SeqCst);
        self.active.fetch_add(1, Ordering::SeqCst);
    }
    pub fn end_active(&self) {
        self.active.fetch_sub(1, Ordering::SeqCst);
        self.managed.fetch_sub(1, Ordering::SeqCst);
    }
    pub fn begin_quiescence(&self) {
        self.managed.fetch_add(1, Ordering::SeqCst);
        self.quiescence.fetch_add(1, Ordering::SeqCst);
    }
    pub fn end_quiescence(&self) {
        self.quiescence.fetch_sub(1, Ordering::SeqCst);
        self.managed.fetch_sub(1, Ordering::SeqCst);
    }
    pub fn begin_control(&self) {
        self.managed.fetch_add(1, Ordering::SeqCst);
    }
    pub fn end_control(&self) {
        self.managed.fetch_sub(1, Ordering::SeqCst);
    }
    pub fn join_drain(&self) -> Result<()> {
        self.managed
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
                n.checked_add(1).filter(|_| n > 0)
            })
            .map(|_| ())
            .map_err(|_| anyhow::anyhow!("RUNNER_NOT_READY"))
    }
    pub async fn register_cancellation(&self, id: String, token: Arc<AtomicBool>) -> Result<()> {
        let mut tokens = self.cancellations.lock().unwrap();
        if tokens.contains_key(&id) {
            bail!("JOB_ALREADY_OWNED");
        }
        tokens.insert(id, token);
        Ok(())
    }
    pub async fn unregister(&self, id: &str) {
        self.cancellations.lock().unwrap().remove(id);
    }
    pub async fn cancel(&self, id: &str) -> bool {
        if let Some(token) = self.cancellations.lock().unwrap().get(id) {
            token.store(true, Ordering::SeqCst);
            true
        } else {
            false
        }
    }
    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::SeqCst);
        self.set_draining(true);
    }
    pub(super) fn stopping(&self) -> bool {
        self.shutdown.load(Ordering::SeqCst)
    }
    pub(super) fn reap(&self) {
        let mut tasks = self.recovery_tasks.lock().unwrap();
        while let Some(result) = tasks.try_join_next() {
            if result.is_err() {
                eprintln!("RECOVERY_TASK_FAILED");
            }
        }
    }
    pub(super) fn claim(self: &Arc<Self>, id: String) -> Option<JobRegistration> {
        if !self.owned_jobs.lock().unwrap().insert(id.clone()) {
            return None;
        }
        Some(JobRegistration {
            supervisor: self.clone(),
            id,
        })
    }
    pub(super) fn spawn_recovery(
        &self,
        registration: JobRegistration,
        work: impl Future<Output = ()> + Send + 'static,
    ) {
        self.recovery_tasks.lock().unwrap().spawn(async move {
            let _registration = registration;
            work.await;
        });
    }
    pub async fn join_recovery(&self) {
        let mut tasks = std::mem::replace(
            &mut *self.recovery_tasks.lock().unwrap(),
            tokio::task::JoinSet::new(),
        );
        while let Some(result) = tasks.join_next().await {
            if result.is_err() {
                eprintln!("RECOVERY_TASK_FAILED");
            }
        }
    }
}
pub(super) struct JobRegistration {
    supervisor: Arc<ExecutionSupervisor>,
    id: String,
}
impl Drop for JobRegistration {
    fn drop(&mut self) {
        self.supervisor
            .cancellations
            .lock()
            .unwrap()
            .remove(&self.id);
        self.supervisor.owned_jobs.lock().unwrap().remove(&self.id);
    }
}

pub(super) struct ActiveJob(Arc<Daemon>);
impl ActiveJob {
    pub(super) fn new(daemon: Arc<Daemon>) -> Self {
        daemon.execution.begin_active();
        Self(daemon)
    }
}
impl Drop for ActiveJob {
    fn drop(&mut self) {
        self.0.execution.end_active();
    }
}

pub(super) struct Quiescence(Arc<Daemon>);
impl Quiescence {
    pub(super) fn new(daemon: Arc<Daemon>) -> Self {
        daemon.execution.begin_quiescence();
        Self(daemon)
    }
}
impl Drop for Quiescence {
    fn drop(&mut self) {
        self.0.execution.end_quiescence();
    }
}
pub(super) fn admit(daemon: &Arc<Daemon>) -> Result<Option<Quiescence>> {
    let _lock = daemon.execution.admission_lock()?;
    if daemon.execution.is_draining() || daemon.execution.logout_requested() {
        return Ok(None);
    }

    Ok(Some(Quiescence::new(daemon.clone())))
}
#[derive(Default)]
pub(super) struct ExecutionScope {
    pub(super) finished: Arc<AtomicBool>,
    pub(super) tasks: Mutex<Vec<tokio::task::JoinHandle<()>>>,
    pub(super) evidence: Mutex<Option<Arc<EvidenceIo>>>,
}
impl ExecutionScope {
    pub(super) fn register(&self, task: tokio::task::JoinHandle<()>) {
        self.tasks.lock().unwrap().push(task);
    }
    pub(super) async fn stop(&self) {
        self.finished.store(true, Ordering::SeqCst);
        let tasks = std::mem::take(&mut *self.tasks.lock().unwrap());
        for task in &tasks {
            task.abort();
        }
        for task in tasks {
            let _ = task.await;
        }
        let evidence = self.evidence.lock().unwrap().clone();
        if let Some(evidence) = evidence {
            evidence.wait_idle().await;
        }
    }
}
impl Drop for ExecutionScope {
    fn drop(&mut self) {
        self.finished.store(true, Ordering::SeqCst);
        for task in self.tasks.get_mut().unwrap() {
            task.abort();
        }
    }
}
struct OwnedTask(tokio::task::JoinHandle<()>);
impl Drop for OwnedTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}
struct OwnedWork(tokio::task::JoinHandle<Result<()>>);
impl Drop for OwnedWork {
    fn drop(&mut self) {
        self.0.abort();
    }
}

async fn drain_owned_workers(workers: &mut tokio::task::JoinSet<()>) {
    while workers.join_next().await.is_some() {}
}

const FAST_EMPTY_THRESHOLD: Duration = Duration::from_secs(5);

#[derive(Default)]
struct LeaseIdlePacing {
    fast_empty_streak: usize,
}

impl LeaseIdlePacing {
    fn reset(&mut self) {
        self.fast_empty_streak = 0;
    }

    fn empty_delay(&mut self, elapsed: Duration, jitter_per_mille: u32) -> Duration {
        if elapsed >= FAST_EMPTY_THRESHOLD {
            self.reset();
            return Duration::ZERO;
        }
        debug_assert!((800..=1200).contains(&jitter_per_mille));
        let cycle_seconds = [1, 2, 4, 5][self.fast_empty_streak.min(3)];
        self.fast_empty_streak = (self.fast_empty_streak + 1).min(3);
        // The target is the entire request cycle, not an extra delay after it.
        Duration::from_millis(cycle_seconds * u64::from(jitter_per_mille)).saturating_sub(elapsed)
    }
}

fn lease_job(response: &Value) -> Result<Option<&Value>> {
    let job = response.get("job").context("BACKEND_PROTOCOL_ERROR")?;
    if job.is_null() {
        return Ok(None);
    }
    let id = job
        .as_object()
        .and_then(|object| object.get("id"))
        .and_then(Value::as_str)
        .context("BACKEND_PROTOCOL_ERROR")?;
    Uuid::parse_str(id).map_err(|_| anyhow::anyhow!("BACKEND_PROTOCOL_ERROR"))?;
    Ok(Some(job))
}

async fn wait_for_idle_cycle(
    supervisor: &ExecutionSupervisor,
    reconnect_requested: &AtomicBool,
    delay: Duration,
) -> bool {
    let deadline = TokioInstant::now() + delay;
    loop {
        if supervisor.stopping()
            || supervisor.is_draining()
            || supervisor.logout_requested()
            || reconnect_requested.load(Ordering::SeqCst)
        {
            return false;
        }
        let now = TokioInstant::now();
        if now >= deadline {
            return true;
        }
        // All existing stop flags are observable within 50ms without changing
        // ownership or delaying independently spawned heartbeat/worker tasks.
        tokio::time::sleep_until(deadline.min(now + Duration::from_millis(50))).await;
    }
}

pub async fn run(daemon: Arc<Daemon>) {
    let mut last_sweep = 0;
    let mut running = HashSet::new();
    let mut tasks = tokio::task::JoinSet::new();
    let mut task_organizations = HashMap::new();
    loop {
        daemon.execution.reap();
        if daemon.execution.stopping() {
            break;
        }
        if state::now().saturating_sub(last_sweep) >= 3600 {
            if let Ok(Some(_admission)) = admit(&daemon) {
                let _ = crate::retention::sweep(&daemon.dir, state::now());
                last_sweep = state::now();
            }
        }
        while let Some(result) = tasks.try_join_next_with_id() {
            match result {
                Ok((id, org)) => {
                    running.remove(&org);
                    task_organizations.remove(&id);
                }
                Err(error) => {
                    if let Some(org) = task_organizations.remove(&error.id()) {
                        running.remove(&org);
                    }
                }
            }
        }
        if !daemon.execution.is_draining() && !daemon.execution.logout_requested() {
            if let Ok(orgs) = daemon.auth.enrolled_organizations().await {
                for org in orgs {
                    if running.insert(org.clone()) {
                        let d = daemon.clone();
                        let task_org = org.clone();
                        let handle = tasks.spawn(async move {
                            let _ = session(d, org.clone()).await;
                            org
                        });
                        task_organizations.insert(handle.id(), task_org);
                    }
                }
            }
        }
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }
    while tasks.join_next().await.is_some() {}
    daemon.execution.join_recovery().await;
}
pub(super) async fn session(daemon: Arc<Daemon>, org: String) -> Result<()> {
    let Some(_session_admission) = admit(&daemon)? else {
        return Ok(());
    };
    let manifest = runner_manifest(&daemon).await?;
    let response = daemon
        .backend(
            &org,
            "POST",
            "v1/sessions/",
            Some(json!({"transport":"long_poll","manifest":manifest})),
            None,
        )
        .await?;
    let sid = response["session"]["id"]
        .as_str()
        .context("BACKEND_PROTOCOL_ERROR")?
        .to_string();
    recover(daemon.clone(), &org, &sid).await?;
    let d = daemon.clone();
    let heartbeat_org = org.clone();
    let heartbeat_sid = sid.clone();
    let stop = Arc::new(AtomicBool::new(false));
    let heartbeat_stop = stop.clone();

    let heartbeat_active = Quiescence::new(daemon.clone());
    let heartbeat = OwnedTask(tokio::spawn(async move {
        let _active = heartbeat_active;
        while !heartbeat_stop.load(Ordering::SeqCst) {
            tokio::time::sleep(std::time::Duration::from_secs(15)).await;
            if let Ok(response) = d
                .backend(
                    &heartbeat_org,
                    "POST",
                    &format!("v1/sessions/{heartbeat_sid}/heartbeat/"),
                    Some(json!({"manifest":manifest})),
                    None,
                )
                .await
            {
                apply_cancellations(&d, &response).await;
            }
        }
    }));
    let mut workers = tokio::task::JoinSet::new();
    let reconnect_requested = Arc::new(AtomicBool::new(false));
    let mut idle_pacing = LeaseIdlePacing::default();
    let result: Result<()> = async {
        while !daemon.execution.is_draining()
            && !reconnect_requested.load(Ordering::SeqCst)
        {
            let Some(_lease_admission)=admit(&daemon)? else{break};
            while workers.try_join_next().is_some() {}
            if reconnect_requested.load(Ordering::SeqCst) {
                break;
            }
            let lease_started = Instant::now();
            let counters = &daemon.execution.lease_polls;
            counters.requests.fetch_add(1, Ordering::Relaxed);
            let response = daemon
                .backend(
                    &org,
                    "POST",
                    "v1/jobs/lease/",
                    Some(json!({"sessionId":sid,"waitSeconds":20})),
                    None,
                )
                .await?;
            let elapsed = lease_started.elapsed();
            let job = lease_job(&response).inspect_err(|_| {
                counters.protocol_errors.fetch_add(1, Ordering::Relaxed);
            })?;
            if let Some(job) = job {
                idle_pacing.reset();
                let job = job.clone();
                let id = job["id"]
                    .as_str()
                    .context("BACKEND_PROTOCOL_ERROR")?
                    .to_string();
                let path = daemon.dir.join("jobs").join(&id).join("journal.json");
                if path.exists() {
                    // A server retry never authorizes duplicate local spawn.
                    continue;
                }
                let Some(registration)=daemon.execution.claim(id.clone()) else {continue;};
                let journal = Journal {
                    job,
                    organization: org.clone(),
                    session: sid.clone(),
                    recovery_session: None,
                    phase: JournalPhase::Leased,
                    identity: None,
                    result: None,
                    error: None,
                    terminal_key: Uuid::new_v4().to_string(),
                    started_at: state::now(),
                    acknowledged_at: None,
        delivery_diagnostic: None,
        first_failure_diagnostic: None,
                    lease_requests:Default::default(),event_sender:Default::default(),durable_writer:Default::default(),
                    stdout_pending: None,
                    stderr_pending: None,
                    progress_buffer: Vec::new(),
                    progress_buffer_offset: 0,
                    progress_discarding: false,
                    progress_pending: None,
        public_status_latest: None,
        public_status_pending: None,
        public_status_next_sequence: 0,
        public_status_last_sent_at_ms: 0,
                    stdout_offset: 0,
                    stderr_offset: 0,
                };
                persist(&path, &journal)?;
                let cancellation = Arc::new(AtomicBool::new(false));
                daemon.execution.register_cancellation(id.clone(), cancellation.clone()).await?;

                let d = daemon.clone();
                let worker_reconnect = reconnect_requested.clone();
                let active = ActiveJob::new(d.clone());
                workers.spawn(async move {
                    let _registration=registration;
                    let _active = active;
                    let scope = Arc::new(ExecutionScope::default());
                    let worker_scope = scope.clone();
                    let worker_daemon = d.clone();
                    let worker_path = path.clone();

                    let work_active=Quiescence::new(d.clone());
                    let mut worker = OwnedWork(tokio::spawn(async move {
                        let _active=work_active;
                        work(worker_daemon, worker_path, journal, cancellation, worker_scope).await
                    }));
                    let outcome = (&mut worker.0).await;
                    if matches!(&outcome, Ok(Err(error)) if error.to_string() == "RUNNER_JOB_RECOVERY_SESSION_REQUIRED") {
                        worker_reconnect.store(true, Ordering::SeqCst);
                    }
                    // Even on panic, join every helper before writing a terminal record.
                    scope.stop().await;
                    if outcome.is_err() {
                        if let Ok(mut record) = state::read_json::<Journal>(&path) {
                            if !matches!(record.phase,JournalPhase::Exited|JournalPhase::TerminalPending|JournalPhase::Acknowledged|JournalPhase::DeliveryBlocked) {
                                if record.transition(JournalPhase::TerminalPending).is_err() { return; }
                                record.result = None;
                                record.error = Some(json!({"code":"JOB_TASK_PANICKED","message":"Local task stopped without a confirmed outcome","indeterminate":true}));
                            }
                            if matches!(record.phase,JournalPhase::Acknowledged|JournalPhase::DeliveryBlocked) {return;}

                            if persist(&path, &record).is_ok() {
                                let _ = deliver(d.clone(), &path, Arc::new(Mutex::new(record))).await;
                            }
                        }
                    }
                });
            } else {
                counters.empty_responses.fetch_add(1, Ordering::Relaxed);
                if elapsed < FAST_EMPTY_THRESHOLD {
                    counters.fast_empty_responses.fetch_add(1, Ordering::Relaxed);
                }
                let jitter_per_mille = 800 + rand::random::<u32>() % 401;
                let delay = idle_pacing.empty_delay(elapsed, jitter_per_mille);
                if !delay.is_zero() {
                    counters.paced_waits.fetch_add(1, Ordering::Relaxed);
                    if !wait_for_idle_cycle(&daemon.execution, &reconnect_requested, delay).await {
                        counters.interrupted_waits.fetch_add(1, Ordering::Relaxed);
                        break;
                    }
                }
            }
        }
        Ok(())
    }
    .await;
    drain_owned_workers(&mut workers).await;
    stop.store(true, Ordering::SeqCst);
    heartbeat.0.abort();
    let _ = daemon
        .backend(
            &org,
            "POST",
            &format!("v1/sessions/{sid}/disconnect/"),
            Some(json!({"reason":"daemon drained"})),
            None,
        )
        .await;
    result
}

#[cfg(test)]
mod ownership_tests {
    use super::*;

    #[test]
    fn idle_cycles_escalate_with_bounded_jitter_and_subtract_request_time() {
        for jitter in [800, 1000, 1200] {
            let mut pacing = LeaseIdlePacing::default();
            for seconds in [1, 2, 4, 5, 5, 5] {
                assert_eq!(
                    pacing.empty_delay(Duration::from_millis(200), jitter),
                    Duration::from_millis(seconds * u64::from(jitter) - 200),
                );
            }
        }
        let mut pacing = LeaseIdlePacing::default();
        assert_eq!(
            pacing.empty_delay(Duration::from_millis(1200), 800),
            Duration::ZERO,
        );
        assert_eq!(
            pacing.empty_delay(Duration::from_millis(100), 1000),
            Duration::from_millis(1900),
        );
    }

    #[test]
    fn idle_cycle_resets_after_a_job_or_real_backend_wait() {
        let mut pacing = LeaseIdlePacing::default();
        pacing.empty_delay(Duration::ZERO, 1000);
        pacing.empty_delay(Duration::ZERO, 1000);
        pacing.reset(); // The job branch resets before deduplication/admission.
        assert_eq!(
            pacing.empty_delay(Duration::ZERO, 1000),
            Duration::from_secs(1)
        );
        assert_eq!(
            pacing.empty_delay(Duration::from_secs(5), 1200),
            Duration::ZERO,
        );
        assert_eq!(
            pacing.empty_delay(Duration::ZERO, 1000),
            Duration::from_secs(1)
        );
        assert_eq!(
            pacing.empty_delay(Duration::from_secs(20), 1200),
            Duration::ZERO,
        );
        assert_eq!(
            pacing.empty_delay(Duration::ZERO, 1000),
            Duration::from_secs(1)
        );
    }

    #[test]
    fn only_explicit_null_is_an_empty_lease_and_protocol_errors_are_sanitized() {
        assert!(lease_job(&json!({"job":null})).unwrap().is_none());
        let valid = json!({"job":{"id":"11111111-1111-4111-8111-111111111111"}});
        assert_eq!(lease_job(&valid).unwrap(), valid.get("job"));
        for malformed in [
            Value::Null,
            json!({"private":"secret backend data"}),
            json!({"job":false}),
            json!({"job":42}),
            json!({"job":"secret backend data"}),
            json!({"job":[]}),
            json!({"job":{}}),
            json!({"job":{"id":null}}),
            json!({"job":{"id":"secret backend data"}}),
        ] {
            assert_eq!(
                lease_job(&malformed).unwrap_err().to_string(),
                "BACKEND_PROTOCOL_ERROR"
            );
        }
    }

    #[tokio::test]
    async fn idle_wait_observes_every_stop_signal_within_100ms() {
        for signal in ["drain", "logout", "shutdown", "reconnect"] {
            let supervisor = Arc::new(ExecutionSupervisor::new(false));
            let reconnect = Arc::new(AtomicBool::new(false));
            let waiting_supervisor = supervisor.clone();
            let waiting_reconnect = reconnect.clone();
            let (started, ready) = tokio::sync::oneshot::channel();
            let waiter = tokio::spawn(async move {
                let _ = started.send(());
                wait_for_idle_cycle(
                    &waiting_supervisor,
                    &waiting_reconnect,
                    Duration::from_secs(6),
                )
                .await
            });
            ready.await.unwrap();
            // This sibling continues to run while the lease loop is sleeping.
            tokio::task::yield_now().await;
            match signal {
                "drain" => supervisor.set_draining(true),
                "logout" => supervisor.set_logout_requested(true),
                "shutdown" => supervisor.shutdown(),
                "reconnect" => reconnect.store(true, Ordering::SeqCst),
                _ => unreachable!(),
            }
            assert!(
                !tokio::time::timeout(Duration::from_millis(100), waiter)
                    .await
                    .unwrap()
                    .unwrap(),
                "{signal}"
            );
        }
    }

    #[tokio::test]
    async fn idle_wait_finishes_normally_and_already_stopped_wait_never_sleeps() {
        let supervisor = ExecutionSupervisor::new(false);
        let reconnect = AtomicBool::new(false);
        assert!(wait_for_idle_cycle(&supervisor, &reconnect, Duration::from_millis(1)).await);
        supervisor.set_logout_requested(true);
        assert!(
            !tokio::time::timeout(
                Duration::from_millis(20),
                wait_for_idle_cycle(&supervisor, &reconnect, Duration::from_secs(6)),
            )
            .await
            .unwrap()
        );
    }

    #[test]
    fn lease_poll_diagnostics_are_only_fixed_numeric_counters() {
        let supervisor = ExecutionSupervisor::new(false);
        supervisor
            .lease_polls
            .requests
            .fetch_add(7, Ordering::Relaxed);
        supervisor
            .lease_polls
            .empty_responses
            .fetch_add(6, Ordering::Relaxed);
        assert_eq!(
            supervisor.lease_poll_diagnostics(),
            json!({
                "requests":7,"emptyResponses":6,"fastEmptyResponses":0,
                "pacedWaits":0,"interruptedWaits":0,"protocolErrors":0,
            })
        );
    }

    #[tokio::test]
    async fn fast_empty_lease_does_not_immediately_poll_again() {
        use super::super::protocol_tests::{daemon, receive, reply};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let temp = tempfile::tempdir().unwrap();
        let daemon = daemon(
            temp.path(),
            format!("http://{}", listener.local_addr().unwrap()),
        );
        let session_daemon = daemon.clone();
        let session = tokio::spawn(async move { session(session_daemon, "org".into()).await });
        let (stream, _) = receive(&listener).await;
        reply(stream, json!({"session":{"id":"session"}})).await;
        let (stream, body) = receive(&listener).await;
        assert_eq!(body, json!({"sessionId":"session","waitSeconds":20}));
        reply(stream, json!({"job":null})).await;
        assert!(
            tokio::time::timeout(Duration::from_millis(250), receive(&listener))
                .await
                .is_err()
        );
        assert_eq!(
            daemon.execution.lease_poll_diagnostics(),
            json!({
                "requests":1,"emptyResponses":1,"fastEmptyResponses":1,
                "pacedWaits":1,"interruptedWaits":0,"protocolErrors":0,
            })
        );
        daemon.execution.shutdown();
        let (stream, body) = tokio::time::timeout(Duration::from_millis(100), receive(&listener))
            .await
            .unwrap();
        assert_eq!(body, json!({"reason":"daemon drained"}));
        reply(stream, json!({})).await;
        session.await.unwrap().unwrap();
        assert_eq!(
            daemon.execution.lease_poll_diagnostics()["interruptedWaits"],
            1
        );
    }

    #[tokio::test]
    async fn missing_lease_job_is_a_protocol_error_without_repolling() {
        use super::super::protocol_tests::{daemon, receive, reply};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let temp = tempfile::tempdir().unwrap();
        let daemon = daemon(
            temp.path(),
            format!("http://{}", listener.local_addr().unwrap()),
        );
        let session = tokio::spawn(async move { session(daemon, "org".into()).await });
        let (stream, _) = receive(&listener).await;
        reply(stream, json!({"session":{"id":"session"}})).await;
        let (stream, _) = receive(&listener).await;
        reply(stream, json!({"private":"backend response detail"})).await;
        let (stream, body) = receive(&listener).await;
        assert_eq!(body, json!({"reason":"daemon drained"}));
        reply(stream, json!({})).await;
        assert_eq!(
            session.await.unwrap().unwrap_err().to_string(),
            "BACKEND_PROTOCOL_ERROR"
        );
    }

    #[tokio::test]
    async fn reconnect_drain_preserves_healthy_sibling_until_it_finishes() {
        let reconnect = Arc::new(AtomicBool::new(false));
        let healthy_finished = Arc::new(AtomicBool::new(false));
        let healthy_release = Arc::new(tokio::sync::Semaphore::new(0));
        let mut workers = tokio::task::JoinSet::new();
        let stale_flag = reconnect.clone();
        workers.spawn(async move {
            stale_flag.store(true, Ordering::SeqCst);
        });
        let sibling_release = healthy_release.clone();
        let sibling_finished = healthy_finished.clone();
        workers.spawn(async move {
            sibling_release.acquire().await.unwrap().forget();
            sibling_finished.store(true, Ordering::SeqCst);
        });
        tokio::time::timeout(Duration::from_secs(1), async {
            while !reconnect.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let drain = tokio::spawn(async move { drain_owned_workers(&mut workers).await });
        tokio::task::yield_now().await;
        assert!(!drain.is_finished());
        assert!(!healthy_finished.load(Ordering::SeqCst));
        healthy_release.add_permits(1);
        drain.await.unwrap();
        assert!(healthy_finished.load(Ordering::SeqCst));
    }
    #[tokio::test]
    async fn one_job_owner_releases_cancellation_on_drop() {
        let s = Arc::new(ExecutionSupervisor::new(false));
        let guard = s.claim("job".into()).unwrap();
        assert!(s.claim("job".into()).is_none());
        let token = Arc::new(AtomicBool::new(false));
        s.register_cancellation("job".into(), token.clone())
            .await
            .unwrap();
        assert!(s.cancel("job").await);
        assert!(token.load(Ordering::SeqCst));
        drop(guard);
        assert!(!s.cancel("job").await);
        assert!(s.claim("job".into()).is_some());
    }
    #[tokio::test]
    async fn recovery_panic_is_joined_and_releases_ownership() {
        let s = Arc::new(ExecutionSupervisor::new(false));
        let guard = s.claim("job".into()).unwrap();
        s.spawn_recovery(guard, async {
            panic!("injected");
        });
        s.join_recovery().await;
        assert!(s.claim("job".into()).is_some());
    }
    #[test]
    fn closed_drain_cannot_be_reopened_by_control_registration() {
        let s = ExecutionSupervisor::new(true);
        assert!(s.join_drain().is_err());
        s.begin_active();
        s.join_drain().unwrap();
        assert_eq!(s.managed_work(), 2);
        s.end_control();
        s.end_active();
        assert_eq!(s.managed_work(), 0);
        assert!(s.join_drain().is_err());
    }
}
