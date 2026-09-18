//! One owner for admission accounting, cancellation registration and recovery tasks.
use super::*;

pub struct ExecutionSupervisor {
    draining: AtomicBool,
    active: std::sync::atomic::AtomicUsize,
    quiescence: std::sync::atomic::AtomicUsize,
    managed: std::sync::atomic::AtomicUsize,
    admission: Mutex<()>,
    cancellations: Mutex<HashMap<String, Arc<AtomicBool>>>,
    recovery_tasks: Mutex<tokio::task::JoinSet<()>>,
    owned_jobs: Mutex<HashSet<String>>,
    shutdown: AtomicBool,
}
impl ExecutionSupervisor {
    pub fn new(draining: bool) -> Self {
        Self {
            draining: AtomicBool::new(draining),
            active: Default::default(),
            quiescence: Default::default(),
            managed: Default::default(),
            admission: Mutex::new(()),
            cancellations: Default::default(),
            recovery_tasks: Mutex::new(tokio::task::JoinSet::new()),
            owned_jobs: Default::default(),
            shutdown: AtomicBool::new(false),
        }
    }
    pub fn is_draining(&self) -> bool {
        self.draining.load(Ordering::SeqCst)
    }
    pub fn set_draining(&self, value: bool) {
        self.draining.store(value, Ordering::SeqCst);
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
    if daemon.execution.is_draining() {
        return Ok(None);
    }

    Ok(Some(Quiescence::new(daemon.clone())))
}
#[derive(Default)]
pub(super) struct ExecutionScope {
    pub(super) finished: Arc<AtomicBool>,
    pub(super) tasks: Mutex<Vec<tokio::task::JoinHandle<()>>>,
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
        if !daemon.execution.is_draining() {
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
    let manifest = runner_manifest();
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
    let result: Result<()> = async {
        while !daemon.execution.is_draining() {
            let Some(_lease_admission)=admit(&daemon)? else{break};
            while workers.try_join_next().is_some() {}
            let response = daemon
                .backend(
                    &org,
                    "POST",
                    "v1/jobs/lease/",
                    Some(json!({"sessionId":sid,"waitSeconds":20})),
                    None,
                )
                .await?;
            if let Some(job) = response.get("job").filter(|v| !v.is_null()) {
                let job = job.clone();
                let id = job["id"]
                    .as_str()
                    .context("BACKEND_PROTOCOL_ERROR")?
                    .to_string();
                Uuid::parse_str(&id)?;
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
                    event_sender:Default::default(),
                    stdout_pending: None,
                    stderr_pending: None,
                    progress_buffer: Vec::new(),
                    progress_buffer_offset: 0,
                    progress_discarding: false,
                    progress_pending: None,
                    stdout_offset: 0,
                    stderr_offset: 0,
                };
                persist(&path, &journal)?;
                let cancellation = Arc::new(AtomicBool::new(false));
                daemon.execution.register_cancellation(id.clone(), cancellation.clone()).await?;

                let d = daemon.clone();
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
            }
        }
        Ok(())
    }
    .await;
    while workers.join_next().await.is_some() {}
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
