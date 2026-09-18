use super::*;
use crate::{api::Api, auth::Auth, state::WorkspaceGrant};

#[test]
fn unavailable_provider_binary_fixture_never_discovers_or_executes_a_provider() {
    let temp = tempfile::tempdir().unwrap();
    let missing = temp.path().join("missing-provider-binary");
    assert!(find_executable(missing.to_str().unwrap()).is_none());
    assert!(!missing.exists());
}

#[tokio::test]
async fn provider_snapshot_drift_rejects_a_prepared_binding_deterministically() {
    let temp = tempfile::tempdir().unwrap();
    let workspace = temp.path().join("workspace");
    std::fs::create_dir(&workspace).unwrap();
    let workspace = std::fs::canonicalize(workspace).unwrap();
    let api = Api::for_test_origin("http://127.0.0.1:9").unwrap();
    let daemon = Daemon::new(
        temp.path().join("state"),
        api.clone(),
        Auth::test_enrolled(api, "org", "runner"),
    )
    .unwrap();
    let install = daemon.auth.installation_id().await.unwrap();
    daemon
        .public
        .lock()
        .await
        .grants
        .push(WorkspaceGrant::new(&workspace, "org", &install, "key").unwrap());
    let prepared_snapshot = json!({
        "gemini": {
            "path": "/fixture/gemini",
            "adapter": "gemini",
            "checksumSha256": "fixture-before",
            "sizeBytes": 1,
            "modifiedNanos": "1",
            "executionPolicy": "host_user/v1"
        }
    });
    let config = json!({"requested": {}, "installed": prepared_snapshot});
    let preparation = Uuid::new_v4();
    let journal = Journal {
        job: json!({"id":Uuid::new_v4(),"kind":"command.run","payload":{"preparationId":preparation,"bindingDigest":"exact-binding","executionPolicy":"host_user/v1","workspacePath":workspace,"providerConfiguration":config,"command":["/usr/bin/true"]}}),
        organization: "org".into(),
        session: "session".into(),
        recovery_session: None,
        phase: JournalPhase::Leased,
        identity: None,
        result: None,
        error: None,
        terminal_key: "terminal".into(),
        started_at: 0,
        acknowledged_at: None,
        event_sender: Default::default(),
        stdout_pending: None,
        stderr_pending: None,
        progress_buffer: Vec::new(),
        progress_buffer_offset: 0,
        progress_discarding: false,
        progress_pending: None,
        stdout_offset: 0,
        stderr_offset: 0,
    };
    state::write_json(
        &daemon
            .dir
            .join("preparations")
            .join(format!("{preparation}.json")),
        &json!({
            "organizationId":"org",
            "installationId":install,
            "workspacePath":workspace,
            "bindingDigest":"exact-binding",
            "binding":{"executionPolicy":"host_user/v1","providerConfiguration":config},
            "providers":prepared_snapshot,
            "commitAuthorization":{"preparationId":preparation,"bindingDigest":"exact-binding"}
        }),
    )
    .unwrap();
    assert_eq!(
        require_execution_authorization_with(&daemon, &journal, || Ok(prepared_snapshot.clone()))
            .await
            .unwrap(),
        workspace
    );
    let changed_snapshot = json!({
        "gemini": {
            "path": "/fixture/gemini",
            "adapter": "gemini",
            "checksumSha256": "fixture-after",
            "sizeBytes": 1,
            "modifiedNanos": "2",
            "executionPolicy": "host_user/v1"
        }
    });
    assert_eq!(
        require_execution_authorization_with(&daemon, &journal, || Ok(changed_snapshot))
            .await
            .unwrap_err()
            .to_string(),
        "PROVIDER_CONFIGURATION_CHANGED"
    );
}

#[tokio::test]
async fn workspace_choice_never_substitutes_for_confirmed_preparation() {
    let temp = tempfile::tempdir().unwrap();
    let workspace = temp.path().join("workspace");
    std::fs::create_dir(&workspace).unwrap();
    let workspace = std::fs::canonicalize(workspace).unwrap();
    let api = Api::for_test_origin("http://127.0.0.1:9").unwrap();
    let daemon = Daemon::new(
        temp.path().join("state"),
        api.clone(),
        Auth::test_enrolled(api, "org", "runner"),
    )
    .unwrap();
    let install = daemon.auth.installation_id().await.unwrap();
    daemon
        .public
        .lock()
        .await
        .grants
        .push(WorkspaceGrant::new(&workspace, "org", &install, "key").unwrap());
    let prep = Uuid::new_v4();
    let providers = provider_snapshot().unwrap();
    let config = json!({"requested":{},"installed":providers});
    let mut j = Journal {
        job: json!({"id":Uuid::new_v4(),"kind":"command.run","payload":{"preparationId":prep,"bindingDigest":"exact-binding","executionPolicy":"host_user/v1","workspacePath":workspace,"providerConfiguration":config,"command":["/usr/bin/true"]}}),
        organization: "org".into(),
        session: "session".into(),
        recovery_session: None,
        phase: JournalPhase::Leased,
        identity: None,
        result: None,
        error: None,
        terminal_key: "terminal".into(),
        started_at: 0,
        acknowledged_at: None,
        event_sender: Default::default(),
        stdout_pending: None,
        stderr_pending: None,
        progress_buffer: Vec::new(),
        progress_buffer_offset: 0,
        progress_discarding: false,
        progress_pending: None,
        stdout_offset: 0,
        stderr_offset: 0,
    };
    assert!(require_execution_authorization(&daemon, &j).await.is_err());
    let path = daemon.dir.join("preparations").join(format!("{prep}.json"));
    let mut record = json!({"organizationId":"org","installationId":install,"workspacePath":workspace,"bindingDigest":"exact-binding","binding":{"executionPolicy":"host_user/v1","providerConfiguration":config},"providers":providers});
    state::write_json(&path, &record).unwrap();
    assert!(require_execution_authorization(&daemon, &j).await.is_err());
    record["commitAuthorization"] = json!({"preparationId":prep,"bindingDigest":"exact-binding","idempotencyKey":Uuid::new_v4(),"authorizedAt":state::now()});
    state::write_json(&path, &record).unwrap();
    assert_eq!(
        require_execution_authorization(&daemon, &j).await.unwrap(),
        workspace
    );
    j.job["payload"]["bindingDigest"] = json!("changed");
    assert!(require_execution_authorization(&daemon, &j).await.is_err());
    j.job["payload"]["bindingDigest"] = json!("exact-binding");
    j.job["payload"]["command"] = json!("touch unauthorized");
    j.job["payload"]["shell"] = json!(true);
    j.job["payloadDigest"] = json!(state::json_digest(&j.job["payload"]));
    let journal_path = daemon
        .dir
        .join("jobs")
        .join(Uuid::new_v4().to_string())
        .join("journal.json");
    let shared = Arc::new(Mutex::new(j));
    let error = execute_job(
        Arc::new(daemon),
        &journal_path,
        shared,
        Arc::new(AtomicBool::new(false)),
        Arc::new(ExecutionScope::default()),
    )
    .await
    .unwrap_err();
    assert_eq!(error.to_string(), "INVALID_COMMAND");
    assert!(!workspace.join("unauthorized").exists());
}
#[tokio::test]
async fn active_accounting_survives_task_panic() {
    let t = tempfile::tempdir().unwrap();
    let api = Api::for_test_origin("http://127.0.0.1:9").unwrap();
    let d = Arc::new(Daemon::new(t.path().into(), api.clone(), Auth::test_unauthed(api)).unwrap());

    let copy = d.clone();
    let task = tokio::spawn(async move {
        let _active = ActiveJob::new(copy);
        panic!("synthetic worker failure")
    });
    assert!(task.await.is_err());
    assert_eq!(d.execution.active_work(), 0);
}
