use super::*;
use crate::{api::Api, auth::Auth};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
async fn receive_with_headers(listener: &TcpListener) -> (TcpStream, String, Value) {
    let (mut stream, _) = listener.accept().await.unwrap();
    let mut bytes = Vec::new();
    loop {
        let mut buf = [0; 8192];
        let n = stream.read(&mut buf).await.unwrap();
        assert!(n > 0);
        bytes.extend_from_slice(&buf[..n]);
        if let Some(end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&bytes[..end]);
            let length = head
                .lines()
                .find_map(|l| {
                    l.to_ascii_lowercase()
                        .strip_prefix("content-length: ")
                        .map(|s| s.parse::<usize>().unwrap())
                })
                .unwrap();
            if bytes.len() >= end + 4 + length {
                return (
                    stream,
                    head.into_owned(),
                    serde_json::from_slice(&bytes[end + 4..]).unwrap(),
                );
            }
        }
    }
}
pub(super) async fn receive(listener: &TcpListener) -> (TcpStream, Value) {
    let (stream, _, body) = receive_with_headers(listener).await;
    (stream, body)
}
pub(super) async fn reply(mut stream: TcpStream, data: Value) {
    let body = json!({"data":data,"meta":{}}).to_string();
    stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{}",body.len(),body).as_bytes()).await.unwrap();
}
async fn reply_error(mut stream: TcpStream, code: &str) {
    let body = json!({"error":{"code":code},"meta":{}}).to_string();
    stream.write_all(format!("HTTP/1.1 422 Unprocessable Entity\r\nContent-Length: {}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{}",body.len(),body).as_bytes()).await.unwrap();
}
pub(super) fn journal() -> Journal {
    Journal {
        job: json!({"id":"11111111-1111-4111-8111-111111111111","idempotencyKey":"original-job-key","leaseVersion":7,"leasedUntilEpochMs":2000000000000u64,"payloadDigest":"digest","createdByExecutionId":"22222222-2222-4222-8222-222222222222","createdByNodeExecutionId":null,"payload":{"command":["/bin/sh","-c","exit 99"]}}),
        organization: "org".into(),
        session: "old-session".into(),
        recovery_session: None,
        phase: JournalPhase::Running,
        identity: None,
        result: None,
        error: None,
        terminal_key: "persistent-terminal-key".into(),
        started_at: 0,
        acknowledged_at: None,
        delivery_diagnostic: None,
        first_failure_diagnostic: None,
        event_sender: Default::default(),
        durable_writer: Default::default(),
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
    }
}
pub(super) fn daemon(path: &Path, origin: String) -> Arc<Daemon> {
    let api = Api::for_test_origin(&origin).unwrap();
    Arc::new(
        Daemon::new(
            path.into(),
            api.clone(),
            Auth::test_enrolled(api, "org", "runner"),
        )
        .unwrap(),
    )
}
#[test]
fn older_terminal_journals_remain_readable_without_invented_diagnostics() {
    let mut old = serde_json::to_value(journal()).unwrap();
    old["phase"] = json!("delivery_blocked");
    old.as_object_mut().unwrap().remove("deliveryDiagnostic");
    old.as_object_mut()
        .unwrap()
        .remove("firstFailureDiagnostic");
    let decoded: Journal = serde_json::from_value(old).unwrap();
    assert_eq!(decoded.phase, JournalPhase::DeliveryBlocked);
    assert!(decoded.delivery_diagnostic.is_none());
    assert!(decoded.first_failure_diagnostic.is_none());
    assert!(decoded.public_status_latest.is_none());
    assert!(decoded.public_status_pending.is_none());
    assert!(
        serde_json::to_value(decoded)
            .unwrap()
            .get("deliveryDiagnostic")
            .is_none()
    );
}

#[test]
fn unqualified_public_status_is_not_advertised_or_injected_for_a_sealed_job() {
    let mut record = journal();
    record.job["payload"]["publicStatus"] =
        json!({"schemaVersion":"ai.public-status/v1","enabled":true});
    assert!(enabled(&record.job));
    record.job["payload"]["provider"] = json!("codex");
    assert!(codex_opted_in(&record.job));
    assert!(!dispatch_enabled(&record.job));
    record.job["payload"]["provider"] = json!("claude");
    assert!(enabled(&record.job));
    assert!(!codex_opted_in(&record.job));
    assert!(!dispatch_enabled(&record.job));
    assert_eq!(
        runner_manifest_with_memory(false)["capabilities"]["ai.public-status/v1"],
        false
    );
    assert_eq!(
        runner_manifest_with_memory(false)["capabilities"]["shell.exec"],
        true
    );
    assert_eq!(
        runner_manifest_with_memory(false)["capabilities"]["codex.native-projected-json/v3"],
        true
    );
}

#[tokio::test]
async fn public_status_capability_is_job_scoped_and_retires_with_process() {
    let temp = tempfile::tempdir().unwrap();
    let d = daemon(&temp.path().join("state"), "http://127.0.0.1:1".into());
    let mut record = journal();
    record.job["payload"]["publicStatus"] =
        json!({"schemaVersion":"ai.public-status/v1","enabled":true});
    record.job["createdByNodeExecutionId"] = json!("33333333-3333-4333-8333-333333333333");
    let path = d.dir.join("jobs").join("public-test").join("journal.json");
    state::write_json(&path, &record).unwrap();
    let shared = Arc::new(Mutex::new(record));
    let server = StatusServer::start(&d, &path, shared.clone()).unwrap();
    let capability: serde_json::Value = state::read_json(&server.capability_file).unwrap();
    let send = |token: String| {
        let socket = server.socket.clone();
        async move {
            let mut stream = tokio::net::UnixStream::connect(socket).await.unwrap();
            stream
                .write_all(
                    format!(
                        "{}\n",
                        json!({"token":token,"message":"  Drafting a plan  "})
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
            let mut response = String::new();
            tokio::io::BufReader::new(stream)
                .read_line(&mut response)
                .await
                .unwrap();
            serde_json::from_str::<Value>(&response).unwrap()
        }
    };
    // One same-user half-open client must not block another tool call.
    let _idle_client = tokio::net::UnixStream::connect(&server.socket)
        .await
        .unwrap();
    assert_eq!(send("wrong-token".into()).await["ok"], false);
    assert!(snapshot(&shared).unwrap().public_status_latest.is_none());
    assert_eq!(
        tokio::time::timeout(
            Duration::from_secs(1),
            send(capability["token"].as_str().unwrap().into())
        )
        .await
        .unwrap()["ok"],
        true
    );
    assert_eq!(
        snapshot(&shared).unwrap().public_status_latest.unwrap()["text"],
        "Drafting a plan"
    );
    {
        let mut locked = shared.lock().unwrap();
        locked.phase = JournalPhase::Exited;
        persist(&path, &locked).unwrap();
    }
    assert_eq!(
        send(capability["token"].as_str().unwrap().into()).await["ok"],
        false
    );
    drop(server);
    assert!(
        !path
            .parent()
            .unwrap()
            .join(capability["socket"].as_str().unwrap())
            .exists()
    );
}

#[tokio::test]
async fn public_status_codex_config_is_additive_and_keeps_final_prompt() {
    let temp = tempfile::tempdir().unwrap();
    let d = daemon(&temp.path().join("state"), "http://127.0.0.1:1".into());
    let record = journal();
    let path = d
        .dir
        .join("jobs")
        .join("public-config")
        .join("journal.json");
    state::write_json(&path, &record).unwrap();
    let shared = Arc::new(Mutex::new(record));
    let server = StatusServer::start(&d, &path, shared.clone()).unwrap();
    let original = vec![
        "codex".into(),
        "exec".into(),
        "--json".into(),
        "final prompt".into(),
    ];
    let mut request = ExecutionRequest {
        job_id: "public-config".into(),
        workspace: temp.path().into(),
        additional_workspaces: Vec::new(),
        cwd: None,
        argv: original.clone(),
        env: Default::default(),
        output_dir: path.parent().unwrap().into(),
        policy: "host_user/v1".into(),
        observer: Arc::new(Observer {
            path: path.clone(),
            journal: shared,
        }),
    };
    server.configure_request(&mut request, "codex").unwrap();
    assert_eq!(&request.argv[..3], &original[..3]);
    assert_eq!(request.argv.last().unwrap(), "final prompt");
    assert_eq!(request.argv.iter().filter(|arg| *arg == "-c").count(), 3);
    assert!(
        request
            .argv
            .iter()
            .any(|arg| arg.contains("--internal-public-status-mcp"))
    );
    assert!(
        !request
            .argv
            .iter()
            .any(|arg| arg.contains("public-status-sockets"))
    );
}

#[tokio::test]
async fn public_status_close_fences_an_already_connected_handler_before_terminal_transition() {
    let temp = tempfile::tempdir().unwrap();
    let d = daemon(&temp.path().join("state"), "http://127.0.0.1:1".into());
    let mut record = journal();
    record.job["payload"]["publicStatus"] =
        json!({"schemaVersion":"ai.public-status/v1","enabled":true});
    record.job["createdByNodeExecutionId"] = json!("33333333-3333-4333-8333-333333333333");
    let path = d.dir.join("jobs").join("public-close").join("journal.json");
    state::write_json(&path, &record).unwrap();
    let shared = Arc::new(Mutex::new(record));
    let server = StatusServer::start(&d, &path, shared.clone()).unwrap();
    let mut connected = tokio::net::UnixStream::connect(&server.socket)
        .await
        .unwrap();
    let capability: Value = state::read_json(&server.capability_file).unwrap();
    let gate = server.gate.clone();
    // The connection is accepted but has not submitted a complete message.
    // Closing is synchronous even while the journal still says Running.
    drop(server);
    assert!(!*gate.lock().unwrap());
    assert!(accept_if_open(&gate, &path, &shared, "late status").is_err());
    let _ = connected
        .write_all(
            format!(
                "{}\n",
                json!({
                    "token":capability["token"],"message":"late status"
                })
            )
            .as_bytes(),
        )
        .await;
    tokio::task::yield_now().await;
    assert_eq!(snapshot(&shared).unwrap().phase, JournalPhase::Running);
    assert!(snapshot(&shared).unwrap().public_status_latest.is_none());
}

#[tokio::test]
async fn public_status_event_keeps_exact_identity_after_ambiguous_send() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let temp = tempfile::tempdir().unwrap();
    let d = daemon(
        &temp.path().join("state"),
        format!("http://{}", listener.local_addr().unwrap()),
    );
    let mut record = journal();
    record.job["payload"]["publicStatus"] =
        json!({"schemaVersion":"ai.public-status/v1","enabled":true});
    record.job["createdByNodeExecutionId"] = json!("33333333-3333-4333-8333-333333333333");
    let path = d.dir.join("jobs").join("public-event").join("journal.json");
    state::write_json(&path, &record).unwrap();
    let shared = Arc::new(Mutex::new(record));
    accept_status(&path, &shared, "Reviewing the draft").unwrap();
    let first_d = d.clone();
    let first_p = path.clone();
    let first_j = shared.clone();
    let first = tokio::spawn(async move { stream_events(&first_d, &first_p, &first_j).await });
    let (stream, sent) = receive(&listener).await;
    assert_eq!(sent["events"][0]["eventType"], "ai.public-status.v1");
    assert_eq!(
        sent["events"][0]["payload"]["eventId"],
        "11111111-1111-4111-8111-111111111111:public-status:1"
    );
    assert_eq!(sent["events"][0]["payload"]["provenance"], "ai_reported");
    drop(stream);
    // Advisory delivery failure is retained without failing required output
    // or terminal delivery.
    assert!(!first.await.unwrap().unwrap());
    let recovered = Arc::new(Mutex::new(state::read_json::<Journal>(&path).unwrap()));
    let retry_d = d.clone();
    let retry_p = path.clone();
    let retry_j = recovered.clone();
    let retry = tokio::spawn(async move { stream_events(&retry_d, &retry_p, &retry_j).await });
    let (stream, replay) = receive(&listener).await;
    assert_eq!(sent, replay);
    reply(stream, json!({})).await;
    assert!(retry.await.unwrap().unwrap());
    assert!(
        snapshot(&recovered)
            .unwrap()
            .public_status_pending
            .is_none()
    );
}

#[tokio::test]
async fn rejected_advisory_status_never_changes_terminal_result_or_fence() {
    for (terminal_rejected, status_stalled, auth_stalled) in [
        (false, false, false),
        (true, false, false),
        (false, true, false),
        (false, false, true),
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let temp = tempfile::tempdir().unwrap();
        let d = daemon(
            &temp.path().join("state"),
            format!("http://{}", listener.local_addr().unwrap()),
        );
        let mut record = journal();
        record.job["kind"] = json!("shell.exec");
        record.job["payload"]["provider"] = json!("codex");
        record.job["payload"]["publicStatus"] =
            json!({"schemaVersion":"ai.public-status/v1","enabled":true});
        record.job["createdByNodeExecutionId"] = json!("33333333-3333-4333-8333-333333333333");
        let path = d
            .dir
            .join("jobs")
            .join("advisory-terminal")
            .join("journal.json");
        let stdout = path.parent().unwrap().join("stdout");
        let stderr = path.parent().unwrap().join("stderr");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&stdout, []).unwrap();
        std::fs::write(&stderr, []).unwrap();
        let process_result = json!({"exitCode":0,"cancelled":false,"timedOut":false,"stdoutPath":stdout,"stderrPath":stderr});
        record.result = Some(process_result.clone());
        state::write_json(&path, &record).unwrap();
        let shared = Arc::new(Mutex::new(record));
        accept_status(&path, &shared, "Preparing the result").unwrap();
        {
            let mut locked = shared.lock().unwrap();
            locked.transition(JournalPhase::Exited).unwrap();
            persist(&path, &locked).unwrap();
        }

        let final_d = d.clone();
        let final_p = path.clone();
        let final_j = shared.clone();
        let credential_gate = if auth_stalled {
            Some(d.auth.test_hold_credential_gate().await)
        } else {
            None
        };
        let finalization =
            tokio::spawn(async move { initial_finalization(&final_d, &final_p, &final_j).await });
        let stalled_status_stream = if auth_stalled {
            // The optional send is stuck before HTTP in credential acquisition;
            // the total status budget still releases finalization.
            tokio::time::sleep(Duration::from_millis(3200)).await;
            assert!(snapshot(&shared).unwrap().public_status_pending.is_some());
            drop(credential_gate);
            None
        } else {
            let (stream, status_body) = receive(&listener).await;
            assert_eq!(status_body["events"][0]["eventType"], "ai.public-status.v1");
            if status_stalled {
                Some(stream)
            } else {
                reply_error(stream, "PUBLIC_STATUS_REJECTED").await;
                None
            }
        };
        for stream_name in ["stdout", "stderr"] {
            let (stream, start) = receive(&listener).await;
            assert_eq!(start["sizeBytes"], 0);
            assert!(start["name"].as_str().unwrap().contains(stream_name));
            reply(
                stream,
                json!({"transferId":format!("transfer-{stream_name}"),"offset":0}),
            )
            .await;
            let (stream, complete) = receive(&listener).await;
            assert_eq!(complete, json!({}));
            reply(
                stream,
                json!({"artifactId":format!("artifact-{stream_name}")}),
            )
            .await;
        }
        finalization.await.unwrap().unwrap();
        assert_eq!(
            snapshot(&shared).unwrap().phase,
            JournalPhase::TerminalPending
        );
        let finalized_result = snapshot(&shared).unwrap().result.unwrap();
        assert_eq!(finalized_result["exitCode"], 0);
        assert_eq!(finalized_result["stdoutArtifactId"], "artifact-stdout");
        assert_eq!(finalized_result["stderrArtifactId"], "artifact-stderr");
        assert!(finalized_result.get("stdoutPath").is_none());
        assert!(snapshot(&shared).unwrap().public_status_pending.is_some());

        let delivery_d = d.clone();
        let delivery_p = path.clone();
        let delivery_j = shared.clone();
        let terminal =
            tokio::spawn(async move { deliver(delivery_d, &delivery_p, delivery_j).await });
        let (stream, body) = receive(&listener).await;
        assert_eq!(body["sessionId"], "old-session");
        assert_eq!(body["leaseVersion"], 7);
        assert_eq!(body["result"], finalized_result);
        assert!(body.get("error").is_none());
        if terminal_rejected {
            reply_error(stream, "RUNNER_PROOF_INVALID").await;
            assert!(terminal.await.unwrap().is_err());
            assert_eq!(
                snapshot(&shared).unwrap().phase,
                JournalPhase::DeliveryBlocked
            );
            assert_eq!(snapshot(&shared).unwrap().result, Some(finalized_result));
        } else {
            reply(stream, json!({})).await;
            terminal.await.unwrap().unwrap();
            assert_eq!(snapshot(&shared).unwrap().phase, JournalPhase::Acknowledged);
        }
        drop(stalled_status_stream);
    }
}

#[test]
fn public_status_acceptance_requires_exact_opt_in_and_live_authority() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("journal.json");
    let mut record = journal();
    record.job["createdByNodeExecutionId"] = json!("33333333-3333-4333-8333-333333333333");
    let shared = Arc::new(Mutex::new(record));
    state::write_json(&path, &snapshot(&shared).unwrap()).unwrap();
    assert!(accept_status(&path, &shared, "ready").is_err());
    {
        let mut locked = shared.lock().unwrap();
        locked.job["payload"]["publicStatus"] =
            json!({"schemaVersion":"ai.public-status/v1","enabled":true});
        locked.job["leasedUntilEpochMs"] = json!(now_millis().saturating_sub(1));
    }
    assert!(accept_status(&path, &shared, "ready").is_err());
    {
        let mut locked = shared.lock().unwrap();
        locked.job["leasedUntilEpochMs"] = json!(now_millis() + 60_000);
        locked.recovery_session = Some("recovery".into());
    }
    assert!(accept_status(&path, &shared, "ready").is_err());
    {
        let mut locked = shared.lock().unwrap();
        locked.recovery_session = None;
        locked.job["status"] = json!("canceling");
    }
    assert!(accept_status(&path, &shared, "ready").is_err());
    assert!(snapshot(&shared).unwrap().public_status_latest.is_none());
}

#[test]
fn public_status_coalesces_latest_without_replacing_pending_identity() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("journal.json");
    let mut record = journal();
    record.job["payload"]["publicStatus"] =
        json!({"schemaVersion":"ai.public-status/v1","enabled":true});
    record.job["createdByNodeExecutionId"] = json!("33333333-3333-4333-8333-333333333333");
    record.public_status_last_sent_at_ms = now_millis();
    state::write_json(&path, &record).unwrap();
    let shared = Arc::new(Mutex::new(record));
    accept_status(&path, &shared, "old status").unwrap();
    accept_status(&path, &shared, "latest status").unwrap();
    assert!(promote_latest(&path, &shared).unwrap().is_none());
    {
        let mut locked = shared.lock().unwrap();
        locked.public_status_last_sent_at_ms = 0;
        persist(&path, &locked).unwrap();
    }
    let pending = promote_latest(&path, &shared).unwrap().unwrap();
    assert_eq!(pending["text"], "latest status");
    accept_status(&path, &shared, "newer status").unwrap();
    assert_eq!(promote_latest(&path, &shared).unwrap().unwrap(), pending);
    let restored: Journal = state::read_json(&path).unwrap();
    assert_eq!(restored.public_status_pending.unwrap(), pending);
    assert_eq!(
        restored.public_status_latest.unwrap()["text"],
        "newer status"
    );
}

#[tokio::test]
async fn first_artifact_rejection_is_not_reissued_and_process_result_survives() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let temp = tempfile::tempdir().unwrap();
    let daemon = daemon(
        &temp.path().join("state"),
        format!("http://{}", listener.local_addr().unwrap()),
    );
    let mut record = journal();
    record.phase = JournalPhase::Exited;
    record.job["kind"] = json!("shell.exec");
    let path = daemon
        .dir
        .join("jobs")
        .join(record.job["id"].as_str().unwrap())
        .join("journal.json");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let stdout = path.parent().unwrap().join("stdout");
    let stderr = path.parent().unwrap().join("stderr");
    std::fs::write(&stdout, []).unwrap();
    std::fs::write(&stderr, []).unwrap();
    record.result = Some(json!({
        "exitCode":0,"cancelled":false,"timedOut":false,
        "stdoutPath":stdout,"stderrPath":stderr,
    }));
    let original_result = record.result.clone();
    state::write_json(&path, &record).unwrap();
    let shared = Arc::new(Mutex::new(record));
    let server = tokio::spawn(async move {
        let (stream, transfer) = receive(&listener).await;
        assert_eq!(transfer["jobId"], "11111111-1111-4111-8111-111111111111");
        reply_error(stream, "ARTIFACT_TRANSFER_REJECTED").await;
        let (stream, terminal) = receive(&listener).await;
        assert_eq!(terminal["error"]["code"], "ARTIFACT_FINALIZATION_FAILED");
        assert!(terminal.get("result").is_none());
        reply(stream, json!({"job":{"status":"failed"}})).await;
        assert!(
            tokio::time::timeout(Duration::from_millis(150), listener.accept())
                .await
                .is_err()
        );
    });
    let first = initial_finalization(&daemon, &path, &shared)
        .await
        .unwrap_err();
    assert_eq!(first.to_string(), "ARTIFACT_TRANSFER_REJECTED");
    handle_finalization_error(
        &daemon,
        &path,
        &shared,
        DeliveryDiagnosticCategory::ArtifactFinalization,
        first,
    )
    .await
    .unwrap();
    deliver(daemon, &path, shared).await.unwrap();
    server.await.unwrap();
    let persisted: Journal = state::read_json(&path).unwrap();
    assert_eq!(persisted.phase, JournalPhase::Acknowledged);
    assert_eq!(persisted.result, original_result);
    assert_eq!(
        persisted.first_failure_diagnostic.unwrap().code,
        "ARTIFACT_TRANSFER_REJECTED"
    );
    assert!(persisted.delivery_diagnostic.is_none());
    assert!(stdout.exists() && stderr.exists());
}

#[tokio::test]
async fn expired_local_lease_waits_for_new_session_then_reclaims_terminal_only() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let temp = tempfile::tempdir().unwrap();
    let daemon = daemon(
        &temp.path().join("state"),
        format!("http://{}", listener.local_addr().unwrap()),
    );
    let mut record = journal();
    record.phase = JournalPhase::TerminalPending;
    record.job["leasedUntilEpochMs"] = json!(1);
    record.error = Some(json!({"code":"EXECUTION_INDETERMINATE","indeterminate":true}));
    let path = daemon
        .dir
        .join("jobs")
        .join(record.job["id"].as_str().unwrap())
        .join("journal.json");
    state::write_json(&path, &record).unwrap();
    let shared = Arc::new(Mutex::new(record));
    let error = deliver(daemon.clone(), &path, shared.clone())
        .await
        .unwrap_err();
    assert_eq!(error.to_string(), "RUNNER_JOB_RECOVERY_SESSION_REQUIRED");
    assert!(
        tokio::time::timeout(Duration::from_millis(100), listener.accept())
            .await
            .is_err()
    );
    let stalled: Journal = state::read_json(&path).unwrap();
    assert_eq!(stalled.phase, JournalPhase::TerminalPending);
    assert_eq!(
        stalled.error.as_ref().unwrap()["code"],
        "EXECUTION_INDETERMINATE"
    );
    {
        let mut current = shared.lock().unwrap();
        current.recovery_session = Some("new-session".into());
        persist(&path, &current).unwrap();
    }
    let server = tokio::spawn(async move {
        let (stream, headers, reclaim) = receive_with_headers(&listener).await;
        assert_eq!(reclaim["sessionId"], "new-session");
        assert_eq!(reclaim["expectedLeaseVersion"], 7);
        assert_eq!(reclaim["terminalSubmission"], true);
        assert_eq!(reclaim["idempotencyKey"], "original-job-key");
        assert!(
            headers
                .lines()
                .any(|line| { line.eq_ignore_ascii_case("idempotency-key: original-job-key") })
        );
        let mut renewed = journal().job;
        renewed["leaseVersion"] = json!(8);
        reply(stream, json!({"job":renewed})).await;
        let (stream, terminal) = receive(&listener).await;
        assert_eq!(terminal["sessionId"], "new-session");
        assert_eq!(terminal["leaseVersion"], 8);
        assert_eq!(terminal["error"]["code"], "EXECUTION_INDETERMINATE");
        assert_eq!(terminal["idempotencyKey"], "persistent-terminal-key");
        reply(stream, json!({"job":{"status":"failed"}})).await;
    });
    deliver(daemon, &path, shared).await.unwrap();
    server.await.unwrap();
    let recovered: Journal = state::read_json(&path).unwrap();
    assert_eq!(recovered.phase, JournalPhase::Acknowledged);
    assert_eq!(recovered.terminal_key, "persistent-terminal-key");
}

#[tokio::test]
async fn keyless_older_job_reclaims_without_borrowing_the_terminal_key() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let temp = tempfile::tempdir().unwrap();
    let daemon = daemon(
        &temp.path().join("state"),
        format!("http://{}", listener.local_addr().unwrap()),
    );
    let mut record = journal();
    record.job.as_object_mut().unwrap().remove("idempotencyKey");
    record.phase = JournalPhase::TerminalPending;
    record.recovery_session = Some("new-session".into());
    let path = daemon
        .dir
        .join("jobs")
        .join(record.job["id"].as_str().unwrap())
        .join("journal.json");
    state::write_json(&path, &record).unwrap();
    let shared = Arc::new(Mutex::new(record));
    let server = tokio::spawn(async move {
        let (stream, headers, reclaim) = receive_with_headers(&listener).await;
        assert_eq!(reclaim["idempotencyKey"], "");
        assert!(
            !headers
                .lines()
                .any(|line| line.to_ascii_lowercase().starts_with("idempotency-key:"))
        );
        let mut renewed = journal().job;
        renewed["leaseVersion"] = json!(8);
        renewed["idempotencyKey"] = Value::Null;
        reply(stream, json!({"job":renewed})).await;
    });
    reclaim_terminal(&daemon, &path, &shared).await.unwrap();
    server.await.unwrap();
    let recovered: Journal = state::read_json(&path).unwrap();
    assert_eq!(recovered.job["leaseVersion"], 8);
    assert_eq!(recovered.terminal_key, "persistent-terminal-key");
}

#[tokio::test]
async fn blocked_terminal_delivery_records_only_typed_safe_diagnostic() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("journal.json");
    let mut record = journal();
    record.phase = JournalPhase::TerminalPending;
    record.result = Some(json!({"secret":"private terminal result"}));
    let shared = Arc::new(Mutex::new(record));
    let daemon = daemon(temp.path(), "http://127.0.0.1:9".into());
    let error = crate::api::ApiError {
        code: "AUTH_EXPIRED".into(),
        retryable: false,
        status: None,
        data: Some(json!({"private":"never copy me"})),
        correlation_id: Some("11111111-1111-4111-8111-111111111111".into()),
    };
    let failed = retry_delivery(
        &daemon,
        &path,
        &shared,
        DeliveryDiagnosticCategory::TerminalSubmission,
        error.into(),
    )
    .await;
    assert_eq!(failed.err().unwrap().to_string(), "AUTH_EXPIRED");
    let persisted: Journal = state::read_json(&path).unwrap();
    assert_eq!(persisted.phase, JournalPhase::DeliveryBlocked);
    assert_eq!(
        persisted.result,
        Some(json!({"secret":"private terminal result"}))
    );
    let diagnostic = persisted.delivery_diagnostic.unwrap();
    assert_eq!(
        diagnostic.schema_version,
        "loomex.runner.delivery-diagnostic/v1"
    );
    assert_eq!(
        diagnostic.category,
        DeliveryDiagnosticCategory::TerminalSubmission
    );
    assert_eq!(diagnostic.code, "AUTH_EXPIRED");
    assert_eq!(
        diagnostic.correlation_id.as_deref(),
        Some("11111111-1111-4111-8111-111111111111")
    );
    assert!(diagnostic.observed_at_epoch_ms > 0);
    let wire = serde_json::to_string(&diagnostic).unwrap();
    assert!(!wire.contains("private") && !wire.contains("secret"));
}

#[test]
fn diagnostic_rejects_arbitrary_error_text_and_correlation() {
    let error = crate::api::ApiError {
        code: "secret path /tmp/input".into(),
        retryable: false,
        status: None,
        data: Some(json!({"private":"provider output"})),
        correlation_id: Some("private-correlation".into()),
    };
    let diagnostic = delivery_diagnostic(DeliveryDiagnosticCategory::LeaseReclaim, &error.into());
    assert_eq!(diagnostic.code, "DELIVERY_FAILED");
    assert!(diagnostic.correlation_id.is_none());
    assert!(
        !serde_json::to_string(&diagnostic)
            .unwrap()
            .contains("private")
    );
}
#[tokio::test]
async fn blocked_terminal_journal_is_not_replayed_on_session_recovery() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let temp = tempfile::tempdir().unwrap();
    let daemon = daemon(
        &temp.path().join("state"),
        format!("http://{}", listener.local_addr().unwrap()),
    );
    let mut record = journal();
    record.phase = JournalPhase::DeliveryBlocked;
    record.result = Some(json!({"terminal":"retained"}));
    record.delivery_diagnostic = Some(delivery_diagnostic(
        DeliveryDiagnosticCategory::TerminalSubmission,
        &anyhow::anyhow!("AUTH_EXPIRED"),
    ));
    let path = daemon
        .dir
        .join("jobs")
        .join(record.job["id"].as_str().unwrap())
        .join("journal.json");
    state::write_json(&path, &record).unwrap();
    let before: Value = state::read_json(&path).unwrap();
    recover(daemon, "org", "new-session").await.unwrap();
    let after: Value = state::read_json(&path).unwrap();
    assert_eq!(after, before);
    assert_eq!(
        listener.into_std().unwrap().accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}
#[tokio::test]
async fn concurrent_output_senders_serialize_offsets() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let t = tempfile::tempdir().unwrap();
    let d = daemon(
        &t.path().join("state"),
        format!("http://{}", listener.local_addr().unwrap()),
    );
    let j = Arc::new(Mutex::new(journal()));
    let path = d
        .dir
        .join("jobs")
        .join(journal().job["id"].as_str().unwrap())
        .join("journal.json");
    state::write_json(&path, &snapshot(&j).unwrap()).unwrap();
    let stdout = path.parent().unwrap().join("stdout");
    std::fs::write(&stdout, vec![b'a'; 32768]).unwrap();
    let d1 = d.clone();
    let j1 = j.clone();
    let p1 = path.clone();
    let first = tokio::spawn(async move { stream_events(&d1, &p1, &j1).await.unwrap() });
    let (stream, body) = receive(&listener).await;
    assert_eq!(body["events"][0]["payload"]["offset"], 0);
    let d2 = d.clone();
    let j2 = j.clone();
    let p2 = path.clone();
    let second = tokio::spawn(async move { stream_events(&d2, &p2, &j2).await.unwrap() });
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(30), listener.accept())
            .await
            .is_err()
    );
    std::fs::write(&stdout, vec![b'a'; 65536]).unwrap();
    reply(stream, json!({})).await;
    let (stream, body) = receive(&listener).await;
    assert_eq!(body["events"][0]["payload"]["offset"], 32768);
    assert_eq!(body["events"][0]["payload"]["chunkId"], "stdout:32768");
    reply(stream, json!({})).await;
    assert!(first.await.unwrap() && second.await.unwrap());
    assert_eq!(snapshot(&j).unwrap().stdout_offset, 65536);
    assert!(!stream_events(&d, &path, &j).await.unwrap());
}
#[tokio::test]
async fn lost_output_response_retries_exact_durable_chunk_when_spool_grows() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let t = tempfile::tempdir().unwrap();
    let d = daemon(
        &t.path().join("state"),
        format!("http://{}", listener.local_addr().unwrap()),
    );
    let j = Arc::new(Mutex::new(journal()));
    let path = d
        .dir
        .join("jobs")
        .join(journal().job["id"].as_str().unwrap())
        .join("journal.json");
    state::write_json(&path, &snapshot(&j).unwrap()).unwrap();
    let stdout = path.parent().unwrap().join("stdout");
    std::fs::write(&stdout, b"first chunk").unwrap();
    let d1 = d.clone();
    let j1 = j.clone();
    let p1 = path.clone();
    let first = tokio::spawn(async move { stream_events(&d1, &p1, &j1).await });
    let (stream, original) = receive(&listener).await;
    drop(stream);
    assert!(first.await.unwrap().is_err());
    std::fs::write(&stdout, b"first chunk plus later output").unwrap();
    // Simulate restart: pending length must be in the durable journal.
    let recovered = Arc::new(Mutex::new(state::read_json::<Journal>(&path).unwrap()));
    let d2 = d.clone();
    let p2 = path.clone();
    let j2 = recovered.clone();
    let retry = tokio::spawn(async move { stream_events(&d2, &p2, &j2).await.unwrap() });
    let (stream, retried) = receive(&listener).await;
    assert_eq!(original, retried);
    reply(stream, json!({})).await;
    assert!(retry.await.unwrap());
    assert_eq!(snapshot(&recovered).unwrap().stdout_offset, 11);
}
#[tokio::test]
async fn provider_progress_retries_with_its_durable_output_chunk() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let t = tempfile::tempdir().unwrap();
    let d = daemon(
        &t.path().join("state"),
        format!("http://{}", listener.local_addr().unwrap()),
    );
    let mut record = journal();
    record.job["payload"]["provider"] = json!("codex");
    record.job["createdByNodeExecutionId"] = json!("33333333-3333-4333-8333-333333333333");
    let j = Arc::new(Mutex::new(record));
    let path = d
        .dir
        .join("jobs")
        .join(journal().job["id"].as_str().unwrap())
        .join("journal.json");
    state::write_json(&path, &snapshot(&j).unwrap()).unwrap();
    let stdout = path.parent().unwrap().join("stdout");
    std::fs::write(
        &stdout,
        br#"{"type":"item.started","item":{"type":"command_execution","command":"private command"}}
"#,
    )
    .unwrap();
    let first_daemon = d.clone();
    let first_path = path.clone();
    let first_journal = j.clone();
    let first =
        tokio::spawn(
            async move { stream_events(&first_daemon, &first_path, &first_journal).await },
        );
    let (stream, original) = receive(&listener).await;
    assert_eq!(original["events"].as_array().unwrap().len(), 2);
    assert_eq!(original["events"][1]["eventType"], "ai.progress.v1");
    assert_eq!(original["events"][1]["payload"]["kind"], "tool.started");
    assert!(
        !original["events"][1]
            .to_string()
            .contains("private command")
    );
    drop(stream);
    assert!(first.await.unwrap().is_err());

    let recovered = Arc::new(Mutex::new(state::read_json::<Journal>(&path).unwrap()));
    let retry_daemon = d.clone();
    let retry_path = path.clone();
    let retry_journal = recovered.clone();
    let retry = tokio::spawn(async move {
        stream_events(&retry_daemon, &retry_path, &retry_journal)
            .await
            .unwrap()
    });
    let (stream, replay) = receive(&listener).await;
    assert_eq!(original, replay);
    reply(stream, json!({})).await;
    assert!(retry.await.unwrap());
    assert!(snapshot(&recovered).unwrap().progress_pending.is_none());
}

#[tokio::test]
async fn canonical_provider_completion_progress_is_delivered_from_fixture_output() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let temp = tempfile::tempdir().unwrap();
    let daemon = daemon(
        &temp.path().join("state"),
        format!("http://{}", listener.local_addr().unwrap()),
    );
    let fixtures = [
        (
            "codex",
            r#"{"type":"turn.completed"}"#,
            "activity.completed",
        ),
        (
            "claude",
            r#"{"type":"result","is_error":false}"#,
            "activity.completed",
        ),
        (
            "gemini",
            r#"{"type":"result","status":"success"}"#,
            "activity.completed",
        ),
        (
            "antigravity",
            r#"{"conversation_id":"fixture","structured_output":{}}"#,
            "activity.completed",
        ),
    ];
    for (provider, output, expected_kind) in fixtures {
        let mut record = journal();
        record.job["payload"]["provider"] = json!(provider);
        record.job["createdByNodeExecutionId"] = json!("33333333-3333-4333-8333-333333333333");
        let shared = Arc::new(Mutex::new(record));
        let path = daemon
            .dir
            .join("jobs")
            .join(format!("provider-{provider}"))
            .join("journal.json");
        state::write_json(&path, &snapshot(&shared).unwrap()).unwrap();
        std::fs::write(path.parent().unwrap().join("stdout"), format!("{output}\n")).unwrap();
        let task_daemon = daemon.clone();
        let task_path = path.clone();
        let task_journal = shared.clone();
        let task = tokio::spawn(async move {
            stream_events(&task_daemon, &task_path, &task_journal)
                .await
                .unwrap()
        });
        let (stream, body) = receive(&listener).await;
        assert_eq!(body["events"].as_array().unwrap().len(), 2, "{provider}");
        assert_eq!(
            body["events"][1]["eventType"], "ai.progress.v1",
            "{provider}"
        );
        assert_eq!(
            body["events"][1]["payload"]["kind"], expected_kind,
            "{provider}"
        );
        assert_eq!(
            body["events"][1]["payload"]["provenance"], "provider_reported",
            "{provider}"
        );
        reply(stream, json!({})).await;
        assert!(task.await.unwrap(), "{provider}");
    }
}
#[tokio::test]
async fn helper_scope_joins_writers_before_panic_terminal_is_recorded() {
    let t = tempfile::tempdir().unwrap();
    let path = t.path().join("journal.json");
    let scope = Arc::new(ExecutionScope::default());
    let helper_path = path.clone();
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    scope.register(tokio::spawn(async move {
        let _ = ready_tx.send(());
        tokio::time::sleep(std::time::Duration::from_millis(40)).await;
        state::write_json(&helper_path, &json!({"phase":"started"})).unwrap();
    }));
    ready_rx.await.unwrap();
    let worker = tokio::spawn(async { panic!("injected execution task panic") });
    assert!(worker.await.is_err());
    scope.stop().await;
    state::write_json(
        &path,
        &json!({"phase":"acknowledged","error":"JOB_TASK_PANICKED"}),
    )
    .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(60)).await;
    assert_eq!(
        state::read_json::<Value>(&path).unwrap()["phase"],
        "acknowledged"
    );
    assert!(scope.tasks.lock().unwrap().is_empty());
}
#[tokio::test]
async fn drain_counts_held_startup_and_lease_until_session_writers_finish() {
    for hold_startup in [true, false] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let t = tempfile::tempdir().unwrap();
        let d = daemon(
            &t.path().join("state"),
            format!("http://{}", listener.local_addr().unwrap()),
        );
        let worker_daemon = d.clone();
        let task = tokio::spawn(async move { session(worker_daemon, "org".into()).await.unwrap() });
        let (stream, _) = receive(&listener).await;
        let held = if hold_startup {
            stream
        } else {
            reply(stream, json!({"session":{"id":"session"}})).await;
            receive(&listener).await.0
        };
        let status = d.dispatch("status.get", json!({})).await.unwrap();
        assert_eq!(status["activeJobs"], 0);
        let drain = d
            .dispatch("daemon.drain", json!({"idempotencyKey":Uuid::new_v4()}))
            .await
            .unwrap();
        assert!(drain["activeJobs"].as_u64().unwrap() > 0);
        assert_eq!(drain["updateDeferred"], true);
        assert!(admit(&d).unwrap().is_none());
        reply(
            held,
            if hold_startup {
                json!({"session":{"id":"session"}})
            } else {
                json!({"job":null})
            },
        )
        .await;
        let (stream, body) = receive(&listener).await;
        assert_eq!(body["reason"], "daemon drained");
        reply(stream, json!({})).await;
        task.await.unwrap();
        tokio::task::yield_now().await;
        assert_eq!(d.managed_work(), 0);
    }
}
#[tokio::test]
async fn artifact_upload_resumes_and_preserves_more_than_one_transport_frame() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let t = tempfile::tempdir().unwrap();
    let d = daemon(
        &t.path().join("state"),
        format!("http://{}", listener.local_addr().unwrap()),
    );
    let data: Vec<u8> = (0..1_200_017).map(|i| (i % 251) as u8).collect();
    let expected = data.clone();
    let path = t.path().join("large-output");
    std::fs::write(&path, &data).unwrap();
    let server = tokio::spawn(async move {
        let (stream, start) = receive(&listener).await;
        assert_eq!(start["checksumSha256"], state::digest(&expected));
        assert_eq!(start["jobId"], "11111111-1111-4111-8111-111111111111");
        let mut offset = 262144usize;
        reply(stream, json!({"transferId":"transfer","offset":offset})).await;
        while offset < expected.len() {
            let (stream, chunk) = receive(&listener).await;
            assert_eq!(chunk["offset"].as_u64(), Some(offset as u64));
            let raw = STANDARD
                .decode(chunk["dataBase64"].as_str().unwrap())
                .unwrap();
            assert!(raw.len() <= 262144);
            assert_eq!(raw, expected[offset..offset + raw.len()]);
            offset += raw.len();
            reply(stream, json!({"offset":offset})).await;
        }
        let (stream, body) = receive(&listener).await;
        assert_eq!(body, json!({}));
        reply(
            stream,
            json!({"artifactId":"33333333-3333-4333-8333-333333333333"}),
        )
        .await;
    });
    let record = journal();
    let shared = Arc::new(Mutex::new(record.clone()));
    let result = upload(
        &d,
        &shared,
        &record,
        &path,
        "output.bin",
        "application/octet-stream",
        "stdout",
    )
    .await
    .unwrap();
    server.await.unwrap();
    assert_eq!(result["sizeBytes"], data.len());
    assert_eq!(result["checksumSha256"], state::digest(&data));
}

#[tokio::test]
async fn large_binary_http_response_is_finalized_as_a_versioned_artifact_reference() {
    let artifact_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let response_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let response_address = response_listener.local_addr().unwrap();
    let temp = tempfile::tempdir().unwrap();
    let daemon = daemon(
        &temp.path().join("state"),
        format!("http://{}", artifact_listener.local_addr().unwrap()),
    );
    let response_body = vec![0xff; MAX_INLINE_HTTP_RESULT_BYTES + 1];
    let expected_upload = response_body.clone();
    let expected_checksum = state::digest(&expected_upload);
    let response_server = tokio::spawn(async move {
        let (mut stream, _) = response_listener.accept().await.unwrap();
        let mut request = [0u8; 4096];
        assert!(stream.read(&mut request).await.unwrap() > 0);
        stream
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        response_body.len()
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
        stream.write_all(&response_body).await.unwrap();
    });
    let artifact_server = tokio::spawn(async move {
        let (stream, start) = receive(&artifact_listener).await;
        assert_eq!(start["sizeBytes"], expected_upload.len());
        assert_eq!(start["checksumSha256"], state::digest(&expected_upload));
        reply(stream, json!({"transferId":"http-body","offset":0})).await;
        let mut offset = 0usize;
        while offset < expected_upload.len() {
            let (stream, chunk) = receive(&artifact_listener).await;
            assert_eq!(chunk["offset"], offset);
            let bytes = STANDARD
                .decode(chunk["dataBase64"].as_str().unwrap())
                .unwrap();
            assert_eq!(bytes, expected_upload[offset..offset + bytes.len()]);
            offset += bytes.len();
            reply(stream, json!({"offset":offset})).await;
        }
        let (stream, complete) = receive(&artifact_listener).await;
        assert_eq!(complete, json!({}));
        reply(
            stream,
            json!({"artifactId":"44444444-4444-4444-8444-444444444444"}),
        )
        .await;
    });
    let payload = json!({
        "schemaVersion": HTTP_REQUEST_SCHEMA,
        "resultContract": {"schemaVersion":HTTP_RESULT_SCHEMA,"artifactRefSchemaVersion":HTTP_BODY_REF_SCHEMA},
        "method": "GET",
        "url": format!("http://{response_address}/"),
        "headers": {},
        "timeoutSeconds": 10,
    });
    let journal_path = daemon.dir.join("jobs/http-response/journal.json");
    let body_path = journal_path.parent().unwrap().join("http-response-body");
    state::private_dir(journal_path.parent().unwrap()).unwrap();
    let result = execute_test_http(&payload, Arc::new(AtomicBool::new(false)), &body_path)
        .await
        .unwrap();
    response_server.await.unwrap();
    assert!(result.get("body").is_none());
    assert_eq!(result["bodyPath"], body_path.to_string_lossy().as_ref());
    assert!(body_path.exists());

    let mut record = journal();
    record.job["kind"] = json!("http.request");
    record.transition(JournalPhase::Exited).unwrap();
    record.result = Some(result);
    state::write_json(&journal_path, &record).unwrap();
    let journal = Arc::new(Mutex::new(record));
    materialize_terminal(&daemon, &journal_path, &journal)
        .await
        .unwrap();
    artifact_server.await.unwrap();
    let finalized = snapshot(&journal).unwrap();
    let result = finalized.result.unwrap();
    assert_eq!(finalized.phase, "terminal_pending");
    assert_eq!(result["bodyStorage"], "artifact");
    assert!(result.get("bodyPath").is_none());
    assert_eq!(
        result["bodyRef"],
        json!({
            "schemaVersion": HTTP_BODY_REF_SCHEMA,
            "artifactId":"44444444-4444-4444-8444-444444444444",
            "name":"11111111-1111-4111-8111-111111111111-http-response.bin",
            "sizeBytes":MAX_INLINE_HTTP_RESULT_BYTES + 1,
            "checksumSha256":expected_checksum,
            "contentType":"application/octet-stream",
        })
    );
}
#[tokio::test]
async fn restart_reclaims_terminal_authority_before_delivery() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let t = tempfile::tempdir().unwrap();
    let d = daemon(
        &t.path().join("state"),
        format!("http://{}", listener.local_addr().unwrap()),
    );
    let j = journal();
    let path = d
        .dir
        .join("jobs")
        .join(j.job["id"].as_str().unwrap())
        .join("journal.json");
    state::write_json(&path, &j).unwrap();
    let server = tokio::spawn(async move {
        let (stream, body) = receive(&listener).await;
        assert_eq!(body["sessionId"], "new-session");
        assert_eq!(body["terminalSubmission"], true);
        assert_eq!(body["expectedLeaseVersion"], 7);
        let mut renewed = journal().job;
        renewed["leaseVersion"] = json!(8);
        reply(stream, json!({"job":renewed})).await;
        let (stream, body) = receive(&listener).await;
        assert_eq!(body["sessionId"], "new-session");
        assert_eq!(body["leaseVersion"], 8);
        assert_eq!(body["error"]["code"], "EXECUTION_INDETERMINATE");
        reply(stream, json!({"job":{"status":"failed"}})).await;
    });
    recover(d.clone(), "org", "new-session").await.unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(8), async {
        server.await.unwrap();
        d.execution.join_recovery().await;
    })
    .await
    .unwrap();
    assert_eq!(d.execution.active_work(), 0);
    let record: Journal = state::read_json(&path).unwrap();
    assert_eq!(record.phase, "acknowledged");
    assert_eq!(record.session, "new-session");
    assert!(record.identity.is_none());
}
#[tokio::test]
async fn definitive_reclaim_proof_rejection_blocks_without_replay() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let temp = tempfile::tempdir().unwrap();
    let daemon = daemon(
        &temp.path().join("state"),
        format!("http://{}", listener.local_addr().unwrap()),
    );
    let mut record = journal();
    record.phase = JournalPhase::TerminalPending;
    record.recovery_session = Some("new-session".into());
    record.error = Some(json!({"code":"EXECUTION_INDETERMINATE"}));
    let path = daemon
        .dir
        .join("jobs")
        .join(record.job["id"].as_str().unwrap())
        .join("journal.json");
    persist(&path, &record).unwrap();
    let shared = Arc::new(Mutex::new(record));
    let server = tokio::spawn(async move {
        let (stream, reclaim) = receive(&listener).await;
        assert_eq!(reclaim["terminalSubmission"], true);
        assert_eq!(reclaim["sessionId"], "new-session");
        reply_error(stream, "RUNNER_PROOF_INVALID").await;
        assert!(
            tokio::time::timeout(Duration::from_millis(150), listener.accept())
                .await
                .is_err()
        );
    });
    let error = retry_delivery(
        &daemon,
        &path,
        &shared,
        DeliveryDiagnosticCategory::TerminalSubmission,
        anyhow::anyhow!("RUNNER_JOB_LEASE_EXPIRED"),
    )
    .await
    .unwrap_err();
    assert_eq!(error.to_string(), "RUNNER_PROOF_INVALID");
    server.await.unwrap();
    let saved: Journal = state::read_json(&path).unwrap();
    assert_eq!(saved.phase, JournalPhase::DeliveryBlocked);
    assert_eq!(saved.recovery_session.as_deref(), Some("new-session"));
    let diagnostic = saved.delivery_diagnostic.unwrap();
    assert_eq!(
        diagnostic.category,
        DeliveryDiagnosticCategory::LeaseReclaim
    );
    assert_eq!(diagnostic.code, "RUNNER_PROOF_INVALID");
    assert_eq!(saved.error.unwrap()["code"], "EXECUTION_INDETERMINATE");
}
#[tokio::test]
async fn definitive_reclaim_fence_rejection_does_not_start_second_reclaim() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let temp = tempfile::tempdir().unwrap();
    let daemon = daemon(
        &temp.path().join("state"),
        format!("http://{}", listener.local_addr().unwrap()),
    );
    let mut record = journal();
    record.phase = JournalPhase::TerminalPending;
    record.recovery_session = Some("new-session".into());
    record.error = Some(json!({"code":"EXECUTION_INDETERMINATE"}));
    let path = daemon
        .dir
        .join("jobs")
        .join(record.job["id"].as_str().unwrap())
        .join("journal.json");
    persist(&path, &record).unwrap();
    let server = tokio::spawn(async move {
        let (stream, reclaim) = receive(&listener).await;
        assert_eq!(reclaim["terminalSubmission"], true);
        assert_eq!(reclaim["sessionId"], "new-session");
        reply_error(stream, "RUNNER_JOB_LEASE_CONFLICT").await;
        assert!(
            tokio::time::timeout(Duration::from_millis(150), listener.accept())
                .await
                .is_err()
        );
    });
    let error = deliver(daemon, &path, Arc::new(Mutex::new(record)))
        .await
        .unwrap_err();
    assert_eq!(error.to_string(), "RUNNER_JOB_LEASE_CONFLICT");
    server.await.unwrap();
    let saved: Journal = state::read_json(&path).unwrap();
    assert_eq!(saved.phase, JournalPhase::DeliveryBlocked);
    assert_eq!(saved.recovery_session.as_deref(), Some("new-session"));
    let diagnostic = saved.delivery_diagnostic.unwrap();
    assert_eq!(
        diagnostic.category,
        DeliveryDiagnosticCategory::LeaseReclaim
    );
    assert_eq!(diagnostic.code, "RUNNER_JOB_LEASE_CONFLICT");
    assert_eq!(saved.error.unwrap()["code"], "EXECUTION_INDETERMINATE");
}
#[tokio::test]
async fn restart_redelivers_indeterminate_terminal_without_replaying_command() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let t = tempfile::tempdir().unwrap();
    let d = daemon(
        &t.path().join("state"),
        format!("http://{}", listener.local_addr().unwrap()),
    );
    let j = journal();
    let path = d
        .dir
        .join("jobs")
        .join(j.job["id"].as_str().unwrap())
        .join("journal.json");
    state::write_json(&path, &j).unwrap();
    let server = tokio::spawn(async move {
        let (stream, reclaim) = receive(&listener).await;
        assert_eq!(reclaim["sessionId"], "new-session");
        assert_eq!(reclaim["expectedLeaseVersion"], 7);
        assert_eq!(reclaim["terminalSubmission"], true);
        assert_eq!(reclaim["idempotencyKey"], "original-job-key");
        let mut renewed = journal().job;
        renewed["leaseVersion"] = json!(8);
        reply(stream, json!({"job":renewed})).await;
        let (stream, body) = receive(&listener).await;
        assert_eq!(body["sessionId"], "new-session");
        assert_eq!(body["leaseVersion"], 8);
        assert_eq!(body["idempotencyKey"], "persistent-terminal-key");
        assert_eq!(body["error"]["code"], "EXECUTION_INDETERMINATE");
        assert!(body.get("result").is_none());
        reply(stream, json!({"job":{"status":"failed"}})).await;
    });
    recover(d.clone(), "org", "new-session").await.unwrap();
    server.await.unwrap();
    for _ in 0..100 {
        if d.execution.active_work() == 0 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    let recovered: Journal = state::read_json(&path).unwrap();
    assert_eq!(recovered.phase, "acknowledged");
    assert!(recovered.identity.is_none());
    assert!(recovered.error.is_some());
    assert!(!path.parent().unwrap().join("stdout").exists());
}

#[test]
fn transition_rejects_reexecution_and_preserves_terminal_key() {
    let mut record = journal();
    assert!(record.transition(JournalPhase::StartPending).is_err());
    record.transition(JournalPhase::Exited).unwrap();
    record.transition(JournalPhase::TerminalPending).unwrap();
    record.transition(JournalPhase::Acknowledged).unwrap();
    assert!(record.transition(JournalPhase::Running).is_err());
    assert_eq!(record.terminal_key, "persistent-terminal-key");
}

#[test]
fn failed_journal_replacement_keeps_previous_terminal_evidence() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("journal.json");
    let record = journal();
    persist(&path, &record).unwrap();
    // A file in place of a directory deterministically fails before replacement.
    assert!(persist(&path.join("journal.json"), &record).is_err());
    let recovered: Journal = state::read_json(&path).unwrap();
    assert_eq!(recovered.terminal_key, record.terminal_key);
    assert_eq!(recovered.phase, record.phase);
}

#[tokio::test]
async fn unreadable_journal_does_not_block_valid_recovery_or_get_deleted() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let temp = tempfile::tempdir().unwrap();
    let d = daemon(
        &temp.path().join("state"),
        format!("http://{}", listener.local_addr().unwrap()),
    );
    let bad = d.dir.join("jobs/broken/journal.json");
    state::private_dir(bad.parent().unwrap()).unwrap();
    std::fs::write(&bad, b"broken").unwrap();
    let record = journal();
    let path = d
        .dir
        .join("jobs")
        .join(record.job["id"].as_str().unwrap())
        .join("journal.json");
    persist(&path, &record).unwrap();
    let server = tokio::spawn(async move {
        let (stream, reclaim) = receive(&listener).await;
        assert_eq!(reclaim["terminalSubmission"], true);
        assert_eq!(reclaim["idempotencyKey"], "original-job-key");
        let mut renewed = journal().job;
        renewed["leaseVersion"] = json!(8);
        reply(stream, json!({"job":renewed})).await;
        let (stream, body) = receive(&listener).await;
        assert_eq!(body["idempotencyKey"], "persistent-terminal-key");
        reply(stream, json!({"job":{"status":"failed"}})).await;
    });
    recover(d.clone(), "org", "new-session").await.unwrap();
    d.execution.join_recovery().await;
    server.await.unwrap();
    assert_eq!(std::fs::read(&bad).unwrap(), b"broken");
    assert_eq!(
        state::read_json::<Journal>(&path).unwrap().phase,
        JournalPhase::Acknowledged
    );
}

#[tokio::test]
async fn lease_renewal_during_output_drain_reuses_event_identity_with_fresh_fence() {
    let shared = Arc::new(Mutex::new(journal()));
    let original = snapshot(&shared).unwrap();
    let event = json!({"eventType":"output","payload":{"chunkId":"stdout:0","offset":0}});
    let mut attempts = Vec::new();
    let mut count = 0;
    let result = transfer_request_with(
        &shared,
        &original,
        |lease| {
            let mut body = fence(lease);
            body["events"] = json!([event]);
            Some(body)
        },
        |lease, body| {
            count += 1;
            let attempt = count;
            let body = body.unwrap();
            attempts.push((lease.job["leaseVersion"].clone(), body.clone()));
            let shared = shared.clone();
            async move {
                if attempt == 1 {
                    // The renewal lands after output is durably selected, but
                    // before the request reaches the backend pre-send check.
                    let mut record = shared.lock().unwrap();
                    record.job["leaseVersion"] = json!(8);
                    record.job["leasedUntilEpochMs"] = json!(now_millis() + 60_000);
                    return Err(anyhow::Error::new(crate::api::ApiError {
                        code: "RUNNER_JOB_LEASE_CONFLICT".into(),
                        retryable: false,
                        status: None,
                        data: None,
                        correlation_id: None,
                    }));
                }
                Ok(body)
            }
        },
    )
    .await
    .unwrap();
    assert_eq!(attempts.len(), 2);
    assert_eq!(attempts[0].0, 7);
    assert_eq!(attempts[1].0, 8);
    assert_eq!(attempts[0].1["events"], attempts[1].1["events"]);
    assert_eq!(result["leaseVersion"], 8);
    assert_eq!(result["events"][0]["payload"]["chunkId"], "stdout:0");
}

#[tokio::test]
async fn backend_lease_rejection_is_not_replayed_with_another_fence() {
    let shared = Arc::new(Mutex::new(journal()));
    let original = snapshot(&shared).unwrap();
    let mut attempts = 0;
    let error = transfer_request_with(
        &shared,
        &original,
        |lease| Some(fence(lease)),
        |_, _| {
            attempts += 1;
            async {
                Err(anyhow::Error::new(crate::api::ApiError {
                    code: "RUNNER_JOB_LEASE_CONFLICT".into(),
                    retryable: false,
                    status: Some(409),
                    data: None,
                    correlation_id: None,
                }))
            }
        },
    )
    .await
    .unwrap_err();
    assert_eq!(attempts, 1);
    assert_eq!(error.to_string(), "RUNNER_JOB_LEASE_CONFLICT");
    assert!(!local_pre_send_lease_change(&error));
    assert_eq!(
        delivery_diagnostic(DeliveryDiagnosticCategory::OutputDelivery, &error).code,
        "RUNNER_JOB_LEASE_CONFLICT"
    );
}

#[tokio::test]
async fn local_authority_replacement_is_distinct_from_lease_renewal() {
    let shared = Arc::new(Mutex::new(journal()));
    let original = snapshot(&shared).unwrap();
    shared.lock().unwrap().job["connectionGeneration"] = json!(99);
    let mut attempts = 0;
    let error = transfer_request_with(
        &shared,
        &original,
        |lease| Some(fence(lease)),
        |_, _| {
            attempts += 1;
            async { Ok(json!({})) }
        },
    )
    .await
    .unwrap_err();
    assert_eq!(attempts, 0);
    assert_eq!(error.to_string(), "RUNNER_JOB_LOCAL_AUTHORITY_CHANGED");
    assert!(fence_error(&error.to_string()));
}

#[tokio::test]
async fn finalization_local_renewal_reuses_transfer_key_without_replaying_backend_rejection() {
    let shared = Arc::new(Mutex::new(journal()));
    let original = snapshot(&shared).unwrap();
    let transfer_key = "job-11111111-1111-4111-8111-111111111111-stream-stdout";
    let body = json!({"jobId":original.job["id"],"idempotencyKey":transfer_key});
    let mut attempts = Vec::new();
    let response = transfer_request_with(
        &shared,
        &original,
        |_| Some(body.clone()),
        |_, body| {
            let sent = body.unwrap();
            attempts.push(sent.clone());
            let attempt = attempts.len();
            let shared = shared.clone();
            async move {
                if attempt == 1 {
                    let mut record = shared.lock().unwrap();
                    record.job["leaseVersion"] = json!(8);
                    record.job["leasedUntilEpochMs"] = json!(now_millis() + 60_000);
                    return Err(anyhow::Error::new(crate::api::ApiError {
                        code: "RUNNER_JOB_LEASE_CONFLICT".into(),
                        retryable: false,
                        status: None,
                        data: None,
                        correlation_id: None,
                    }));
                }
                Ok(json!({"transferId":"retained-transfer"}))
            }
        },
    )
    .await
    .unwrap();
    assert_eq!(response["transferId"], "retained-transfer");
    assert_eq!(attempts, vec![body.clone(), body]);
    assert_eq!(attempts[0]["idempotencyKey"], transfer_key);
}

#[tokio::test]
async fn repeated_local_lease_changes_have_a_distinct_safe_diagnostic() {
    let shared = Arc::new(Mutex::new(journal()));
    let original = snapshot(&shared).unwrap();
    let mut attempts = 0;
    let error = transfer_request_with(
        &shared,
        &original,
        |lease| Some(fence(lease)),
        |_, _| {
            attempts += 1;
            let shared = shared.clone();
            async move {
                let mut record = shared.lock().unwrap();
                record.job["leaseVersion"] =
                    json!(record.job["leaseVersion"].as_u64().unwrap() + 1);
                record.job["leasedUntilEpochMs"] = json!(now_millis() + 60_000);
                Err(anyhow::Error::new(crate::api::ApiError {
                    code: "RUNNER_JOB_LEASE_CONFLICT".into(),
                    retryable: false,
                    status: None,
                    data: None,
                    correlation_id: None,
                }))
            }
        },
    )
    .await
    .unwrap_err();
    assert_eq!(attempts, 3);
    assert_eq!(error.to_string(), "RUNNER_JOB_LOCAL_LEASE_CHANGED");
    assert_eq!(
        delivery_diagnostic(DeliveryDiagnosticCategory::ArtifactFinalization, &error).code,
        "RUNNER_JOB_LOCAL_LEASE_CHANGED"
    );
    assert!(fence_error(&error.to_string()));
}

#[tokio::test]
async fn responsive_output_batch_drains_one_mib_with_fair_streams() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let temp = tempfile::tempdir().unwrap();
    let daemon = daemon(
        temp.path(),
        format!("http://{}", listener.local_addr().unwrap()),
    );
    let shared = Arc::new(Mutex::new(journal()));
    let path = temp.path().join("jobs/throughput/journal.json");
    state::write_json(&path, &snapshot(&shared).unwrap()).unwrap();
    for stream in ["stdout", "stderr"] {
        std::fs::write(path.parent().unwrap().join(stream), vec![b'x'; 1_048_576]).unwrap();
    }
    let server = tokio::spawn(async move {
        for index in 0..64 {
            let (stream, body) = receive(&listener).await;
            let expected_stream = if index % 2 == 0 { "stdout" } else { "stderr" };
            let event = &body["events"][0];
            assert_eq!(event["stream"], expected_stream);
            assert_eq!(event["payload"]["offset"], (index / 2) * 32768);
            assert_eq!(
                STANDARD
                    .decode(event["payload"]["data"].as_str().unwrap())
                    .unwrap()
                    .len(),
                32768
            );
            reply(stream, json!({})).await;
        }
    });
    let start = Instant::now();
    let mut wakes = 0;
    while snapshot(&shared).unwrap().stdout_offset < 1_048_576 {
        assert!(stream_event_batch(&daemon, &path, &shared).await.unwrap());
        wakes += 1;
    }
    server.await.unwrap();
    let elapsed = start.elapsed();
    assert!(
        elapsed < Duration::from_secs(10),
        "controlled output took {elapsed:?}"
    );
    let record = snapshot(&shared).unwrap();
    assert_eq!(record.stderr_offset, 1_048_576);
    assert!((8..=32).contains(&wakes));
    assert_eq!(record.durable_writer.commits.load(Ordering::SeqCst), 128);
    println!(
        "responsive output: bytes=2097152 events=64 durable_commits=128 wakes={wakes} elapsed_ms={}",
        elapsed.as_millis()
    );
}

// Each deliberate worker stall owns an isolated copy of the production 2/1
// admissions. Jobs within a fixture still contend for those exact shared slots.
fn fault_journal(record: Journal) -> Arc<Mutex<Journal>> {
    let shared = Arc::new(Mutex::new(record));
    *snapshot(&shared)
        .unwrap()
        .durable_writer
        .test_slots
        .lock()
        .unwrap() = Some(Arc::new(TestIoSlots::default()));
    shared
}

#[tokio::test]
async fn responsive_canceled_ack_waiter_retains_sender_and_durable_scope_ownership() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let temp = tempfile::tempdir().unwrap();
    let daemon = daemon(
        temp.path(),
        format!("http://{}", listener.local_addr().unwrap()),
    );
    let shared = fault_journal(journal());
    let path = temp.path().join("jobs/canceled-ack/journal.json");
    state::write_json(&path, &snapshot(&shared).unwrap()).unwrap();
    std::fs::write(path.parent().unwrap().join("stdout"), b"first").unwrap();
    let scope = Arc::new(ExecutionScope::default());
    let evidence = snapshot(&shared).unwrap().durable_writer;
    *scope.evidence.lock().unwrap() = Some(evidence.clone());
    let d = daemon.clone();
    let j = shared.clone();
    let p = path.clone();
    let sender = tokio::spawn(async move { stream_events(&d, &p, &j).await });
    let (stream, body) = receive(&listener).await;
    assert_eq!(body["events"][0]["payload"]["offset"], 0);
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    *evidence.delay_write.lock().unwrap() = Some((ready_tx, release_rx));
    reply(stream, json!({})).await;
    ready_rx.await.unwrap();
    sender.abort();
    let _ = sender.await;
    // The canceled waiter has not published its uncommitted offset or released
    // sender/evidence ownership. Snapshots and local-control remain responsive.
    assert_eq!(snapshot(&shared).unwrap().stdout_offset, 0);
    assert!(daemon.managed_work() > 0);
    let status = tokio::time::timeout(Duration::from_millis(100), async {
        tokio::time::sleep(Duration::from_millis(10)).await;
        daemon.dispatch("status.get", json!({})).await
    })
    .await
    .unwrap()
    .unwrap();
    assert!(status["version"].as_str().is_some());
    let d = daemon.clone();
    let j = shared.clone();
    let p = path.clone();
    let second = tokio::spawn(async move { stream_events(&d, &p, &j).await });
    let stop_scope = scope.clone();
    let stop = tokio::spawn(async move { stop_scope.stop().await });
    tokio::time::sleep(Duration::from_millis(40)).await;
    assert!(!stop.is_finished());
    assert!(!second.is_finished());
    assert_eq!(snapshot(&shared).unwrap().stdout_pending, Some(5));
    release_tx.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(2), stop)
        .await
        .unwrap()
        .unwrap();
    assert!(!second.await.unwrap().unwrap());
    assert_eq!(snapshot(&shared).unwrap().stdout_offset, 5);
    assert_eq!(state::read_json::<Journal>(&path).unwrap().stdout_offset, 5);
    assert_eq!(daemon.managed_work(), 0);
    assert!(
        tokio::time::timeout(Duration::from_millis(40), listener.accept())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn responsive_blocking_workers_stay_bounded_after_waiter_cancellation() {
    let temp = tempfile::tempdir().unwrap();
    let daemon = daemon(temp.path(), "http://127.0.0.1:9".into());
    let shared = fault_journal(journal());
    let release = Arc::new(std::sync::Barrier::new(3));
    let (started_tx, mut started_rx) = tokio::sync::mpsc::unbounded_channel();
    let mut tasks = Vec::new();
    for index in 0..3 {
        let daemon = daemon.clone();
        let journal = shared.clone();
        let release = release.clone();
        let started = started_tx.clone();
        tasks.push(tokio::spawn(async move {
            job_io(&daemon, &journal, move || {
                started.send(index).unwrap();
                if index < 2 {
                    release.wait();
                }
                Ok(())
            })
            .await
        }));
        if index < 2 {
            assert_eq!(started_rx.recv().await, Some(index));
        }
    }
    let first = tasks.remove(0);
    first.abort();
    let _ = first.await;
    assert!(
        tokio::time::timeout(Duration::from_millis(40), started_rx.recv())
            .await
            .is_err()
    );
    assert!(daemon.managed_work() >= 2);
    release.wait();
    assert_eq!(started_rx.recv().await, Some(2));
    for task in tasks {
        task.await.unwrap().unwrap();
    }
    snapshot(&shared).unwrap().durable_writer.wait_idle().await;
    assert_eq!(daemon.managed_work(), 0);
}

#[tokio::test]
async fn responsive_two_slow_hashes_reserve_capacity_for_durable_renewal() {
    let temp = tempfile::tempdir().unwrap();
    let daemon = daemon(temp.path(), "http://127.0.0.1:9".into());
    let shared = fault_journal(journal());
    let path = temp.path().join("journal.json");
    state::write_json(&path, &snapshot(&shared).unwrap()).unwrap();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let d = daemon.clone();
    let j = shared.clone();
    let first = tokio::spawn(async move {
        job_hash_io(&d, &j, move || {
            ready_tx.send(()).unwrap();
            release_rx.recv_timeout(Duration::from_secs(5))?;
            Ok(())
        })
        .await
    });
    ready_rx.await.unwrap();
    let (second_tx, mut second_rx) = tokio::sync::oneshot::channel();
    let d = daemon.clone();
    let j = shared.clone();
    let second = tokio::spawn(async move {
        job_hash_io(&d, &j, move || {
            second_tx.send(()).unwrap();
            Ok(())
        })
        .await
    });
    // The first actual hash remains delayed, the second hash waits outside
    // the shared two-worker pool, and a renewal can commit its newer fence.
    let start = Instant::now();
    tokio::time::timeout(
        Duration::from_secs(1),
        update(&daemon, &path, &shared, |record| {
            record.job["leaseVersion"] = json!(8);
            Ok(())
        }),
    )
    .await
    .unwrap()
    .unwrap();
    let committed_in = start.elapsed();
    assert_eq!(snapshot(&shared).unwrap().job["leaseVersion"], 8);
    assert_eq!(
        state::read_json::<Journal>(&path).unwrap().job["leaseVersion"],
        8
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(30), &mut second_rx)
            .await
            .is_err()
    );
    println!(
        "reserved journal capacity: delayed_hash_requests=2 active_hash_workers=1 renewal_commit_ms={}",
        committed_in.as_millis()
    );
    first.abort();
    let _ = first.await;
    // Cancellation retains hash admission until its actual worker finishes.
    assert!(
        tokio::time::timeout(Duration::from_millis(30), &mut second_rx)
            .await
            .is_err()
    );
    release_tx.send(()).unwrap();
    second_rx.await.unwrap();
    second.await.unwrap().unwrap();
    snapshot(&shared).unwrap().durable_writer.wait_idle().await;
    assert_eq!(daemon.managed_work(), 0);
}

#[tokio::test]
async fn responsive_artifact_hash_await_rechecks_current_lease_before_transfer() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let temp = tempfile::tempdir().unwrap();
    let daemon = daemon(
        temp.path(),
        format!("http://{}", listener.local_addr().unwrap()),
    );
    let original = journal();
    let shared = fault_journal(original.clone());
    let journal_path = temp.path().join("journal.json");
    state::write_json(&journal_path, &original).unwrap();
    let artifact_path = temp.path().join("artifact");
    std::fs::write(&artifact_path, b"immutable transfer bytes").unwrap();
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    *original.durable_writer.delay_hash.lock().unwrap() = Some((ready_tx, release_rx));
    let d = daemon.clone();
    let j = shared.clone();
    let upload = tokio::spawn(async move {
        upload(
            &d,
            &j,
            &original,
            &artifact_path,
            "artifact",
            "application/octet-stream",
            "stable-tag",
        )
        .await
    });
    ready_rx.await.unwrap();
    update(&daemon, &journal_path, &shared, |record| {
        record.job["leasedUntilEpochMs"] = json!(0);
        Ok(())
    })
    .await
    .unwrap();
    release_tx.send(()).unwrap();
    assert_eq!(
        upload.await.unwrap().unwrap_err().to_string(),
        "RUNNER_JOB_LEASE_EXPIRED"
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(40), listener.accept())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn responsive_failed_durable_commit_preserves_committed_offsets() {
    let temp = tempfile::tempdir().unwrap();
    let daemon = daemon(temp.path(), "http://127.0.0.1:9".into());
    let shared = Arc::new(Mutex::new(journal()));
    let path = temp.path().join("journal.json");
    state::write_json(&path, &snapshot(&shared).unwrap()).unwrap();
    let invalid_path = path.join("journal.json");
    assert!(
        update(&daemon, &invalid_path, &shared, |record| {
            record.stdout_offset = 99;
            record.stdout_pending = None;
            Ok(())
        })
        .await
        .is_err()
    );
    assert_eq!(snapshot(&shared).unwrap().stdout_offset, 0);
    assert_eq!(state::read_json::<Journal>(&path).unwrap().stdout_offset, 0);
    assert_eq!(daemon.managed_work(), 0);
}

#[tokio::test]
async fn responsive_advisory_ack_timeout_retains_sender_until_durable_commit() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let temp = tempfile::tempdir().unwrap();
    let daemon = daemon(
        temp.path(),
        format!("http://{}", listener.local_addr().unwrap()),
    );
    let mut record = journal();
    record.job["payload"]["publicStatus"] =
        json!({"schemaVersion":"ai.public-status/v1","enabled":true});
    record.job["createdByNodeExecutionId"] = json!("33333333-3333-4333-8333-333333333333");
    let shared = fault_journal(record);
    let path = temp.path().join("journal.json");
    state::write_json(&path, &snapshot(&shared).unwrap()).unwrap();
    accept_status(&path, &shared, "Reviewing the draft").unwrap();
    let d = daemon.clone();
    let j = shared.clone();
    let p = path.clone();
    let first = tokio::spawn(async move { stream_events(&d, &p, &j).await });
    let (stream, event) = receive(&listener).await;
    assert_eq!(event["events"][0]["eventType"], "ai.public-status.v1");
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    *snapshot(&shared)
        .unwrap()
        .durable_writer
        .delay_write
        .lock()
        .unwrap() = Some((ready_tx, release_rx));
    reply(stream, json!({})).await;
    ready_rx.await.unwrap();
    // Exercise the real advisory timeout, which drops only the async waiter.
    assert!(
        !tokio::time::timeout(Duration::from_secs(4), first)
            .await
            .unwrap()
            .unwrap()
            .unwrap()
    );
    assert!(snapshot(&shared).unwrap().public_status_pending.is_some());
    assert!(daemon.managed_work() > 0);
    let d = daemon.clone();
    let j = shared.clone();
    let p = path.clone();
    let second = tokio::spawn(async move { stream_events(&d, &p, &j).await });
    assert!(
        tokio::time::timeout(Duration::from_millis(40), listener.accept())
            .await
            .is_err()
    );
    assert!(!second.is_finished());
    release_tx.send(()).unwrap();
    assert!(!second.await.unwrap().unwrap());
    assert!(snapshot(&shared).unwrap().public_status_pending.is_none());
    assert!(
        state::read_json::<Journal>(&path)
            .unwrap()
            .public_status_pending
            .is_none()
    );
    assert_eq!(daemon.managed_work(), 0);
}

#[tokio::test]
async fn responsive_fault_fixture_slots_do_not_capture_unrelated_recovery_capacity() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let temp = tempfile::tempdir().unwrap();
    let d = daemon(
        temp.path(),
        format!("http://{}", listener.local_addr().unwrap()),
    );
    let fault = fault_journal(journal());
    let (hash_ready_tx, hash_ready_rx) = tokio::sync::oneshot::channel();
    let (hash_release_tx, hash_release_rx) = std::sync::mpsc::channel();
    let hash_d = d.clone();
    let hash_j = fault.clone();
    let hash = tokio::spawn(async move {
        job_hash_io(&hash_d, &hash_j, move || {
            hash_ready_tx.send(()).unwrap();
            hash_release_rx.recv_timeout(Duration::from_secs(5))?;
            Ok(())
        })
        .await
    });
    hash_ready_rx.await.unwrap();
    let (write_ready_tx, write_ready_rx) = tokio::sync::oneshot::channel();
    let (write_release_tx, write_release_rx) = std::sync::mpsc::channel();
    let write_d = d.clone();
    let write_j = fault.clone();
    let write = tokio::spawn(async move {
        job_io(&write_d, &write_j, move || {
            write_ready_tx.send(()).unwrap();
            write_release_rx.recv_timeout(Duration::from_secs(5))?;
            Ok(())
        })
        .await
    });
    write_ready_rx.await.unwrap();
    // A normal fixture continues to use the real process-global admissions.
    // Fault owners stay held throughout renewal and terminal acknowledgment.
    let healthy = Arc::new(Mutex::new(journal()));
    let renewal_path = temp.path().join("healthy/journal.json");
    tokio::time::timeout(
        Duration::from_secs(1),
        update(&d, &renewal_path, &healthy, |record| {
            record.job["leaseVersion"] = json!(9);
            Ok(())
        }),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(
        state::read_json::<Journal>(&renewal_path).unwrap().job["leaseVersion"],
        9
    );
    let record = journal();
    let recovery_path = d
        .dir
        .join("jobs")
        .join(record.job["id"].as_str().unwrap())
        .join("journal.json");
    state::write_json(&recovery_path, &record).unwrap();
    let server = tokio::spawn(async move {
        let (stream, reclaim) = receive(&listener).await;
        assert_eq!(reclaim["sessionId"], "new-session");
        assert_eq!(reclaim["expectedLeaseVersion"], 7);
        assert_eq!(reclaim["terminalSubmission"], true);
        let mut renewed = journal().job;
        renewed["leaseVersion"] = json!(8);
        reply(stream, json!({"job":renewed})).await;
        let (stream, terminal) = receive(&listener).await;
        assert_eq!(terminal["sessionId"], "new-session");
        assert_eq!(terminal["leaseVersion"], 8);
        assert_eq!(terminal["idempotencyKey"], "persistent-terminal-key");
        assert_eq!(terminal["error"]["code"], "EXECUTION_INDETERMINATE");
        reply(stream, json!({"job":{"status":"failed"}})).await;
    });
    recover(d.clone(), "org", "new-session").await.unwrap();
    tokio::time::timeout(Duration::from_secs(8), async {
        server.await.unwrap();
        d.execution.join_recovery().await;
    })
    .await
    .unwrap();
    let final_record: Journal = state::read_json(&recovery_path).unwrap();
    assert_eq!(final_record.phase, JournalPhase::Acknowledged);
    assert_eq!(final_record.session, "new-session");
    assert_eq!(final_record.job["leaseVersion"], 8);
    assert_eq!(final_record.terminal_key, "persistent-terminal-key");
    assert!(final_record.delivery_diagnostic.is_none());
    assert!(final_record.identity.is_none());
    assert_eq!(d.execution.active_work(), 0);
    assert!(!hash.is_finished() && !write.is_finished());
    assert!(d.managed_work() >= 2);
    println!(
        "isolated fault overlap: held_hash=1 held_journal=1 normal_renewal=durable recovery=acknowledged fence=new-session/8 terminal_key=unchanged command_replayed=false"
    );
    hash_release_tx.send(()).unwrap();
    write_release_tx.send(()).unwrap();
    hash.await.unwrap().unwrap();
    write.await.unwrap().unwrap();
    snapshot(&fault).unwrap().durable_writer.wait_idle().await;
    assert_eq!(d.managed_work(), 0);
}
