use super::*;
use crate::{api::Api, auth::Auth};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
async fn receive(listener: &TcpListener) -> (TcpStream, Value) {
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
                return (stream, serde_json::from_slice(&bytes[end + 4..]).unwrap());
            }
        }
    }
}
async fn reply(mut stream: TcpStream, data: Value) {
    let body = json!({"data":data,"meta":{}}).to_string();
    stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{}",body.len(),body).as_bytes()).await.unwrap();
}
fn journal() -> Journal {
    Journal {
        job: json!({"id":"11111111-1111-4111-8111-111111111111","leaseVersion":7,"payloadDigest":"digest","createdByExecutionId":"22222222-2222-4222-8222-222222222222","createdByNodeExecutionId":null,"payload":{"command":["/bin/sh","-c","exit 99"]}}),
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
        event_sender: Default::default(),
        stdout_pending: None,
        stderr_pending: None,
        progress_buffer: Vec::new(),
        progress_buffer_offset: 0,
        progress_discarding: false,
        progress_pending: None,
        stdout_offset: 0,
        stderr_offset: 0,
    }
}
fn daemon(path: &Path, origin: String) -> Arc<Daemon> {
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
    let result = upload(
        &d,
        &journal(),
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
async fn restart_reclaims_only_terminal_delivery_after_historical_fence_is_rejected() {
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
        let (mut stream, body) = receive(&listener).await;
        assert_eq!(body["sessionId"], "old-session");
        let error = json!({"error":{"code":"RUNNER_JOB_NOT_FOUND"}}).to_string();
        stream
            .write_all(
                format!(
                    "HTTP/1.1 409 Conflict\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    error.len(),
                    error
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        drop(stream);
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
    tokio::time::timeout(std::time::Duration::from_secs(8), server)
        .await
        .unwrap()
        .unwrap();
    for _ in 0..100 {
        if d.execution.active_work() == 0 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    let record: Journal = state::read_json(&path).unwrap();
    assert_eq!(record.phase, "acknowledged");
    assert_eq!(record.session, "new-session");
    assert!(record.identity.is_none());
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
        let (stream, body) = receive(&listener).await;
        assert_eq!(body["sessionId"], "old-session");
        assert_eq!(body["leaseVersion"], 7);
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
