use super::*;
use tokio::{io::AsyncReadExt, net::TcpListener};

fn receipt(method: &str) -> Value {
    let session = Uuid::new_v4();
    json!({
        "schemaVersion":"loomex.native-authoring-session/v1",
        "sessionId":session,"builderSessionId":session,"executionId":Uuid::new_v4(),
        "status":"queued",
        "systemWorkflowKey":if method == "builder.start" { "workflow_builder" } else { "workflow_editor" },
        "systemWorkflowVersionId":Uuid::new_v4(),
        "systemWorkflowDefinitionChecksum":"a".repeat(64),"nextAction":"run_get"
    })
}

fn arguments(method: &str) -> Value {
    let mut input =
        json!({"prompt":"Build the requested workflow","idempotencyKey":Uuid::new_v4()});
    if method == "editor.start" {
        input["workflowId"] = json!(Uuid::new_v4());
        input["expectedVersion"] = json!(0);
        input["expectedDefinitionChecksum"] = json!("b".repeat(64));
    }
    input
}

fn daemon(dir: &Path, api: Api, account: &str) -> Daemon {
    let daemon = Daemon::new(
        dir.into(),
        api.clone(),
        Auth::test_enrolled(api, "org", account),
    )
    .unwrap();
    *daemon.test_provider_paths.lock().unwrap() = Some(Vec::new());
    daemon
}

async fn request(listener: &TcpListener) -> (tokio::net::TcpStream, String, Value) {
    let (mut stream, _) = listener.accept().await.unwrap();
    let mut bytes = Vec::new();
    loop {
        let mut buffer = [0; 8192];
        let count = stream.read(&mut buffer).await.unwrap();
        assert!(count > 0);
        bytes.extend_from_slice(&buffer[..count]);
        if let Some(end) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&bytes[..end]).into_owned();
            let length = head
                .lines()
                .find_map(|line| {
                    line.to_ascii_lowercase()
                        .strip_prefix("content-length: ")
                        .and_then(|value| value.parse::<usize>().ok())
                })
                .unwrap_or(0);
            if bytes.len() >= end + 4 + length {
                return (
                    stream,
                    head,
                    if length == 0 {
                        json!({})
                    } else {
                        serde_json::from_slice(&bytes[end + 4..end + 4 + length]).unwrap()
                    },
                );
            }
        }
    }
}

async fn respond(mut stream: tokio::net::TcpStream, status: u16, data: Value) {
    let body = if status == 200 {
        json!({"data":data})
    } else {
        data
    }
    .to_string();
    stream.write_all(format!("HTTP/1.1 {status} Reply\r\nContent-Length: {}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes()).await.unwrap();
}

#[test]
fn native_start_contract_rejects_execution_and_publication_authority() {
    let catalog: Value =
        serde_json::from_str(include_str!("../contracts/method-catalog.json")).unwrap();
    for method in ["builder.start", "editor.start"] {
        let schema = &catalog["methods"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["name"] == method)
            .unwrap()["inputSchema"];
        let input = arguments(method);
        assert!(validate_params(&input, schema).is_ok());
        for field in [
            "workspacePath",
            "model",
            "providerConfiguration",
            "context",
            "executionPolicy",
            "publish",
            "confirm",
        ] {
            let mut changed = input.clone();
            changed[field] = json!(true);
            assert!(
                validate_params(&changed, schema).is_err(),
                "{method}/{field}"
            );
        }
        let mut changed = input.clone();
        changed["prompt"] = json!(" \n\t ");
        assert!(validate_params(&changed, schema).is_err());
        if method == "editor.start" {
            for field in [
                "workflowId",
                "expectedVersion",
                "expectedDefinitionChecksum",
            ] {
                let mut changed = input.clone();
                changed.as_object_mut().unwrap().remove(field);
                assert!(validate_params(&changed, schema).is_err());
            }
        }
        let (_, path, body) = backend_route(method, &input).unwrap();
        assert_eq!(
            path,
            if method == "builder.start" {
                "v2/workflow-builder/start/"
            } else {
                "v2/workflow-edit/start/"
            }
        );
        assert_eq!(body, Some(input));
        assert!(account_scoped_method(method));
    }
    for method in ["builder.get", "interactions.get", "workflow.operations.get"] {
        assert!(account_scoped_method(method));
    }
}

#[tokio::test]
async fn native_run_read_spools_deny_another_account_for_all_four_methods() {
    for method in ["runs.get", "runs.wait", "runs.events", "runs.result"] {
        let temp = tempfile::tempdir().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let api =
            Api::for_test_origin(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
        let owner = daemon(temp.path(), api.clone(), "first-owner");
        owner.public.lock().await.active_organization = Some("org".into());
        let run = Uuid::new_v4();
        let binding = json!({"schemaVersion":"loomex.native-authoring/v1","mode":"create","systemKey":"workflow_builder","sessionId":Uuid::new_v4(),"runnerId":Uuid::new_v4(),"workflowVersionId":Uuid::new_v4(),"definitionChecksum":"a".repeat(64)});
        let expected_binding = binding.clone();
        let server = tokio::spawn(async move {
            let (stream, head, _) = request(&listener).await;
            assert!(head.starts_with(&format!(
                "GET /api/v1/runner-control/runner/v1/executions/{run}/"
            )));
            respond(stream, 200, json!({"execution":{"id":run,"status":"running","privateDraft":"d".repeat(MAX_FRAME)},"humanRequest":null,"events":[],"latestSequence":0,"hasMoreEvents":false,"timedOut":false,"requiresAgentResponse":true,"agentRequest":{"id":Uuid::new_v4(),"requestType":"plugin_agent","answerChannel":"current_chat"},"nativeAuthoringBinding":binding})).await;
        });
        let result = owner
            .dispatch(method, json!({"runId":run,"timeoutSeconds":1}))
            .await
            .unwrap();
        let reference = result["responseRef"].as_str().unwrap();
        let stored: Value = state::read_json(
            &temp
                .path()
                .join("responses")
                .join(format!("{reference}.json")),
        )
        .unwrap();
        assert_eq!(stored["nativeAuthoringBinding"], expected_binding);
        assert_eq!(
            stored["execution"]["privateDraft"].as_str().unwrap().len(),
            MAX_FRAME
        );
        let metadata: Value = state::read_json(
            &temp
                .path()
                .join("responses")
                .join(format!("{reference}.meta.json")),
        )
        .unwrap();
        assert_eq!(
            metadata["ownerScope"],
            json!({"organizationId":"org","accountSubject":"first-owner"})
        );
        let read = json!({"responseRef":reference});
        assert!(owner.dispatch("responses.read", read.clone()).await.is_ok());
        let changed = daemon(temp.path(), api, "second-owner");
        changed.public.lock().await.active_organization = Some("org".into());
        assert_eq!(
            changed
                .dispatch("responses.read", read.clone())
                .await
                .unwrap_err()
                .to_string(),
            "RESPONSE_NOT_FOUND",
            "{method}"
        );
        assert_eq!(
            changed
                .dispatch(
                    "responses.delete",
                    json!({"responseRef":reference,"idempotencyKey":Uuid::new_v4()})
                )
                .await
                .unwrap_err()
                .to_string(),
            "RESPONSE_NOT_FOUND",
            "{method}"
        );
        server.await.unwrap();
    }
}

#[tokio::test]
async fn scoped_authoring_reads_reject_queued_account_substitution_before_transport() {
    for method in [
        "builder.get",
        "interactions.get",
        "workflow.operations.get",
        "runs.get",
        "runs.wait",
        "runs.events",
        "runs.result",
    ] {
        let temp = tempfile::tempdir().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let api =
            Api::for_test_origin(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
        let owner = Arc::new(daemon(temp.path(), api, "owner-a"));
        owner.public.lock().await.active_organization = Some("org".into());
        let input = match method {
            "builder.get" => json!({"sessionId":Uuid::new_v4()}),
            "interactions.get" => json!({"requestId":Uuid::new_v4()}),
            "workflow.operations.get" => {
                json!({"operation":"builder.start","idempotencyKey":Uuid::new_v4()})
            }
            _ => json!({"runId":Uuid::new_v4(),"timeoutSeconds":1}),
        };
        let gate = owner.auth.test_hold_credential_gate().await;
        let reader = owner.clone();
        let task = tokio::spawn(async move { reader.dispatch(method, input).await });
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert!(!task.is_finished());
        let changer = owner.clone();
        let drift = tokio::spawn(async move {
            changer
                .auth
                .test_fingerprint_identity_drift("org", None, Some("owner-b"))
                .await
        });
        tokio::time::sleep(Duration::from_millis(30)).await;
        drop(gate);
        drift.await.unwrap().unwrap();
        assert_eq!(
            task.await.unwrap().unwrap_err().to_string(),
            "AUTH_IDENTITY_CHANGED",
            "{method}"
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(100), listener.accept())
                .await
                .is_err(),
            "{method}"
        );
        assert!(!temp.path().join("responses").exists(), "{method}");
    }
}

#[tokio::test]
async fn scoped_authoring_read_rejects_account_drift_during_transport_without_spooling() {
    let temp = tempfile::tempdir().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let api = Api::for_test_origin(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
    let owner = Arc::new(daemon(temp.path(), api, "owner-a"));
    owner.public.lock().await.active_organization = Some("org".into());
    let server_owner = owner.clone();
    let request_id = Uuid::new_v4();
    let server = tokio::spawn(async move {
        let (stream, head, _) = request(&listener).await;
        let proof = head
            .lines()
            .find(|line| {
                line.to_ascii_lowercase()
                    .starts_with("x-loomex-runner-proof:")
            })
            .unwrap()
            .split_once(':')
            .unwrap()
            .1
            .trim();
        let parts: Vec<_> = proof.split('.').collect();
        let path = head
            .lines()
            .next()
            .unwrap()
            .split_whitespace()
            .nth(1)
            .unwrap();
        let message = format!(
            "GET|{path}|{}|{}|{}|testprefix|owner-a",
            state::digest(b""),
            parts[0],
            parts[1]
        );
        let signature = ed25519_dalek::Signature::from_slice(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(parts[2])
                .unwrap(),
        )
        .unwrap();
        ed25519_dalek::Verifier::verify(
            &ed25519_dalek::SigningKey::from_bytes(&[7; 32]).verifying_key(),
            message.as_bytes(),
            &signature,
        )
        .unwrap();
        server_owner
            .auth
            .test_fingerprint_identity_drift("org", None, Some("owner-b"))
            .await
            .unwrap();
        respond(stream, 200, json!({"humanRequest":{"id":request_id,"requestType":"plugin_agent","answerChannel":"current_chat","task":"private".repeat(MAX_FRAME)}})).await;
    });
    assert_eq!(
        owner
            .dispatch("interactions.get", json!({"requestId":request_id}))
            .await
            .unwrap_err()
            .to_string(),
        "AUTH_IDENTITY_CHANGED"
    );
    assert!(!temp.path().join("responses").exists());
    server.await.unwrap();
}

#[tokio::test]
async fn native_stale_proof_rejection_allows_only_exact_args_to_retry_start() {
    for method in ["builder.start", "editor.start"] {
        let temp = tempfile::tempdir().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let api =
            Api::for_test_origin(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
        let daemon = daemon(temp.path(), api, "owner");
        daemon.public.lock().await.active_organization = Some("org".into());
        let input = arguments(method);
        let copy = input.clone();
        let expected = receipt(method);
        let server_expected = expected.clone();
        let server = tokio::spawn(async move {
            for index in 0..2 {
                let (stream, head, body) = request(&listener).await;
                assert!(head.contains(if method == "builder.start" {
                    "/v2/workflow-builder/start/"
                } else {
                    "/v2/workflow-edit/start/"
                }));
                assert_eq!(body, copy);
                if index == 0 {
                    respond(stream, 422, json!({"error":{"code":"RUNNER_PROOF_STALE"}})).await;
                } else {
                    respond(stream, 200, server_expected.clone()).await;
                }
            }
            assert!(
                tokio::time::timeout(Duration::from_millis(100), listener.accept())
                    .await
                    .is_err()
            );
        });
        assert_eq!(
            public_error(&daemon.dispatch(method, input.clone()).await.unwrap_err()).0,
            "RUNNER_PROOF_STALE"
        );
        let mut changed = input.clone();
        changed["prompt"] = json!("Different intent");
        assert_eq!(
            daemon
                .dispatch(method, changed)
                .await
                .unwrap_err()
                .to_string(),
            "IDEMPOTENCY_CONFLICT"
        );
        assert_eq!(daemon.dispatch(method, input).await.unwrap(), expected);
        server.await.unwrap();
    }
}

#[tokio::test]
async fn native_stale_proof_rejection_is_consumed_before_a_transmitted_retry() {
    let temp = tempfile::tempdir().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let api = Api::for_test_origin(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
    let daemon = daemon(temp.path(), api, "owner");
    daemon.public.lock().await.active_organization = Some("org".into());
    let input = arguments("builder.start");
    let key = input["idempotencyKey"].clone();
    let server = tokio::spawn(async move {
        let (stream, head, _) = request(&listener).await;
        assert!(head.contains("/v2/workflow-builder/start/"));
        respond(stream, 422, json!({"error":{"code":"RUNNER_PROOF_STALE"}})).await;
        let (stream, head, _) = request(&listener).await;
        assert!(head.contains("/v2/workflow-builder/start/"));
        drop(stream);
        let (stream, head, body) = request(&listener).await;
        assert!(head.contains("/v2/workflow-operations/get/"));
        assert_eq!(
            body,
            json!({"operation":"builder.start","idempotencyKey":key})
        );
        respond(
            stream,
            200,
            json!({"operation":"builder.start","idempotencyKey":key,"status":"not_found"}),
        )
        .await;
        assert!(
            tokio::time::timeout(Duration::from_millis(100), listener.accept())
                .await
                .is_err()
        );
    });
    assert_eq!(
        public_error(
            &daemon
                .dispatch("builder.start", input.clone())
                .await
                .unwrap_err()
        )
        .0,
        "RUNNER_PROOF_STALE"
    );
    for _ in 0..2 {
        assert_eq!(
            daemon
                .dispatch("builder.start", input.clone())
                .await
                .unwrap_err()
                .to_string(),
            "NETWORK_AMBIGUOUS"
        );
    }
    server.await.unwrap();
}

#[tokio::test]
async fn native_stale_proof_code_without_authoritative_422_never_authorizes_replay() {
    for status in [400, 500] {
        let temp = tempfile::tempdir().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let api =
            Api::for_test_origin(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
        let daemon = daemon(temp.path(), api, "owner");
        daemon.public.lock().await.active_organization = Some("org".into());
        let input = arguments("builder.start");
        let key = input["idempotencyKey"].clone();
        let server = tokio::spawn(async move {
            let (stream, head, _) = request(&listener).await;
            assert!(head.contains("/v2/workflow-builder/start/"));
            respond(
                stream,
                status,
                json!({"error":{"code":"RUNNER_PROOF_STALE"}}),
            )
            .await;
            let (stream, head, _) = request(&listener).await;
            assert!(head.contains("/v2/workflow-operations/get/"));
            respond(
                stream,
                200,
                json!({"operation":"builder.start","idempotencyKey":key,"status":"not_found"}),
            )
            .await;
            assert!(
                tokio::time::timeout(Duration::from_millis(100), listener.accept())
                    .await
                    .is_err()
            );
        });
        assert_eq!(
            public_error(
                &daemon
                    .dispatch("builder.start", input.clone())
                    .await
                    .unwrap_err()
            )
            .0,
            "RUNNER_PROOF_STALE"
        );
        assert_eq!(
            daemon
                .dispatch("builder.start", input)
                .await
                .unwrap_err()
                .to_string(),
            "NETWORK_AMBIGUOUS"
        );
        server.await.unwrap();
    }
}

#[test]
fn native_start_receipt_requires_immutable_core_provenance() {
    for method in ["builder.start", "editor.start"] {
        let original = receipt(method);
        assert!(verify_native_authoring_start(method, &original).is_ok());
        for (field, value) in [
            ("builderSessionId", json!(Uuid::new_v4())),
            ("systemWorkflowVersionId", json!("fabricated")),
            ("systemWorkflowDefinitionChecksum", json!("A".repeat(64))),
            ("status", json!("completed")),
            ("systemWorkflowKey", json!("untrusted_graph")),
            ("executionPolicy", json!("host_user/v1")),
        ] {
            let mut changed = original.clone();
            changed[field] = value;
            assert!(
                verify_native_authoring_start(method, &changed).is_err(),
                "{field}"
            );
        }
    }
}

#[test]
fn native_agent_projection_is_preserved_and_never_coalesced_as_idle_progress() {
    let catalog: Value =
        serde_json::from_str(include_str!("../contracts/method-catalog.json")).unwrap();
    let binding = json!({"schemaVersion":"loomex.native-authoring/v1","mode":"create","systemKey":"workflow_builder","sessionId":Uuid::new_v4(),"runnerId":Uuid::new_v4(),"workflowVersionId":Uuid::new_v4(),"definitionChecksum":"a".repeat(64)});
    let agent =
        json!({"id":Uuid::new_v4(),"requestType":"plugin_agent","answerChannel":"current_chat"});
    let accepted = json!({"schemaVersion":"loomex.native-authoring-result/v1","status":"accepted","workflowId":Uuid::new_v4(),"draft":{"id":Uuid::new_v4(),"revision":1,"definitionChecksum":"b".repeat(64)}});
    let snapshot = json!({"execution":{"id":Uuid::new_v4(),"status":"running"},"humanRequest":null,"waitState":"automated_progress","events":[{"type":"ai.progress.v1","sequence":1}],"latestSequence":1,"hasMoreEvents":false,"timedOut":false,"requiresAgentResponse":true,"agentRequest":agent,"nativeAuthoringBinding":binding});
    assert!(!automated_progress_only(&snapshot));
    for name in ["runs.get", "runs.wait", "runs.events", "runs.result"] {
        let schema = &catalog["methods"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["name"] == name)
            .unwrap()["outputSchema"];
        let result = normalize_catalog_output(snapshot.clone(), schema).unwrap();
        assert_eq!(result["agentRequest"], agent);
        assert_eq!(result["nativeAuthoringBinding"], binding);
        assert!(result.get("details").is_none());
        let mut terminal = snapshot.clone();
        terminal["execution"]["status"] = json!("completed");
        terminal["nativeAuthoringResult"] = accepted.clone();
        let result = normalize_catalog_output(terminal, schema).unwrap();
        assert_eq!(result["nativeAuthoringResult"], accepted);
        assert!(result.get("details").is_none());
    }
    let mut inconsistent = snapshot;
    inconsistent["requiresAgentResponse"] = json!(false);
    assert!(!automated_progress_only(&inconsistent));
}

#[tokio::test]
async fn native_starts_need_no_workspace_or_provider_and_replay_only_receipts() {
    for method in ["builder.start", "editor.start"] {
        let temp = tempfile::tempdir().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let api =
            Api::for_test_origin(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
        let daemon = daemon(temp.path(), api, "owner");
        daemon.public.lock().await.active_organization = Some("org".into());
        let input = arguments(method);
        let expected = receipt(method);
        let server_input = input.clone();
        let server_expected = expected.clone();
        let server = tokio::spawn(async move {
            let (stream, head, body) = request(&listener).await;
            assert!(head.starts_with(&format!(
                "POST /api/v1/runner-control/runner/{} HTTP/1.1",
                if method == "builder.start" {
                    "v2/workflow-builder/start/"
                } else {
                    "v2/workflow-edit/start/"
                }
            )));
            assert_eq!(body, server_input);
            respond(stream, 200, server_expected.clone()).await;
            let (stream, head, body) = request(&listener).await;
            assert!(head.starts_with(
                "POST /api/v1/runner-control/runner/v2/workflow-operations/get/ HTTP/1.1"
            ));
            assert_eq!(
                body,
                json!({"operation":method,"idempotencyKey":server_input["idempotencyKey"]})
            );
            respond(stream, 200, json!({"operation":method,"idempotencyKey":server_input["idempotencyKey"],"status":"completed","response":server_expected})).await;
            assert!(
                tokio::time::timeout(Duration::from_millis(100), listener.accept())
                    .await
                    .is_err()
            );
        });
        assert_eq!(
            daemon.dispatch(method, input.clone()).await.unwrap(),
            expected
        );
        assert_eq!(
            daemon.dispatch(method, input.clone()).await.unwrap(),
            expected
        );
        let mut changed = input;
        changed["prompt"] = json!("Different intent");
        assert_eq!(
            daemon
                .dispatch(method, changed)
                .await
                .unwrap_err()
                .to_string(),
            "IDEMPOTENCY_CONFLICT"
        );
        assert!(daemon.public.lock().await.grants.is_empty());
        assert!(!temp.path().join("preparations").exists());
        server.await.unwrap();
    }
}

#[tokio::test]
async fn native_start_lost_response_never_replays_start_even_without_a_receipt() {
    let temp = tempfile::tempdir().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let api = Api::for_test_origin(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
    let daemon = daemon(temp.path(), api, "owner");
    daemon.public.lock().await.active_organization = Some("org".into());
    let input = arguments("builder.start");
    let key = input["idempotencyKey"].clone();
    let expected = receipt("builder.start");
    let server_expected = expected.clone();
    let server = tokio::spawn(async move {
        let (stream, head, _) = request(&listener).await;
        assert!(head.contains("/v2/workflow-builder/start/"));
        drop(stream);
        for status in ["not_found", "pending", "completed"] {
            let (stream, head, body) = request(&listener).await;
            assert!(head.contains("/v2/workflow-operations/get/"));
            assert_eq!(
                body,
                json!({"operation":"builder.start","idempotencyKey":key})
            );
            let mut data =
                json!({"operation":"builder.start","idempotencyKey":key,"status":status});
            if status == "completed" {
                data["response"] = server_expected.clone();
            }
            respond(stream, 200, data).await;
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(100), listener.accept())
                .await
                .is_err()
        );
    });
    for _ in 0..3 {
        assert_eq!(
            daemon
                .dispatch("builder.start", input.clone())
                .await
                .unwrap_err()
                .to_string(),
            "NETWORK_AMBIGUOUS"
        );
    }
    assert_eq!(
        daemon.dispatch("builder.start", input).await.unwrap(),
        expected
    );
    server.await.unwrap();
}

#[tokio::test]
async fn native_start_journals_are_account_scoped_and_cached_reads_recheck_permission() {
    let temp = tempfile::tempdir().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let api = Api::for_test_origin(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
    let input = arguments("builder.start");
    let first = receipt("builder.start");
    let second = receipt("builder.start");
    let server_first = first.clone();
    let server_second = second.clone();
    let server = tokio::spawn(async move {
        let (stream, head, _) = request(&listener).await;
        assert!(head.contains("/v2/workflow-builder/start/"));
        respond(stream, 200, server_first).await;
        let (stream, head, _) = request(&listener).await;
        assert!(head.contains("/v2/workflow-operations/get/"));
        respond(
            stream,
            403,
            json!({"error":{"code":"AUTHORIZATION_FAILED"}}),
        )
        .await;
        let (stream, head, _) = request(&listener).await;
        assert!(head.contains("/v2/workflow-builder/start/"));
        respond(stream, 200, server_second).await;
        assert!(
            tokio::time::timeout(Duration::from_millis(100), listener.accept())
                .await
                .is_err()
        );
    });
    let owner = daemon(temp.path(), api.clone(), "first-owner");
    owner.public.lock().await.active_organization = Some("org".into());
    assert_eq!(
        owner
            .dispatch("builder.start", input.clone())
            .await
            .unwrap(),
        first
    );
    let denied = owner
        .dispatch("builder.start", input.clone())
        .await
        .unwrap_err();
    assert_eq!(public_error(&denied).0, "AUTHORIZATION_FAILED");
    drop(owner);
    let changed = daemon(temp.path(), api, "second-owner");
    changed.public.lock().await.active_organization = Some("org".into());
    assert_eq!(
        changed.dispatch("builder.start", input).await.unwrap(),
        second
    );
    assert_eq!(
        std::fs::read_dir(temp.path().join("operations"))
            .unwrap()
            .count(),
        2
    );
    server.await.unwrap();
}

#[tokio::test]
async fn native_editor_invalid_baseline_fails_before_backend_dispatch() {
    let temp = tempfile::tempdir().unwrap();
    let api = Api::for_test_origin("http://127.0.0.1:1").unwrap();
    let daemon = daemon(temp.path(), api, "owner");
    daemon.public.lock().await.active_organization = Some("org".into());
    let mut input = arguments("editor.start");
    input["expectedDefinitionChecksum"] = json!("A".repeat(64));
    assert_eq!(
        daemon
            .dispatch("editor.start", input)
            .await
            .unwrap_err()
            .to_string(),
        "INVALID_REQUEST"
    );
    assert!(!temp.path().join("operations").exists());
}

#[tokio::test]
async fn native_agent_task_spool_preserves_complete_schema_and_owner_binding() {
    let temp = tempfile::tempdir().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let api = Api::for_test_origin(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
    let owner = daemon(temp.path(), api.clone(), "owner");
    owner.public.lock().await.active_organization = Some("org".into());
    let request_id = Uuid::new_v4();
    let result = json!({"humanRequest":{"id":request_id,"requestType":"plugin_agent","answerChannel":"current_chat","schemaDigest":"c".repeat(64),"inputSpec":{"prompt":"p".repeat(MAX_FRAME),"outputSchema":{"type":"object","properties":{"proposal":{"type":"object"}},"required":["proposal"],"additionalProperties":false}}},"execution":{"id":Uuid::new_v4()}});
    let expected = result.clone();
    let server = tokio::spawn(async move {
        let (stream, head, body) = request(&listener).await;
        assert!(head.starts_with(&format!(
            "GET /api/v1/runner-control/runner/v1/human-requests/{request_id}/ HTTP/1.1"
        )));
        assert_eq!(body, json!({}));
        respond(stream, 200, result).await;
    });
    let spooled = owner
        .dispatch("interactions.get", json!({"requestId":request_id}))
        .await
        .unwrap();
    let reference = spooled["responseRef"].as_str().unwrap();
    let bytes = std::fs::read(
        temp.path()
            .join("responses")
            .join(format!("{reference}.json")),
    )
    .unwrap();
    assert_eq!(state::digest(&bytes), spooled["checksumSha256"]);
    assert_eq!(serde_json::from_slice::<Value>(&bytes).unwrap(), expected);
    let read = json!({"responseRef":reference});
    assert!(owner.dispatch("responses.read", read.clone()).await.is_ok());
    let other = daemon(temp.path(), api, "other-owner");
    other.public.lock().await.active_organization = Some("org".into());
    assert_eq!(
        other
            .dispatch("responses.read", read)
            .await
            .unwrap_err()
            .to_string(),
        "RESPONSE_NOT_FOUND"
    );
    server.await.unwrap();
}
