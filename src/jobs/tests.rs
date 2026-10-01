use super::*;
fn http_result_contract() -> Value {
    json!({"schemaVersion":HTTP_RESULT_SCHEMA,"artifactRefSchemaVersion":HTTP_BODY_REF_SCHEMA})
}
async fn execute_test_http_request(payload: &Value, cancel: Arc<AtomicBool>) -> Result<Value> {
    let temp = tempfile::tempdir()?;
    let mut payload = payload.clone();
    if payload.get("resultContract").is_none() {
        payload["resultContract"] = http_result_contract();
    }
    execute_test_http(&payload, cancel, &temp.path().join("response-body")).await
}
fn leased_payload_fixture() -> Value {
    json!({
        "payloadDigest": "cbab9f708061faba6e1a3bdc5be2cdac766e781a6f8b0e09f86cd512f2983a3b",
        "payload": {
            "command": ["/usr/bin/printf", "%s\\n", "LOOMEX_DIGEST_OK"],
            "cwd": ".", "executionPolicy": "host_user/v1",
            "workspacePath": "/tmp/loomex-workspace",
            "preparationId": "11111111-1111-4111-8111-111111111111",
            "bindingDigest": "bound-inputs", "providerConfiguration": {}, "env": {},
            "nested": {"authorizationEnvelope": "stable producer value"},
            "authorizationEnvelope": {
                "version": 1, "capability": "shell.exec", "actor": "leased-session",
                "inputDigest": "sha256:capability-input", "workspace": "/tmp/loomex-workspace",
                "expiresAtEpochMs": 2000000000000u64, "nonce": "lease-nonce",
                "approval": {"approved": true, "leaseVersion": 7}
            }
        }
    })
}

#[test]
fn leased_payload_digest_matches_backend_stable_projection() {
    // Digest independently produced by Python json.dumps(sort_keys=True,
    // separators=(',', ':'), ensure_ascii=False) before lease enrichment.
    let mut job = leased_payload_fixture();
    assert_ne!(state::json_digest(&job["payload"]), job["payloadDigest"]);
    verify_payload_digest(&job).unwrap();
    job["payload"]["authorizationEnvelope"]["nonce"] = json!("renewed-lease-nonce");
    verify_payload_digest(&job).unwrap();
    job["payload"]
        .as_object_mut()
        .unwrap()
        .remove("authorizationEnvelope");
    verify_payload_digest(&job).unwrap();
}

#[test]
fn leased_payload_digest_rejects_every_stable_field_tamper() {
    for (pointer, replacement) in [
        ("/payload/command/2", "TAMPERED"),
        ("/payload/workspacePath", "/tmp/other-workspace"),
        ("/payload/cwd", "other-directory"),
        ("/payload/bindingDigest", "different-binding"),
        (
            "/payload/nested/authorizationEnvelope",
            "tampered nested producer value",
        ),
    ] {
        let mut job = leased_payload_fixture();
        *job.pointer_mut(pointer).unwrap() = json!(replacement);
        assert_eq!(
            verify_payload_digest(&job).unwrap_err().to_string(),
            "PAYLOAD_DIGEST_MISMATCH",
            "{pointer}"
        );
    }
}

#[test]
fn typed_http_payload_requires_private_url_and_explicit_body_encoding() {
    let payload = json!({
        "schemaVersion": HTTP_REQUEST_SCHEMA,
        "method": "POST",
        "url": "http://127.0.0.1:8080/path",
        "headers": {"content-type": "application/json"},
        "body": {"encoding": "json", "value": {"safe": true}},
        "timeoutSeconds": 10,
        "expectedStatusCodes": [200],
        "resultContract": http_result_contract()
    });
    assert!(http_request(&payload).is_ok());
    let mut invalid = payload.clone();
    invalid["body"]["encoding"] = json!("base64");
    assert_eq!(
        http_request(&invalid).unwrap_err().to_string(),
        "HTTP_REQUEST_INVALID"
    );
    assert!(local_or_private("127.0.0.1".parse().unwrap()));
    assert!(!local_or_private("8.8.8.8".parse().unwrap()));
}

#[test]
fn resolved_http_addresses_must_be_nonempty_and_all_private() {
    let local: SocketAddr = "127.0.0.1:8080".parse().unwrap();
    assert_eq!(
        validate_private_http_addresses(vec![local]).unwrap(),
        vec![local]
    );
    assert_eq!(
        validate_private_http_addresses(vec![])
            .unwrap_err()
            .to_string(),
        "HTTP_REQUEST_URL_DENIED"
    );
    // This documentation-range address is only synthetic test data; the
    // test makes no network request to it.
    let public: SocketAddr = "203.0.113.1:8080".parse().unwrap();
    assert_eq!(
        validate_private_http_addresses(vec![local, public])
            .unwrap_err()
            .to_string(),
        "HTTP_REQUEST_URL_DENIED"
    );
}

#[tokio::test]
async fn http_resolution_cancellation_prevents_dispatch_phase() {
    let (started, observed_start) = tokio::sync::oneshot::channel();
    let cancel = Arc::new(AtomicBool::new(false));
    let cancellation = cancel.clone();
    let resolution = tokio::spawn(async move {
        resolve_private_http_addresses_with(
            cancellation,
            TokioInstant::now() + Duration::from_secs(1),
            async move {
                let _ = started.send(());
                std::future::pending::<Result<Vec<SocketAddr>>>().await
            },
        )
        .await
    });
    observed_start.await.unwrap();
    cancel.store(true, Ordering::SeqCst);
    assert_eq!(
        tokio::time::timeout(Duration::from_millis(250), resolution)
            .await
            .unwrap()
            .unwrap()
            .unwrap_err()
            .to_string(),
        "JOB_CANCELED"
    );
}

#[tokio::test]
async fn http_resolution_deadline_is_known_not_dispatched_timeout() {
    assert_eq!(
        resolve_private_http_addresses_with(
            Arc::new(AtomicBool::new(false)),
            TokioInstant::now() + Duration::from_millis(30),
            std::future::pending::<Result<Vec<SocketAddr>>>(),
        )
        .await
        .unwrap_err()
        .to_string(),
        "HTTP_REQUEST_TIMEOUT"
    );
}

#[tokio::test]
async fn local_http_execution_pins_local_target_and_redacts_response_headers() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = [0u8; 4096];
        let size = stream.read(&mut request).await.unwrap();
        assert!(
            String::from_utf8_lossy(&request[..size])
                .to_ascii_lowercase()
                .contains("idempotency-key: exact-key")
        );
        stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nX-Trace: visible\r\nSet-Cookie: private\r\nContent-Length: 11\r\nConnection: close\r\n\r\n{\"ok\":true}").await.unwrap();
    });
    let payload = json!({
        "schemaVersion": HTTP_REQUEST_SCHEMA,
        "method": "GET",
        "url": format!("http://{address}/"),
        "headers": {},
        "idempotencyKey": "exact-key",
        "timeoutSeconds": 10
    });
    let result = execute_test_http_request(&payload, Arc::new(AtomicBool::new(false)))
        .await
        .unwrap();
    server.await.unwrap();
    assert_eq!(result["statusCode"], 200);
    assert_eq!(result["body"], json!({"ok":true}));
    assert_eq!(result["headers"]["x-trace"], "visible");
    assert!(result["headers"].get("set-cookie").is_none());
}

#[tokio::test]
async fn cancellation_before_http_dispatch_is_not_dispatched() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let payload = json!({
        "schemaVersion": HTTP_REQUEST_SCHEMA,
        "method": "GET",
        "url": format!("http://{}/", listener.local_addr().unwrap()),
        "headers": {}, "timeoutSeconds": 1
    });
    let cancel = Arc::new(AtomicBool::new(true));
    assert_eq!(
        execute_test_http_request(&payload, cancel)
            .await
            .unwrap_err()
            .to_string(),
        "JOB_CANCELED"
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(100), listener.accept())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn http_deadline_covers_waiting_for_a_response() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let payload = json!({
        "schemaVersion": HTTP_REQUEST_SCHEMA,
        "method": "GET",
        "url": format!("http://{}/", listener.local_addr().unwrap()),
        "headers": {}, "timeoutSeconds": 1
    });
    let server = tokio::spawn(async move {
        let (_stream, _) = listener.accept().await.unwrap();
        tokio::time::sleep(Duration::from_secs(2)).await;
    });
    assert_eq!(
        execute_test_http_request(&payload, Arc::new(AtomicBool::new(false)))
            .await
            .unwrap_err()
            .to_string(),
        "HTTP_REQUEST_INDETERMINATE"
    );
    server.abort();
}

#[tokio::test]
async fn cancellation_after_http_dispatch_is_indeterminate_without_replay() {
    use tokio::io::AsyncReadExt;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (dispatched, observed_dispatch) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = [0u8; 4096];
        assert!(stream.read(&mut request).await.unwrap() > 0);
        let _ = dispatched.send(());
        // The client drops this stalled response on cancellation. A second
        // accepted connection would demonstrate an implicit replay.
        assert!(
            tokio::time::timeout(Duration::from_millis(125), listener.accept())
                .await
                .is_err()
        );
    });
    let payload = json!({
        "schemaVersion": HTTP_REQUEST_SCHEMA,
        "method": "GET",
        "url": format!("http://{address}/"),
        "headers": {}, "timeoutSeconds": 10
    });
    let cancel = Arc::new(AtomicBool::new(false));
    let execution_cancel = cancel.clone();
    let execution =
        tokio::spawn(async move { execute_test_http_request(&payload, execution_cancel).await });
    observed_dispatch.await.unwrap();
    cancel.store(true, Ordering::SeqCst);
    assert_eq!(
        tokio::time::timeout(Duration::from_millis(500), execution)
            .await
            .unwrap()
            .unwrap()
            .unwrap_err()
            .to_string(),
        "HTTP_REQUEST_INDETERMINATE"
    );
    server.await.unwrap();
}

#[tokio::test]
async fn failed_http_dispatch_is_not_retried_by_transport() {
    use tokio::io::AsyncReadExt;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = [0u8; 4096];
        assert!(stream.read(&mut request).await.unwrap() > 0);
        drop(stream); // Simulate a transport failure after first dispatch.
        assert!(
            tokio::time::timeout(Duration::from_millis(250), listener.accept())
                .await
                .is_err()
        );
    });
    let payload = json!({
        "schemaVersion": HTTP_REQUEST_SCHEMA,
        "method": "GET",
        "url": format!("http://{address}/"),
        "headers": {}, "timeoutSeconds": 10
    });
    assert_eq!(
        execute_test_http_request(&payload, Arc::new(AtomicBool::new(false)))
            .await
            .unwrap_err()
            .to_string(),
        "HTTP_REQUEST_INDETERMINATE"
    );
    server.await.unwrap();
}

fn provider_payload(provider: &str, input: &str) -> (Value, Vec<String>) {
    let adapter = canonical_provider_adapter(provider).unwrap();
    let executable = adapter["executable"].as_str().unwrap();
    let transport = if provider == "codex" {
        "codex.native-json/v2"
    } else {
        adapter["outputTransport"].as_str().unwrap()
    };
    let argv = if provider == "codex" {
        vec![
            executable.into(),
            "exec".into(),
            "--output-schema".into(),
            "{loomex:provider-schema}".into(),
            input.into(),
        ]
    } else {
        vec![executable.into(), "-p".into(), input.into()]
    };
    let mut payload = json!({
        "provider": provider,
        "providerAdapter": adapter,
        "providerOutputTransport": transport,
        "providerInput": input,
        "providerInputDigest": state::digest(input.as_bytes()),
    });
    if provider == "codex" {
        let schema = json!({"type":"object","properties":{"answer":{"type":"string"}}});
        payload["providerOutputSchema"] = schema.clone();
        payload["providerOutputSchemaDigest"] = json!(state::json_digest(&schema));
    }
    (payload, argv)
}

fn projected_codex_payload() -> (Value, Vec<String>) {
    let authored = json!({
        "type":"object",
        "properties":{
            "summary":{"type":"string","minLength":1},
            "verification":{"type":"array","items":{"type":"string"}},
            "limitations":{"type":"array","items":{"type":"string"}},
            "changedFiles":{"type":"array","items":{"type":"string"}},
            "generatedArtifacts":{"type":"array","items":{"type":"string"}},
            "relevantEarlierAnswers":{"type":"array","items":{"type":"string"}},
            "questions":{"type":"array","items":{
                "type":"object",
                "properties":{"inputType":{"type":"string","const":"text"}},
                "required":["inputType"],"additionalProperties":false,
            }},
        },
        "required":["summary","verification","limitations","changedFiles","generatedArtifacts","relevantEarlierAnswers","questions"],
        "additionalProperties":false,
    });
    let mut hint = authored.clone();
    hint["properties"]["summary"]
        .as_object_mut()
        .unwrap()
        .remove("minLength");
    hint["properties"]["questions"]["items"]["properties"]["inputType"] =
        json!({"type":"string","enum":["text"]});
    let input = json!({
        "schemaVersion":"loomex.provider-input/v1", "prompt":"fixture only",
        "context":{"outputSchema":authored}, "persona":{},
        "outputContract":"Return exactly the result JSON object requested by the prompt and context.outputSchema as native structured output."
    }).to_string();
    let (mut payload, argv) = provider_payload("codex", &input);
    payload["providerOutputTransport"] = json!("codex.native-projected-json/v3");
    payload["providerOutputSchema"] = hint.clone();
    payload["providerOutputSchemaDigest"] = json!(state::json_digest(&hint));
    payload["providerAuthoredOutputSchema"] = authored.clone();
    payload["providerAuthoredOutputSchemaDigest"] = json!(state::json_digest(&authored));
    (payload, argv)
}

#[test]
fn codex_projected_transport_matches_canonical_backend_vectors() {
    // This file is copied byte-for-byte into the backend tests. Its digests
    // are computed by Python's canonical sort_keys JSON representation.
    let vectors: Value = serde_json::from_str(include_str!(
        "../../contracts/codex-native-projection-v3-vectors.json"
    ))
    .unwrap();
    assert_eq!(vectors["schemaVersion"], "codex.native-projection-test-v1");
    for vector in vectors["vectors"].as_array().unwrap() {
        let id = vector["id"].as_str().unwrap();
        let authored = &vector["authored"];
        assert_eq!(
            state::json_digest(authored),
            vector["authoredDigest"],
            "{id}"
        );
        let mut hint = authored.clone();
        let projected =
            project_codex_native_hint(&mut hint).and_then(|()| validate_native_hint_schema(&hint));
        if vector["accept"] == true {
            projected.unwrap_or_else(|error| panic!("{id}: {error}"));
            assert_eq!(hint, vector["hint"], "{id}");
            assert_eq!(state::json_digest(&hint), vector["hintDigest"], "{id}");
        } else {
            assert!(projected.is_err(), "{id} unexpectedly admitted");
        }
    }
}

#[test]
fn codex_projected_transport_requires_exact_authored_and_hint_bindings() {
    let (payload, argv) = projected_codex_payload();
    validate_provider_input(&payload, &argv).unwrap();

    let mut missing = payload.clone();
    missing
        .as_object_mut()
        .unwrap()
        .remove("providerAuthoredOutputSchema");
    assert_eq!(
        validate_provider_input(&missing, &argv)
            .unwrap_err()
            .to_string(),
        "PROVIDER_SCHEMA_INVALID"
    );

    let mut bad_authored_digest = payload.clone();
    bad_authored_digest["providerAuthoredOutputSchemaDigest"] = json!("0".repeat(64));
    assert_eq!(
        validate_provider_input(&bad_authored_digest, &argv)
            .unwrap_err()
            .to_string(),
        "PROVIDER_SCHEMA_INVALID"
    );

    let mut bad_hint_digest = payload.clone();
    bad_hint_digest["providerOutputSchemaDigest"] = json!("0".repeat(64));
    assert_eq!(
        validate_provider_input(&bad_hint_digest, &argv)
            .unwrap_err()
            .to_string(),
        "PROVIDER_SCHEMA_INVALID"
    );

    let mut wrong_context = payload.clone();
    let mut parsed: Value =
        serde_json::from_str(wrong_context["providerInput"].as_str().unwrap()).unwrap();
    parsed["context"]["outputSchema"]["properties"]["summary"]["minLength"] = json!(2);
    let input = parsed.to_string();
    wrong_context["providerInput"] = json!(input.clone());
    wrong_context["providerInputDigest"] = json!(state::digest(input.as_bytes()));
    let mut wrong_argv = argv.clone();
    *wrong_argv.last_mut().unwrap() = input;
    assert_eq!(
        validate_provider_input(&wrong_context, &wrong_argv)
            .unwrap_err()
            .to_string(),
        "PROVIDER_SCHEMA_INVALID"
    );

    let mut weakened_array = payload.clone();
    weakened_array["providerOutputSchema"]["properties"]["verification"] = json!({"type":"string"});
    weakened_array["providerOutputSchemaDigest"] =
        json!(state::json_digest(&weakened_array["providerOutputSchema"]));
    assert_eq!(
        validate_provider_input(&weakened_array, &argv)
            .unwrap_err()
            .to_string(),
        "PROVIDER_SCHEMA_INVALID"
    );

    let mut wrong_const = payload.clone();
    wrong_const["providerOutputSchema"]["properties"]["questions"]["items"]["properties"]["inputType"]
        ["enum"] = json!(["radio"]);
    wrong_const["providerOutputSchemaDigest"] =
        json!(state::json_digest(&wrong_const["providerOutputSchema"]));
    assert_eq!(
        validate_provider_input(&wrong_const, &argv)
            .unwrap_err()
            .to_string(),
        "PROVIDER_SCHEMA_INVALID"
    );

    let mut old_mode = payload.clone();
    old_mode["providerOutputTransport"] = json!("codex.native-json/v2");
    assert_eq!(
        validate_provider_input(&old_mode, &argv)
            .unwrap_err()
            .to_string(),
        "PROVIDER_SCHEMA_INVALID"
    );
}

#[test]
fn codex_projected_transport_materializes_only_the_bound_hint() {
    let temp = tempfile::tempdir().unwrap();
    let (payload, mut argv) = projected_codex_payload();
    materialize_provider_output_schema(&payload, &mut argv, temp.path()).unwrap();
    let written: Value = state::read_json(&temp.path().join("provider-schema.json")).unwrap();
    assert_eq!(written, payload["providerOutputSchema"]);
    assert_ne!(written, payload["providerAuthoredOutputSchema"]);
    assert_ne!(argv[3], "{loomex:provider-schema}");
}

#[test]
fn provider_adapters_require_exact_canonical_prepared_contracts() {
    for provider in ["codex", "claude", "gemini", "antigravity"] {
        let (payload, argv) = provider_payload(provider, "fixture prompt");
        validate_provider_input(&payload, &argv).unwrap();
    }

    let (mut missing, argv) = provider_payload("claude", "fixture prompt");
    missing.as_object_mut().unwrap().remove("providerAdapter");
    assert_eq!(
        validate_provider_input(&missing, &argv)
            .unwrap_err()
            .to_string(),
        "PROVIDER_ADAPTER_INVALID"
    );

    let (mut extended, argv) = provider_payload("claude", "fixture prompt");
    extended["providerAdapter"]["unreviewed"] = json!(true);
    assert_eq!(
        validate_provider_input(&extended, &argv)
            .unwrap_err()
            .to_string(),
        "PROVIDER_ADAPTER_INVALID"
    );

    let (mut mismatch, argv) = provider_payload("antigravity", "fixture prompt");
    mismatch["provider"] = json!("gemini");
    assert_eq!(
        validate_provider_input(&mismatch, &argv)
            .unwrap_err()
            .to_string(),
        "PROVIDER_ADAPTER_INVALID"
    );

    let (mut transport, argv) = provider_payload("gemini", "fixture prompt");
    transport["providerOutputTransport"] = json!("antigravity.json/v1");
    assert_eq!(
        validate_provider_input(&transport, &argv)
            .unwrap_err()
            .to_string(),
        "PROVIDER_ADAPTER_INVALID"
    );
}

#[test]
fn codex_schema_materialization_is_bound_and_provider_specific() {
    let temp = tempfile::tempdir().unwrap();
    let (payload, mut argv) = provider_payload("codex", "fixture prompt");
    materialize_provider_output_schema(&payload, &mut argv, temp.path()).unwrap();
    let written: Value = state::read_json(&temp.path().join("provider-schema.json")).unwrap();
    assert_eq!(written, payload["providerOutputSchema"]);
    assert_ne!(argv[3], "{loomex:provider-schema}");

    let (payload, mut argv) = provider_payload("codex", "fixture prompt");
    argv.push("{loomex:provider-schema}".into());
    assert_eq!(
        materialize_provider_output_schema(&payload, &mut argv, temp.path())
            .unwrap_err()
            .to_string(),
        "PROVIDER_SCHEMA_INVALID"
    );

    let (mut payload, mut argv) = provider_payload("claude", "fixture prompt");
    payload["providerOutputSchema"] = json!({"type":"object"});
    payload["providerOutputSchemaDigest"] =
        json!(state::json_digest(&payload["providerOutputSchema"]));
    assert_eq!(
        materialize_provider_output_schema(&payload, &mut argv, temp.path())
            .unwrap_err()
            .to_string(),
        "PROVIDER_SCHEMA_INVALID"
    );
}

#[test]
fn fence_preserves_exact_lease() {
    let j = Journal {
        job: json!({"leaseVersion":42}),
        organization: "o".into(),
        session: "s".into(),
        recovery_session: None,
        phase: JournalPhase::Running,
        identity: None,
        result: None,
        error: None,
        terminal_key: "t".into(),
        started_at: 0,
        acknowledged_at: None,
        delivery_diagnostic: None,
        first_failure_diagnostic: None,
        event_sender: Default::default(),
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
    assert_eq!(fence(&j), json!({"sessionId":"s","leaseVersion":42}));
}
