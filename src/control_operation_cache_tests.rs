use super::*;

const ORG: &str = "11111111-1111-4111-8111-111111111111";
const ACCOUNT: &str = "22222222-2222-4222-8222-222222222222";
async fn daemon() -> (tempfile::TempDir, Daemon) {
    let temp = tempfile::tempdir().unwrap();
    let api = Api::for_test_origin("http://127.0.0.1:9").unwrap();
    let daemon = Daemon::new(
        temp.path().into(),
        api.clone(),
        Auth::test_enrolled(api, ORG, ACCOUNT),
    )
    .unwrap();
    daemon.public.lock().await.active_organization = Some(ORG.into());
    (temp, daemon)
}
fn provenance() -> Value {
    json!({"operationId":Uuid::new_v4(),"attemptId":Uuid::new_v4(),"journalSha256":"a".repeat(64),"receiptSha256":"b".repeat(64),"expectedAssessmentSha256":"c".repeat(64),"requestSetSha256":"d".repeat(64),"contextSha256":"e".repeat(64),"installationId":"test-install","retirementScope":"operation-observations","canonicalObservation":{"remoteOutcome":"unknown","safeReason":"missing_binding"}})
}
fn seed(dir: &Path, slot: &str, record: Value) -> PathBuf {
    let path = dir.join("operations").join(format!("{slot}.json"));
    state::write_json(&path, &record).unwrap();
    path
}

#[tokio::test]
async fn operation_cache_ordinary_pending_never_reenters_mutation_handler() {
    let (temp, daemon) = daemon().await;
    let key = Uuid::new_v4().to_string();
    let params = json!({"idempotencyKey":key,"runId":Uuid::new_v4(),"reason":"same request"});
    let record = json!({"digest":operation_cache_identity("runs.cancel",&params,Some(ORG),None),"method":"runs.cancel","status":"pending"});
    let path = seed(temp.path(), &key, record);
    let before = std::fs::read(&path).unwrap();
    assert_eq!(
        daemon
            .dispatch("runs.cancel", params)
            .await
            .unwrap_err()
            .to_string(),
        "OPERATION_RECONCILIATION_REQUIRED"
    );
    assert_eq!(std::fs::read(path).unwrap(), before);
}

#[tokio::test]
async fn operation_cache_legacy_completed_result_remains_replayable() {
    let (temp, daemon) = daemon().await;
    let key = Uuid::new_v4().to_string();
    let params = json!({"idempotencyKey":key,"name":"old creation"});
    let result = json!({"workflow":{"id":Uuid::new_v4(),"name":"old creation"}});
    let record = json!({"digest":operation_cache_identity("workflows.create",&params,Some(ORG),None),"method":"workflows.create","result":result});
    seed(temp.path(), &key, record);
    assert_eq!(
        daemon.dispatch("workflows.create", params).await.unwrap(),
        result
    );
}

#[tokio::test]
async fn operation_cache_inline_and_spooled_commit_replays_keep_execution() {
    let (temp, daemon) = daemon().await;
    let key = Uuid::new_v4().to_string();
    let run = Uuid::new_v4().to_string();
    let params = json!({"idempotencyKey":key,"preparationId":Uuid::new_v4(),"confirmationKey":Uuid::new_v4(),"bindingDigest":"binding"});
    let slot = operation_cache_scoped_key(Some(ORG), Some(ACCOUNT), &key);
    let result = json!({"execution":{"id":run,"large":"x".repeat(MAX_FRAME)},"preparationId":params["preparationId"],"executionPolicy":"host_user/v1"});
    let record = json!({"digest":operation_cache_identity("runs.commit",&params,Some(ORG),Some(ACCOUNT)),"method":"runs.commit","executionId":run,"result":result});
    let path = seed(temp.path(), &slot, record);
    let first = daemon
        .dispatch("runs.commit", params.clone())
        .await
        .unwrap();
    assert!(first["responseRef"].is_string());
    let first_cache: Value = state::read_json(&path).unwrap();
    assert_eq!(first_cache["executionId"], run);
    let metadata_path = temp.path().join("responses").join(format!(
        "{}.meta.json",
        first["responseRef"].as_str().unwrap()
    ));
    let mut metadata: Value = state::read_json(&metadata_path).unwrap();
    assert_eq!(metadata["executionId"], run);
    assert_eq!(
        daemon
            .dispatch("runs.commit", params.clone())
            .await
            .unwrap(),
        first
    );
    let replayed: Value = state::read_json(&path).unwrap();
    assert_eq!(replayed["executionId"], run);
    metadata["executionId"] = json!(Uuid::new_v4());
    state::write_json(&metadata_path, &metadata).unwrap();
    assert_eq!(
        daemon
            .dispatch("runs.commit", params)
            .await
            .unwrap_err()
            .to_string(),
        "OPERATION_CACHE_BINDING_MISMATCH"
    );
}

#[tokio::test]
async fn operation_cache_retired_slot_denies_changed_arguments_and_method_after_source_cleanup() {
    let (temp, daemon) = daemon().await;
    let key = Uuid::new_v4().to_string();
    let slot = operation_cache_scoped_key(Some(ORG), Some(ACCOUNT), &key);
    let old = json!({"digest":"a".repeat(64),"method":"interactions.respond","status":"pending"});
    let path = seed(temp.path(), &slot, old);
    let evidence = crate::operation_cache::retirement_evidence(
        &slot,
        &std::fs::read(&path).unwrap(),
        &provenance(),
    )
    .unwrap();
    state::write_json(
        &temp
            .path()
            .join(crate::operation_cache::retirement_relative(&slot).unwrap()),
        &evidence,
    )
    .unwrap();
    std::fs::remove_file(path).unwrap();
    let changed = json!({"idempotencyKey":key,"requestId":Uuid::new_v4(),"expectedRevision":99});
    assert_eq!(
        daemon
            .dispatch("interactions.draft.delete", changed)
            .await
            .unwrap_err()
            .to_string(),
        "OPERATION_CACHE_RETIRED"
    );
}

#[tokio::test]
async fn operation_cache_bound_installation_drift_blocks_cached_replay() {
    let (temp, daemon) = daemon().await;
    let key = Uuid::new_v4().to_string();
    let params = json!({"idempotencyKey":key,"runId":Uuid::new_v4(),"reason":"same request"});
    let digest = operation_cache_identity("runs.cancel", &params, Some(ORG), None);
    let catalog: Value =
        serde_json::from_str(include_str!("../contracts/method-catalog.json")).unwrap();
    let schema = &catalog["methods"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["name"] == "runs.cancel")
        .unwrap()["inputSchema"];
    let record = crate::operation_cache::completed(
        crate::operation_cache::pending(
            &digest,
            "runs.cancel",
            crate::operation_cache::binding(
                "runs.cancel",
                &key,
                &digest,
                schema,
                &params,
                crate::operation_cache::BindingOrigin {
                    organization: Some(ORG),
                    account: Some(ACCOUNT),
                    installation: "old-installation",
                    control_reference: None,
                },
            ),
        ),
        json!({"cancelled":true}),
        None,
    );
    seed(temp.path(), &key, record);
    assert_eq!(
        daemon
            .dispatch("runs.cancel", params)
            .await
            .unwrap_err()
            .to_string(),
        "OPERATION_CACHE_BINDING_MISMATCH"
    );
}

#[test]
fn operation_cache_binding_is_bounded_and_never_duplicates_prompt_or_answer() {
    let secret = "private-answer".repeat(100_000);
    let params = json!({"requestId":Uuid::new_v4(),"idempotencyKey":Uuid::new_v4(),"answer":{"text":secret},"prompt":secret,"expectedSchemaDigest":"a".repeat(64),"expectedRevision":3});
    let binding = crate::operation_cache::binding(
        "interactions.respond",
        params["idempotencyKey"].as_str().unwrap(),
        &"a".repeat(64),
        &json!({}),
        &params,
        crate::operation_cache::BindingOrigin {
            organization: Some(ORG),
            account: Some(ACCOUNT),
            installation: "installation",
            control_reference: None,
        },
    );
    let encoded = serde_json::to_string(&binding).unwrap();
    assert!(encoded.len() < 8192);
    assert!(!encoded.contains("private-answer"));
    assert_eq!(binding["references"]["expectedRevision"], 3);
}

#[test]
fn operation_cache_submission_fingerprint_preserves_optional_presence_and_fails_closed_for_floats()
{
    let mut params = json!({"requestId":Uuid::new_v4(),"idempotencyKey":Uuid::new_v4(),"answer":{"n":1,"text":"سلام"}});
    let first = interaction_cache_receipt("interactions.respond", &params)
        .unwrap()
        .unwrap();
    params["expectedSchemaDigest"] = json!("schema");
    let second = interaction_cache_receipt("interactions.respond", &params)
        .unwrap()
        .unwrap();
    assert_ne!(
        first["params"]["submissionFingerprint"],
        second["params"]["submissionFingerprint"]
    );
    params["answer"]["n"] = json!(1e-6);
    assert!(
        interaction_cache_receipt("interactions.respond", &params)
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn operation_cache_interaction_pending_uses_exact_read_receipt_and_never_resolves_again() {
    for exact in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let api =
            Api::for_test_origin(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
        let daemon = Daemon::new(
            temp.path().into(),
            api.clone(),
            Auth::test_enrolled(api, ORG, ACCOUNT),
        )
        .unwrap();
        daemon.public.lock().await.active_organization = Some(ORG.into());
        let key = Uuid::new_v4().to_string();
        let run = Uuid::new_v4().to_string();
        let request = Uuid::new_v4().to_string();
        let params = json!({"idempotencyKey":key,"requestId":request,"answer":{"text":"private answer"},"expectedSchemaDigest":"schema"});
        let descriptor = interaction_cache_receipt("interactions.respond", &params)
            .unwrap()
            .unwrap();
        let slot = operation_cache_scoped_key(Some(ORG), Some(ACCOUNT), &key);
        let path = seed(
            temp.path(),
            &slot,
            json!({"digest":operation_cache_identity("interactions.respond",&params,Some(ORG),Some(ACCOUNT)),"method":"interactions.respond","status":"pending"}),
        );
        let before = std::fs::read(&path).unwrap();
        let expected = descriptor["params"].clone();
        let expected_run = run.clone();
        let expected_request = request.clone();
        let server = tokio::spawn(async move {
            let (stream, head, body) = super::conformance::receive_http_with_body(&listener).await;
            assert!(head.starts_with(
                "POST /api/v1/runner-control/runner/v2/interaction-operations/get/ HTTP/1.1"
            ));
            let query: Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(query, expected);
            assert!(!String::from_utf8(body).unwrap().contains("private answer"));
            super::conformance::reply_http(stream,200,json!({"operation":"interaction.resolve","requestId":expected_request,"status":"completed","match":if exact {"exact_request_match"}else{"same_key_only"},"submissionFingerprint":expected["submissionFingerprint"],"submissionFingerprintVersion":"loomex.operation-submission/v1","result":{"requestId":expected_request,"executionId":expected_run,"requestStatus":"resolved","executionStatus":"running"}})).await;
            assert!(
                tokio::time::timeout(Duration::from_millis(50), listener.accept())
                    .await
                    .is_err()
            );
        });
        let outcome = daemon.dispatch("interactions.respond", params).await;
        if exact {
            let accepted = outcome.unwrap();
            assert_eq!(accepted["requestStatus"], "resolved");
            assert_eq!(accepted["executionId"], run);
            let record: Value = state::read_json(&path).unwrap();
            assert_eq!(record["executionId"], run);
            assert!(record["result"].is_object());
        } else {
            assert_eq!(
                outcome.unwrap_err().to_string(),
                "OPERATION_RECONCILIATION_REQUIRED"
            );
            assert_eq!(std::fs::read(path).unwrap(), before);
        }
        server.await.unwrap();
    }
}

#[test]
fn operation_cache_unknown_shapes_and_unproven_rejection_remain_blockers() {
    let digest = "a".repeat(64);
    assert!(!crate::operation_cache::known_record(
        &json!({"digest":digest,"method":"interactions.respond","status":"pending","unexpected":true})
    ));
    assert!(!crate::operation_cache::known_record(
        &json!({"digest":digest,"method":"builder.start","status":"rejected_before_execution","rejection":{"code":"UNAUTHORIZED","httpStatus":401}})
    ));
    assert!(!crate::operation_cache::known_record(
        &json!({"digest":digest,"method":"interactions.respond","status":"maybe_completed","result":{}})
    ));
}

#[tokio::test]
async fn operation_cache_startup_rejects_malformed_unknown_or_unsafe_required_fences() {
    for case in ["malformed", "unknown", "nonprivate", "symlink"] {
        let temp = tempfile::tempdir().unwrap();
        let slot = Uuid::new_v4().to_string();
        let relative = crate::operation_cache::retirement_relative(&slot).unwrap();
        let path = temp.path().join(relative);
        state::atomic_write(
            &path,
            if case == "malformed" {
                b"{"
            } else {
                b"{\"schema\":\"unknown-required-fence/v99\"}"
            },
        )
        .unwrap();
        if case == "nonprivate" {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        }
        if case == "symlink" {
            let target = temp.path().join("target.json");
            std::fs::rename(&path, &target).unwrap();
            std::os::unix::fs::symlink(target, &path).unwrap();
        }
        let api = Api::for_test_origin("http://127.0.0.1:9").unwrap();
        assert!(
            Daemon::new(
                temp.path().into(),
                api.clone(),
                Auth::test_enrolled(api, ORG, ACCOUNT)
            )
            .is_err(),
            "{case}"
        );
    }
}

#[test]
fn operation_cache_raw_reconciliation_advertises_only_implemented_adapters_with_authority() {
    let temp = tempfile::tempdir().unwrap();
    state::private_dir(temp.path()).unwrap();
    let runs = std::collections::BTreeSet::new();
    for method in ["workflows.create", "personas.create"] {
        let key = Uuid::new_v4().to_string();
        let record = crate::operation_cache::pending(
            &"a".repeat(64),
            method,
            crate::operation_cache::binding(
                method,
                &key,
                &"a".repeat(64),
                &json!({}),
                &json!({}),
                crate::operation_cache::BindingOrigin {
                    organization: Some(ORG),
                    account: Some(ACCOUNT),
                    installation: "installation",
                    control_reference: None,
                },
            ),
        );
        assert!(record["binding"]["receipt"].is_object());
        let path = seed(temp.path(), &key, record);
        let candidate = crate::operation_cache::classify(temp.path(), &path, &runs).unwrap();
        assert_eq!(candidate["reconciliationSupported"], false, "{method}");
        assert_eq!(candidate["safeReason"], "unsupported_family", "{method}");
        assert_eq!(candidate["retirementEligible"], true, "{method}");
    }
    for native in [true, false] {
        let method = if native {
            "builder.start"
        } else {
            "interactions.respond"
        };
        let key = Uuid::new_v4().to_string();
        let params =
            json!({"requestId":Uuid::new_v4(),"idempotencyKey":key,"answer":{"text":"private"}});
        let mut binding = crate::operation_cache::binding(
            method,
            &key,
            &"b".repeat(64),
            &json!({}),
            &params,
            crate::operation_cache::BindingOrigin {
                organization: Some(ORG),
                account: Some(ACCOUNT),
                installation: "installation",
                control_reference: None,
            },
        );
        if !native {
            let receipt = interaction_cache_receipt(method, &params).unwrap().unwrap();
            binding["backendSubmissionDigest"] = receipt["params"]["submissionFingerprint"].clone();
            binding["receipt"] = receipt;
        }
        let mut record = crate::operation_cache::pending(&"b".repeat(64), method, binding);
        if native {
            record["executionId"] = json!(Uuid::new_v4());
        }
        let path = seed(temp.path(), &key, record.clone());
        let candidate = crate::operation_cache::classify(temp.path(), &path, &runs).unwrap();
        assert_eq!(candidate["reconciliationSupported"], true, "{method}");
        assert_eq!(candidate["safeReason"], "canonical_pending", "{method}");
        if native {
            record.as_object_mut().unwrap().remove("executionId");
        } else {
            record["binding"]
                .as_object_mut()
                .unwrap()
                .remove("backendSubmissionDigest");
        }
        state::write_json(&path, &record).unwrap();
        let missing = crate::operation_cache::classify(temp.path(), &path, &runs).unwrap();
        assert_eq!(missing["reconciliationSupported"], false, "{method}");
        assert_eq!(missing["safeReason"], "missing_binding", "{method}");
    }
}

#[test]
fn operation_cache_startup_honors_retained_reader_requirement_when_evidence_is_missing() {
    for minimum_reader in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let mut owner = serde_json::to_value(crate::lifecycle::Operation::new(
            crate::lifecycle::OperationKind::Install,
            "completed",
            None,
        ))
        .unwrap();
        if minimum_reader {
            owner["logicalSchema"] = owner["schema"].clone();
            owner["schema"] = json!("app.loomex.runner.lifecycle-operation/v12");
            owner["minimumReaderCapability"] = json!("operation-cache.retirement-fence/v1");
        }
        state::write_json(&temp.path().join("lifecycle-operation.json"), &owner).unwrap();
        let api = Api::for_test_origin("http://127.0.0.1:9").unwrap();
        let outcome = Daemon::new(
            temp.path().into(),
            api.clone(),
            Auth::test_enrolled(api, ORG, ACCOUNT),
        );
        if minimum_reader {
            assert_eq!(
                outcome.err().unwrap().to_string(),
                "OPERATION_RETIREMENT_EVIDENCE_REQUIRED"
            );
            assert!(!temp.path().join("presentation.sqlite3").exists());
        } else {
            assert!(outcome.is_ok());
        }
    }
}
