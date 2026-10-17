//! Emit real delivery projections for the schema regression without daemon or host access.
use loomex_runner::presentation::PresentationStore;
use serde_json::json;
use uuid::Uuid;

#[test]
fn delivery_contract_fixture() {
    let dir = tempfile::tempdir().unwrap();
    let store = PresentationStore::open(dir.path()).unwrap();
    let run = Uuid::new_v4().to_string();
    let identity = format!("follow:{run}:run_started");
    let continuation = json!({
        "kind":"follow", "schemaVersion":"loomex.follow-session.continuation/v1",
        "runId":run, "receipt":"abcdefghijklmnop", "trigger":"run_started",
        "requestId":null, "requestStatus":null
    });
    store
        .register_delivery("org-a", "user-a", &identity, &continuation)
        .unwrap();
    let get = || {
        store
            .dispatch(
                "org-a",
                "user-a",
                "presentation.delivery.get",
                &json!({"identity":identity}),
            )
            .unwrap()
    };
    let ready = get();
    let attempt = Uuid::new_v4();
    let sending = store.dispatch("org-a", "user-a", "presentation.delivery.begin", &json!({
        "identity":identity, "expectedRevision":0, "attemptId":attempt, "idempotencyKey":Uuid::new_v4()
    })).unwrap();
    let unknown = store
        .dispatch(
            "org-a",
            "user-a",
            "presentation.delivery.settle",
            &json!({
                "identity":identity, "expectedRevision":1, "attemptId":attempt,
                "status":"unknown", "idempotencyKey":Uuid::new_v4()
            }),
        )
        .unwrap();
    let mut request = store.maintenance_candidates().unwrap().remove(0);
    request["idempotencyKey"] = json!(Uuid::new_v4());
    let observation = json!({
        "snapshot":{"execution":{"id":run,"status":"completed"},"hasMoreEvents":false},
        "terminalResult":{"execution":{"id":run,"status":"completed"},"hasMoreEvents":false}
    });
    store.maintenance_reconcile(&request, &observation).unwrap();
    store.maintenance_retire(&request).unwrap();
    let retired = get();
    assert_eq!(ready["resolution"], json!({"state":"unresolved"}));
    assert_eq!(sending["continuationEligible"], true);
    assert_eq!(unknown["continuationEligible"], true);
    assert_eq!(retired["continuationEligible"], false);
    assert_eq!(
        retired["resolution"]["candidate"]["backendObservation"]["terminal"],
        true
    );
    assert_eq!(retired["status"], "unknown");
    if let Some(path) = std::env::var_os("LOOMEX_DELIVERY_CONTRACT_FIXTURE") {
        std::fs::write(
            path,
            serde_json::to_vec(&json!([ready, sending, unknown, retired])).unwrap(),
        )
        .unwrap();
    }
}
