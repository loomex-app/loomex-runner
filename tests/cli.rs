use serde_json::Value;
use std::process::Command;

#[test]
fn invalid_commands_are_classified_before_lifecycle_path_discovery() {
    for arguments in [
        vec!["unknown-command"],
        vec!["lifecycle", "unsupported"],
        vec!["lifecycle", "rollback"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_loomex"))
            .args(arguments)
            .env("LOOMEX_STATE_DIR", "/")
            .output()
            .unwrap();
        assert!(!output.status.success());
        let error: Value = serde_json::from_slice(&output.stderr).unwrap();
        assert_eq!(error["code"], "INVALID_REQUEST");
        assert_eq!(error["recovery"], "correct_input");
        assert_eq!(error["outcome"], "rejected");
        assert!(error["correlationId"].is_string());
    }
}

#[test]
fn unavailable_socket_reports_a_pre_dispatch_failure() {
    let directory = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_loomex"))
        .arg("status")
        .env("LOOMEX_STATE_DIR", directory.path())
        .output()
        .unwrap();
    assert!(!output.status.success());
    let error: Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(error["code"], "RUNNER_UNAVAILABLE");
    assert_eq!(error["outcome"], "not_dispatched");
}
