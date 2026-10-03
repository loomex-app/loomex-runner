use serde_json::Value;
use std::process::Command;

#[test]
fn invalid_commands_are_classified_before_lifecycle_path_discovery() {
    for arguments in [
        vec!["unknown-command"],
        vec!["lifecycle", "unsupported"],
        vec!["lifecycle", "rollback"],
    ] {
        let lifecycle = arguments.first() == Some(&"lifecycle");
        let output = Command::new(env!("CARGO_BIN_EXE_loomex"))
            .args(arguments)
            .env("LOOMEX_STATE_DIR", "/")
            .output()
            .unwrap();
        assert!(!output.status.success());
        let error: Value = serde_json::from_slice(&output.stderr).unwrap();
        assert_eq!(
            error["code"],
            if lifecycle {
                "INVALID_ARGUMENT"
            } else {
                "INVALID_REQUEST"
            }
        );
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

#[test]
fn lifecycle_option_matrix_rejects_mistakes_without_creating_files() {
    let directory = tempfile::tempdir().unwrap();
    for args in [
        vec!["status", "--to", "1.2.3"],
        vec!["resume", "--to", "1.2.3"],
        vec!["repair", "--remove", "1.2.3"],
        vec!["help", "--to", "1.2.3"],
        vec!["prune", "--to", "1.2.3"],
        vec!["rollback", "--to"],
        vec!["rollback", "--to", "--json"],
        vec!["rollback", "--to", "not-a-version"],
        vec!["rollback", "--to", "1.2.3", "--to", "1.2.4"],
        vec!["status", "--json", "--json"],
        vec!["status", "--install-base"],
        vec!["status", "--state-dir", "/", "--state-dir", "/"],
        vec![
            "prune", "--remove", "1.2.3", "--remove", "1.2.3", "--retain", "1.2.4",
        ],
        vec![
            "rollback",
            "--to",
            "1.2.3",
            "--expected-operation",
            "invalid",
        ],
        vec!["repair", "--rollback-preflight"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_loomex"))
            .arg("lifecycle")
            .args(&args)
            .env("HOME", directory.path())
            .env("LOOMEX_STATE_DIR", directory.path().join("state"))
            .env("LOOMEX_INSTALL_BASE", directory.path().join("install"))
            .env("LOOMEX_LAUNCH_AGENTS_DIR", directory.path().join("agents"))
            .output()
            .unwrap();
        assert!(!output.status.success(), "{args:?}");
        assert!(output.stdout.is_empty());
        let error: Value = serde_json::from_slice(&output.stderr).unwrap();
        assert_eq!(error["code"], "INVALID_ARGUMENT", "{args:?}");
        assert_eq!(error["recovery"], "correct_input");
        assert_eq!(error["outcome"], "rejected");
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
    }
}

#[test]
fn lifecycle_help_ignores_invalid_environment_without_discovery() {
    let output = Command::new(env!("CARGO_BIN_EXE_loomex"))
        .args(["lifecycle", "help"])
        .env("LOOMEX_STATE_DIR", "/")
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(
        String::from_utf8(output.stdout)
            .unwrap()
            .contains("--rollback-preflight")
    );
}

#[test]
fn unowned_versions_return_stable_input_errors_without_service_dispatch() {
    use std::os::unix::fs::symlink;
    let temporary = tempfile::tempdir().unwrap();
    let root = std::fs::canonicalize(temporary.path()).unwrap();
    let install = root.join("install");
    let state = root.join("state");
    let agents = root.join("agents");
    let current = install.join("versions/1.2.3");
    let retained = install.join("versions/1.2.4");
    for path in [&current, &retained, &state, &agents] {
        std::fs::create_dir_all(path).unwrap();
    }
    symlink(&current, install.join("current")).unwrap();
    let inventory = serde_json::to_vec(&serde_json::json!({
        "schema":"app.loomex.runner.owned-versions/v1", "paths":[current,retained]
    }))
    .unwrap();
    std::fs::write(state.join("owned-versions.json"), &inventory).unwrap();
    for args in [
        vec!["rollback", "--to", "9.9.9"],
        vec!["prune", "--remove", "9.9.9", "--retain", "1.2.4"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_loomex"))
            .arg("lifecycle")
            .args(args)
            .env("HOME", &root)
            .env("LOOMEX_INSTALL_BASE", &install)
            .env("LOOMEX_STATE_DIR", &state)
            .env("LOOMEX_LAUNCH_AGENTS_DIR", &agents)
            .output()
            .unwrap();
        assert!(!output.status.success());
        let error: Value = serde_json::from_slice(&output.stderr).unwrap();
        assert_eq!(error["code"], "VERSION_NOT_OWNED");
        assert_eq!(error["recovery"], "correct_input");
        assert_eq!(error["outcome"], "rejected");
        assert_eq!(
            std::fs::read(state.join("owned-versions.json")).unwrap(),
            inventory
        );
        assert_eq!(
            std::fs::read_link(install.join("current")).unwrap(),
            current
        );
        assert!(!state.join("lifecycle-operation.json").exists());
        assert!(!state.join("drain.json").exists());
        assert_eq!(std::fs::read_dir(&agents).unwrap().count(), 0);
    }
}
