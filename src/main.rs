use anyhow::{Context, Result, bail, ensure};
use loomex_runner::{control, lifecycle, state};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};

fn main() {
    if let Err(error) = entry() {
        let (code, retryable, _) = control::public_error(&error);
        eprintln!("{}", state::safe_error(&code, retryable));
        std::process::exit(1)
    }
}
fn entry() -> Result<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let result = runtime.block_on(run());
    // A started native call cannot be canceled. Bound runtime disposal only;
    // its worker retains singleton ownership until completion or process exit.
    runtime.shutdown_timeout(std::time::Duration::from_secs(2));
    result
}
async fn run() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let command = args.next().unwrap_or_else(|| "status".into());
    if command == "--version" || command == "version" {
        println!("loomex {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    if command == "lifecycle" {
        return run_lifecycle(args.collect()).await;
    }
    let dir = state::state_dir()?;
    if command == "diagnostics" {
        if args.next().is_some() {
            bail!("INVALID_REQUEST")
        }
        println!("{}", serde_json::to_string(&diagnostics(&dir).await)?);
        return Ok(());
    }
    if command == "logout" {
        match args.next().as_deref() {
            Some("--offline") if args.next().is_none() => {
                println!("{}", control::offline_logout(&dir).await?);
                return Ok(());
            }
            None => {}
            _ => bail!("INVALID_REQUEST"),
        }
    }
    let (method, params) = match command.as_str() {
        "status" => ("status.get".into(), json!({})),
        "drain" => (
            "daemon.drain".into(),
            json!({"idempotencyKey":uuid::Uuid::new_v4()}),
        ),
        "logout" => (
            "auth.logout".into(),
            json!({"idempotencyKey":uuid::Uuid::new_v4()}),
        ),
        "login" => (
            "auth.login".into(),
            json!({"idempotencyKey":uuid::Uuid::new_v4()}),
        ),
        "rpc" => {
            let method = args
                .next()
                .ok_or_else(|| anyhow::anyhow!("method required"))?;
            let params = serde_json::from_str(&args.next().unwrap_or_else(|| "{}".into()))?;
            (method, params)
        }
        "--help" | "help" => {
            println!(
                "loomex status | diagnostics | login | logout [--offline] | drain | lifecycle {{status|resume|rollback|repair|prune}} [--json] | rpc METHOD JSON | --version"
            );
            return Ok(());
        }
        _ => bail!("unknown command"),
    };
    let response = control::client(&dir, &method, params).await?;
    let display = if command == "status" && response.get("error").is_none() {
        compact_status(&response["result"])
    } else {
        response.clone()
    };
    println!(
        "{}",
        serde_json::to_string(if command == "rpc" || response.get("error").is_some() {
            &response
        } else {
            &display
        })?
    );
    if response.get("error").is_some() {
        std::process::exit(1)
    }
    if command == "login" && response["result"]["status"] == "pending" {
        // The daemon owns callback handling. The CLI observes its local state.
        let connection = control::client(&dir, "connection.get", json!({})).await?;
        let flow_id = connection["result"]["login"]["flowId"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("LOGIN_FLOW_UNAVAILABLE"))?
            .to_owned();
        if let Some(uri) = response["result"]["authorizationUrl"].as_str() {
            #[cfg(target_os = "macos")]
            {
                let _ = tokio::process::Command::new("/usr/bin/open")
                    .arg(uri)
                    .status()
                    .await;
            }
            #[cfg(not(target_os = "macos"))]
            {
                let _ = uri;
            }
        }
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            let current = control::client(&dir, "connection.get", json!({})).await?;
            if current.get("error").is_some() {
                println!("{current}");
                std::process::exit(1)
            }
            if current["result"]["state"] == "authenticated" {
                println!("{}", current["result"]);
                break;
            }
            if current["result"]["state"] == "verification_expired"
                || current["result"]["state"] == "signed_out"
                || current["result"]["login"]["flowId"] != flow_id
            {
                bail!("LOGIN_EXPIRED_OR_CANCELED")
            }
            if current["result"]["state"] == "recovery_pending"
                || current["result"]["state"] == "credential_store_unavailable"
            {
                bail!("LOGIN_RECOVERY_REQUIRED")
            }
        }
    }
    Ok(())
}

/// Read-only local diagnostics.  It does not start a daemon, access provider
/// credential stores, or print executable paths/checksums.  It is deliberately
/// useful when the daemon is unavailable, so runner-connect errors become data
/// instead of terminating the command.
async fn diagnostics(dir: &Path) -> Value {
    let daemon;
    let mut fingerprint = fingerprint_diagnostics(&Value::Null);
    let installation = json!({"available":false,"reason":"INSTALLATION_ID_UNAVAILABLE"});
    let status = control::client(
        dir,
        "status.get",
        json!({"includeFingerprintDiagnostics":true}),
    )
    .await;
    let status = match status {
        Err(error) if control::public_error(&error).0 == "COMPATIBILITY_ERROR" => {
            control::client(dir, "status.get", json!({})).await
        }
        result => result,
    };
    match status {
        Ok(response) if response.get("error").is_none() => {
            let status = &response["result"];
            fingerprint = fingerprint_diagnostics(&status["fingerprint"]);
            daemon = json!({
                "connected":true,
                "reason":"available",
                "version":status["version"],
                "protocol":status["protocol"],
            });
        }
        Ok(response) => {
            daemon = json!({"connected":false,"reason":response["error"]["code"].as_str().unwrap_or("RUNNER_UNAVAILABLE")});
        }
        Err(error) => {
            let (code, _, _) = control::public_error(&error);
            daemon = json!({"connected":false,"reason":code});
        }
    }
    json!({
        "schemaVersion":"loomex.runner.diagnostics/v1",
        "daemon":daemon,
        "installation":installation,
        "providers":control::provider_diagnostics(),
        "build":build_diagnostics(),
        "fingerprint":fingerprint,
    })
}

fn build_diagnostics() -> Value {
    json!({
        "profile":env!("LOOMEX_BUILD_PROFILE"),
        "optimizationLevel":env!("LOOMEX_BUILD_OPT_LEVEL"),
        "debugAssertions":cfg!(debug_assertions),
        "classification":if cfg!(debug_assertions) { "development" } else { "production" },
    })
}

fn fingerprint_diagnostics(value: &Value) -> Value {
    const COUNTERS: &[&str] = &[
        "workerLimit",
        "activeWorkers",
        "peakWorkers",
        "started",
        "shared",
        "bytesHashed",
        "queueMicros",
        "hashMicros",
        "unavailable",
        "changed",
        "canceled",
        "inFlight",
        "queued",
    ];
    if COUNTERS.iter().any(|key| value[key].as_u64().is_none()) || value["completedCache"] != false
    {
        return json!({"available":false,"reason":"FINGERPRINT_DIAGNOSTICS_UNAVAILABLE"});
    }
    let Some(observations) = value["stageObservations"]
        .as_array()
        .filter(|records| records.len() <= 128)
    else {
        return json!({"available":false,"reason":"FINGERPRINT_DIAGNOSTICS_UNAVAILABLE"});
    };
    let catalog: Value = serde_json::from_str(include_str!("../contracts/method-catalog.json"))
        .expect("embedded catalog");
    if observations
        .iter()
        .any(|record| !safe_stage_observation(record, &catalog))
    {
        return json!({"available":false,"reason":"FINGERPRINT_DIAGNOSTICS_UNAVAILABLE"});
    }
    let mut statistics = serde_json::Map::new();
    for key in COUNTERS {
        statistics.insert((*key).into(), value[key].clone());
    }
    statistics.insert("completedCache".into(), json!(false));
    statistics.insert("stageObservations".into(), json!(observations));
    json!({"available":true,"statistics":statistics})
}

fn safe_stage_observation(value: &Value, catalog: &Value) -> bool {
    let Some(object) = value.as_object().filter(|object| object.len() == 7) else {
        return false;
    };
    let Some(operation) = object.get("operation").and_then(Value::as_str) else {
        return false;
    };
    (operation == "provider.fingerprint"
        || catalog["methods"]
            .as_array()
            .is_some_and(|methods| methods.iter().any(|method| method["name"] == operation)))
        && matches!(
            value["stage"].as_str(),
            Some(
                "credential"
                    | "queue"
                    | "hash"
                    | "backend"
                    | "review_enrichment"
                    | "presentation"
                    | "total"
            )
        )
        && matches!(
            value["provider"].as_str(),
            Some("codex" | "claude" | "gemini" | "antigravity" | "none")
        )
        && matches!(
            value["outcome"].as_str(),
            Some("completed" | "changed" | "unavailable" | "canceled" | "unknown")
        )
        && value["durationMicros"].as_u64().is_some()
        && value["byteCount"].as_u64().is_some()
        && value["correlationReference"]
            .as_str()
            .is_some_and(|reference| uuid::Uuid::parse_str(reference).is_ok())
}

/// Keep the ordinary status command suitable for scripts and quick checks.
/// Detailed runner observations remain available through `rpc status.get` and
/// the separate diagnostics command.
fn compact_status(status: &Value) -> Value {
    json!({
        "version":status["version"],
        "protocol":status["protocol"],
        "activeJobs":status["activeJobs"],
        "draining":status["draining"],
        "updateDeferred":status["updateDeferred"],
    })
}

async fn run_lifecycle(arguments: Vec<String>) -> Result<()> {
    let mut args = arguments.into_iter();
    let action = args.next().unwrap_or_else(|| "status".into());
    let mut json_output = false;
    let mut install_base = None;
    let mut state_dir = None;
    let mut launch_agents_dir = None;
    let mut version = None;
    let mut remove_versions = Vec::new();
    let mut retain_versions = Vec::new();
    let mut expected_operation = None;
    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--json" => json_output = true,
            "--install-base" => {
                install_base = Some(PathBuf::from(
                    args.next().context("--install-base requires a path")?,
                ))
            }
            "--state-dir" => {
                state_dir = Some(PathBuf::from(
                    args.next().context("--state-dir requires a path")?,
                ))
            }
            "--launch-agents-dir" => {
                launch_agents_dir = Some(PathBuf::from(
                    args.next().context("--launch-agents-dir requires a path")?,
                ))
            }
            "--to" => version = Some(args.next().context("--to requires a version")?),
            "--remove" => remove_versions.push(args.next().context("--remove requires a version")?),
            "--retain" => retain_versions.push(args.next().context("--retain requires a version")?),
            "--expected-operation" => {
                ensure!(expected_operation.is_none(), "INVALID_REQUEST");
                expected_operation = Some(
                    uuid::Uuid::parse_str(
                        &args.next().context("--expected-operation requires UUID")?,
                    )
                    .context("INVALID_REQUEST")?,
                );
            }
            _ => bail!("invalid lifecycle argument"),
        }
    }
    // Validate the command before filesystem discovery so malformed input is
    // not misreported as an installation or service failure.
    if !matches!(
        action.as_str(),
        "status" | "resume" | "rollback" | "repair" | "prune" | "--help" | "help"
    ) {
        bail!("INVALID_REQUEST");
    }
    if (action == "rollback" && version.is_none())
        || (action != "rollback" && expected_operation.is_some())
        || (action != "prune" && !remove_versions.is_empty())
        || (action != "prune" && !retain_versions.is_empty())
        || (action == "prune"
            && (remove_versions.is_empty() || retain_versions.is_empty() || version.is_some()))
    {
        bail!("INVALID_REQUEST");
    }
    let mut paths = lifecycle::Paths::from_environment()?;
    if let Some(path) = install_base {
        paths.install_base = path;
    }
    if let Some(path) = state_dir {
        paths.state_dir = path;
    }
    if let Some(path) = launch_agents_dir {
        paths.launch_agents_dir = path;
    }
    paths.validate()?;
    let value = match action.as_str() {
        "status" => lifecycle::status(&paths)?,
        "resume" => lifecycle::resume(&paths).await?,
        "rollback" => {
            lifecycle::rollback_with_expected(
                &paths,
                &version.context("lifecycle rollback requires --to VERSION")?,
                expected_operation,
            )
            .await?
        }
        "repair" => lifecycle::repair(&paths).await?,
        "prune" => lifecycle::prune(&paths, &remove_versions, &retain_versions).await?,
        "--help" | "help" => {
            println!(
                "loomex lifecycle status [--json] [--install-base DIR --state-dir DIR --launch-agents-dir DIR]\nloomex lifecycle resume|repair [--json] [directories]\nloomex lifecycle rollback --to VERSION [--expected-operation UUID] [--json] [directories]\nloomex lifecycle prune --remove VERSION [--remove VERSION ...] --retain ROLLBACK_VERSION [--json] [directories]"
            );
            return Ok(());
        }
        _ => bail!("unknown lifecycle command"),
    };
    if json_output || action != "status" {
        println!("{}", serde_json::to_string(&value)?);
    } else {
        println!("{}", lifecycle::readable(&value));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn expected_operation_flag_is_typed_and_rollback_only() {
        for args in [
            vec![
                "resume",
                "--expected-operation",
                "00000000-0000-0000-0000-000000000001",
            ],
            vec![
                "rollback",
                "--to",
                "0.3.64",
                "--expected-operation",
                "invalid",
            ],
            vec![
                "rollback",
                "--to",
                "0.3.64",
                "--expected-operation",
                "00000000-0000-0000-0000-000000000001",
                "--expected-operation",
                "00000000-0000-0000-0000-000000000001",
            ],
        ] {
            assert!(
                run_lifecycle(args.into_iter().map(str::to_owned).collect())
                    .await
                    .is_err()
            );
        }
    }

    #[test]
    fn status_output_excludes_extended_diagnostics() {
        let value = compact_status(&json!({
            "version":"0.3.22",
            "protocol":"loomex.local-control/v2",
            "activeJobs":0,
            "draining":false,
            "updateDeferred":false,
            "details":{"monitoring":{"runObservationAvailable":true}},
        }));
        assert_eq!(value["version"], "0.3.22");
        assert!(value.get("details").is_none());
    }

    #[tokio::test]
    async fn diagnostics_reports_an_unavailable_daemon_without_sensitive_provider_fields() {
        let temp = tempfile::tempdir().unwrap();
        let value = diagnostics(temp.path()).await;
        assert_eq!(value["schemaVersion"], "loomex.runner.diagnostics/v1");
        assert_eq!(value["daemon"]["connected"], false);
        assert_eq!(value["daemon"]["reason"], "RUNNER_UNAVAILABLE");
        assert_eq!(value["installation"]["available"], false);
        assert_eq!(value["build"], build_diagnostics());
        assert_eq!(value["build"]["debugAssertions"], cfg!(debug_assertions));
        assert_eq!(value["build"]["profile"], env!("LOOMEX_BUILD_PROFILE"));
        assert_eq!(value["fingerprint"]["available"], false);
        assert_eq!(std::fs::read_dir(temp.path()).unwrap().count(), 0);
        for provider in value["providers"].as_object().unwrap().values() {
            assert!(provider["available"].is_boolean());
            assert!(provider["reason"].is_string());
            assert_eq!(provider["modelAccess"], "unknown");
            assert!(provider.get("path").is_none());
            assert!(provider.get("checksumSha256").is_none());
        }
    }

    #[test]
    fn fingerprint_projection_is_allowlisted_and_legacy_compatible() {
        assert_eq!(fingerprint_diagnostics(&Value::Null)["available"], false);
        let mut metrics = json!({"workerLimit":2,"activeWorkers":0,"peakWorkers":1,
            "started":1,"shared":0,"bytesHashed":1024,"queueMicros":12,
            "hashMicros":34,"unavailable":0,"changed":0,"canceled":0,
            "completedCache":false,"inFlight":0,"queued":0,"stageObservations":[],"private":"excluded"});
        let projection = fingerprint_diagnostics(&metrics);
        assert_eq!(projection["available"], true);
        assert!(projection["statistics"].get("private").is_none());
        metrics["bytesHashed"] = json!("invalid");
        assert_eq!(fingerprint_diagnostics(&metrics)["available"], false);
    }

    #[test]
    fn fingerprint_stage_projection_rejects_private_and_oversized_records() {
        let catalog: Value =
            serde_json::from_str(include_str!("../contracts/method-catalog.json")).unwrap();
        let mut observation = json!({"operation":"provider.fingerprint","stage":"hash",
            "durationMicros":123,"byteCount":500,"provider":"codex",
            "correlationReference":uuid::Uuid::new_v4().to_string(),"outcome":"completed"});
        assert!(safe_stage_observation(&observation, &catalog));
        observation["operation"] = json!("private argument");
        assert!(!safe_stage_observation(&observation, &catalog));
        observation["operation"] = json!("provider.fingerprint");
        observation["credential"] = json!("excluded");
        assert!(!safe_stage_observation(&observation, &catalog));
        let metrics = json!({"workerLimit":2,"activeWorkers":0,"peakWorkers":0,
            "started":0,"shared":0,"bytesHashed":0,"queueMicros":0,"hashMicros":0,
            "unavailable":0,"changed":0,"canceled":0,"inFlight":0,"queued":0,
            "completedCache":false,"stageObservations":vec![observation;129]});
        assert_eq!(fingerprint_diagnostics(&metrics)["available"], false);
    }

    #[tokio::test]
    async fn diagnostics_negotiates_opt_in_and_legacy_fallback_without_auth() {
        use std::os::unix::fs::PermissionsExt;
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        for legacy in [false, true] {
            let temp = tempfile::tempdir().unwrap();
            let socket = temp.path().join("control.sock");
            let listener = tokio::net::UnixListener::bind(&socket).unwrap();
            std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
            let server = tokio::spawn(async move {
                for attempt in 0..=usize::from(legacy) {
                    let (stream, _) = listener.accept().await.unwrap();
                    let (reader, mut writer) = stream.into_split();
                    let mut reader = BufReader::new(reader);
                    let mut line = String::new();
                    reader.read_line(&mut line).await.unwrap();
                    let request: Value = serde_json::from_str(&line).unwrap();
                    assert_eq!(request["method"], "protocol.negotiate");
                    let capabilities = &request["params"]["requiredCapabilities"];
                    assert_eq!(
                        capabilities
                            .as_array()
                            .unwrap()
                            .contains(&json!("diagnostics.fingerprint/v1")),
                        attempt == 0
                    );
                    let response = if legacy && attempt == 0 {
                        json!({"protocol":control::PROTOCOL,"id":request["id"],"error":{"code":"COMPATIBILITY_ERROR","retryable":false}})
                    } else {
                        json!({"protocol":control::PROTOCOL,"id":request["id"],"result":{"selectedProtocol":control::PROTOCOL,"maxFrameBytes":1048576,"serverVersion":"0.4.0","capabilities":capabilities}})
                    };
                    writer
                        .write_all(format!("{response}\n").as_bytes())
                        .await
                        .unwrap();
                    if legacy && attempt == 0 {
                        continue;
                    }
                    line.clear();
                    reader.read_line(&mut line).await.unwrap();
                    let request: Value = serde_json::from_str(&line).unwrap();
                    assert_eq!(request["method"], "status.get");
                    assert_eq!(
                        request["params"],
                        if legacy {
                            json!({})
                        } else {
                            json!({"includeFingerprintDiagnostics":true})
                        }
                    );
                    let response = json!({"protocol":control::PROTOCOL,"id":request["id"],"result":{"version":"0.4.0","protocol":control::PROTOCOL}});
                    writer
                        .write_all(format!("{response}\n").as_bytes())
                        .await
                        .unwrap();
                    line.clear();
                    assert_eq!(reader.read_line(&mut line).await.unwrap(), 0);
                }
            });
            let result = diagnostics(temp.path()).await;
            assert_eq!(result["daemon"]["connected"], true);
            assert_eq!(
                result["installation"]["reason"],
                "INSTALLATION_ID_UNAVAILABLE"
            );
            assert_eq!(result["fingerprint"]["available"], false);
            server.await.unwrap();
            assert_eq!(std::fs::read_dir(temp.path()).unwrap().count(), 1);
        }
    }
}
