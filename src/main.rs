use anyhow::{Context, Result, bail};
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
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(run())
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
                "loomex status | diagnostics | login | logout [--offline] | drain | lifecycle {{status|resume|rollback|repair}} [--json] | rpc METHOD JSON | --version"
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
    let mut installation = json!({"available":false,"reason":"RUNNER_UNAVAILABLE"});
    match control::client(dir, "status.get", json!({})).await {
        Ok(response) if response.get("error").is_none() => {
            let status = &response["result"];
            daemon = json!({
                "connected":true,
                "reason":"available",
                "version":status["version"],
                "protocol":status["protocol"],
            });
            match control::client(dir, "auth.status", json!({})).await {
                Ok(response) if response.get("error").is_none() => {
                    let result = &response["result"];
                    if let Some(id) = result["installationId"].as_str() {
                        installation = json!({"available":true,"reason":"available","id":id});
                    } else {
                        installation =
                            json!({"available":false,"reason":"INSTALLATION_ID_UNAVAILABLE"});
                    }
                }
                Ok(response) => {
                    installation = json!({"available":false,"reason":response["error"]["code"].as_str().unwrap_or("RUNNER_UNAVAILABLE")});
                }
                Err(error) => {
                    let (code, _, _) = control::public_error(&error);
                    installation = json!({"available":false,"reason":code});
                }
            }
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
    })
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
            _ => bail!("invalid lifecycle argument"),
        }
    }
    // Validate the command before filesystem discovery so malformed input is
    // not misreported as an installation or service failure.
    if !matches!(
        action.as_str(),
        "status" | "resume" | "rollback" | "repair" | "--help" | "help"
    ) {
        bail!("INVALID_REQUEST");
    }
    if action == "rollback" && version.is_none() {
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
            lifecycle::rollback(
                &paths,
                &version.context("lifecycle rollback requires --to VERSION")?,
            )
            .await?
        }
        "repair" => lifecycle::repair(&paths).await?,
        "--help" | "help" => {
            println!(
                "loomex lifecycle status [--json] [--install-base DIR --state-dir DIR --launch-agents-dir DIR]\nloomex lifecycle resume|repair [--json] [directories]\nloomex lifecycle rollback --to VERSION [--json] [directories]"
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
        for provider in value["providers"].as_object().unwrap().values() {
            assert!(provider["available"].is_boolean());
            assert!(provider["reason"].is_string());
            assert_eq!(provider["modelAccess"], "unknown");
            assert!(provider.get("path").is_none());
            assert!(provider.get("checksumSha256").is_none());
        }
    }
}
