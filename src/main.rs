use anyhow::{Context, Result, bail};
use loomex_runner::{control, lifecycle, state};
use serde_json::json;
use std::path::PathBuf;

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
                "loomex status | login | logout [--offline] | drain | lifecycle {{status|resume|rollback|repair}} [--json] | rpc METHOD JSON | --version"
            );
            return Ok(());
        }
        _ => bail!("unknown command"),
    };
    let response = control::client(&dir, &method, params).await?;
    println!(
        "{}",
        serde_json::to_string(if command == "rpc" || response.get("error").is_some() {
            &response
        } else {
            &response["result"]
        })?
    );
    if response.get("error").is_some() {
        std::process::exit(1)
    }
    if command == "login" && response["result"]["status"] == "pending" {
        // Bind each poll to the exact public flow the runner persisted. This
        // attaches a restarted CLI to an existing login without permitting a
        // stale poll to act on a later flow.
        let connection = control::client(&dir, "connection.get", json!({})).await?;
        let flow_id = connection["result"]["login"]["flowId"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("LOGIN_FLOW_UNAVAILABLE"))?
            .to_owned();
        if let Some(uri) = response["result"]["verificationUri"].as_str() {
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
            tokio::time::sleep(std::time::Duration::from_secs(
                response["result"]["intervalSeconds"]
                    .as_u64()
                    .unwrap_or(5)
                    .max(1),
            ))
            .await;
            let poll = control::client(
                &dir,
                "auth.poll",
                json!({"idempotencyKey":uuid::Uuid::new_v4(),"flowId":flow_id}),
            )
            .await?;
            if poll.get("error").is_some() {
                println!("{}", poll);
                std::process::exit(1)
            }
            if poll["result"]["status"] == "authenticated" {
                println!("{}", poll["result"]);
                break;
            }
        }
    }
    Ok(())
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
