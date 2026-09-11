use anyhow::{Result, bail};
use loomex_runner::{control, state};
use serde_json::json;

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
                "loomex status | login | logout [--offline] | drain | rpc METHOD JSON | --version"
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
