use anyhow::Result;
use loomex_runner::{
    api::Api,
    auth::Auth,
    control::{self, Daemon},
    executor, state,
};
use std::sync::Arc;
fn main() {
    if let Err(error) = entry() {
        eprintln!("{}", control::public_error_record(&error));
        std::process::exit(1)
    }
}
fn entry() -> Result<()> {
    if std::env::args().nth(1).as_deref() == Some("--maintenance-uninstall-work") {
        let context = std::env::args_os()
            .nth(2)
            .ok_or_else(|| anyhow::anyhow!("INVALID_REQUEST"))?;
        if std::env::args_os().nth(3).is_some() {
            anyhow::bail!("INVALID_REQUEST")
        }
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;
        let result = runtime.block_on(loomex_runner::maintenance::run_uninstall_work(
            std::path::Path::new(&context),
        ));
        drop(runtime);
        println!("{}", result?);
        return Ok(());
    }
    if std::env::args()
        .nth(1)
        .is_some_and(|a| a == "--maintenance-offline-logout")
    {
        let dir = std::env::args_os()
            .nth(2)
            .ok_or_else(|| anyhow::anyhow!("INVALID_REQUEST"))?;
        if std::env::args_os().nth(3).is_some() {
            anyhow::bail!("INVALID_REQUEST")
        }
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;
        let result = runtime.block_on(loomex_runner::maintenance::run_offline_logout(
            std::path::Path::new(&dir),
        ));
        // Maintenance may have a native worker after the observer's deadline.
        // Keep this process and its ownership guards until that IO completes.
        drop(runtime);
        println!("{}", result?);
        return Ok(());
    }
    if let Some(mode) = std::env::args().nth(1).filter(|value| {
        matches!(
            value.as_str(),
            "--maintenance-logout" | "--maintenance-identity"
        )
    }) {
        let context = std::env::args_os()
            .nth(2)
            .ok_or_else(|| anyhow::anyhow!("INVALID_REQUEST"))?;
        if std::env::args_os().nth(3).is_some() {
            anyhow::bail!("INVALID_REQUEST")
        }
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;
        let result = runtime.block_on(loomex_runner::maintenance::run(
            std::path::Path::new(&context),
            mode == "--maintenance-identity",
        ));
        drop(runtime);
        println!("{}", result?);
        return Ok(());
    }
    if let Some(argument) = std::env::args().nth(1) {
        if matches!(
            argument.as_str(),
            "--credential-store-probe" | "--credential-store-authorize"
        ) {
            if std::env::args().nth(2).is_some()
                || (argument == "--credential-store-authorize" && !cfg!(debug_assertions))
            {
                anyhow::bail!("STORE_UNAVAILABLE")
            }
            #[cfg(target_os = "macos")]
            let code = loomex_runner::auth::credential_store_probe(
                argument == "--credential-store-authorize",
            );
            #[cfg(not(target_os = "macos"))]
            let code = "UNAVAILABLE";
            println!("{code}");
            if code != "AUTHORIZED" {
                std::process::exit(1)
            }
            return Ok(());
        }
    }
    if executor::maybe_run_supervisor()? {
        return Ok(());
    }
    if std::env::args()
        .nth(1)
        .is_some_and(|a| a == "--internal-persona-memory-mcp")
    {
        let path = std::env::args()
            .nth(2)
            .ok_or_else(|| anyhow::anyhow!("PERSONA_MEMORY_UNAVAILABLE"))?;
        if std::env::args().nth(3).is_some() {
            anyhow::bail!("PERSONA_MEMORY_UNAVAILABLE")
        }
        return tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(loomex_runner::jobs::persona_memory::serve_mcp(
                std::path::Path::new(&path),
            ));
    }
    if std::env::args()
        .nth(1)
        .is_some_and(|a| a == "--internal-public-status-mcp")
    {
        let socket = std::env::args()
            .nth(2)
            .ok_or_else(|| anyhow::anyhow!("PUBLIC_STATUS_UNAVAILABLE"))?;
        if std::env::args().nth(3).is_some() {
            anyhow::bail!("PUBLIC_STATUS_UNAVAILABLE")
        }
        return tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(loomex_runner::jobs::public_status::serve_mcp(
                std::path::Path::new(&socket),
            ));
    }
    if std::env::args().nth(1).is_some_and(|a| a == "--version") {
        println!("loomex-runner {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    if std::env::args_os().nth(1).is_some() {
        anyhow::bail!("INVALID_REQUEST");
    }
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let result = runtime.block_on(async {
        let dir = state::state_dir()?;
        let api = Api::new()?;
        let auth = Auth::new(api.clone())?;
        control::serve(Arc::new(Daemon::new(dir, api, auth)?)).await
    });
    // control::serve has completed the existing managed-work drain. A native
    // worker keeps singleton ownership, but cannot be canceled by disposal.
    runtime.shutdown_timeout(std::time::Duration::from_secs(2));
    result
}
