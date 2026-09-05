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
        let (code, retryable) = control::public_error(&error);
        eprintln!("{}", state::safe_error(&code, retryable));
        std::process::exit(1)
    }
}
fn entry() -> Result<()> {
    if executor::maybe_run_supervisor()? {
        return Ok(());
    }
    if std::env::args().nth(1).is_some_and(|a| a == "--version") {
        println!("loomex-runner {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let dir = state::state_dir()?;
            let api = Api::new()?;
            let auth = Auth::new(api.clone())?;
            control::serve(Arc::new(Daemon::new(dir, api, auth)?)).await
        })
}
