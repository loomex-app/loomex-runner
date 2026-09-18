//! Test-only process boundary around the real owner-scoped presentation store.
//! Always uses a disposable directory; never discovers user state or credentials.
use loomex_runner::{presentation::PresentationStore, state};
use serde_json::{Value, json};
use std::io::{self, BufRead, Write};
fn main() -> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let store = PresentationStore::open(directory.path())?;
    for line in io::stdin().lock().lines() {
        let request: Value = serde_json::from_str(&line?)?;
        let result = store.dispatch(
            request["org"].as_str().unwrap_or("fixture-org"),
            "fixture-account",
            request["method"].as_str().unwrap_or(""),
            &request["params"],
        );
        let response = match result {
            Ok(value) => json!({"result":value}),
            Err(error) => json!({"error":state::safe_error(&error.to_string(),false)}),
        };
        println!("{response}");
        io::stdout().flush()?;
    }
    Ok(())
}
