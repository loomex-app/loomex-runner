//! Test-only process boundary around the real owner-scoped presentation store.
//! Always uses a disposable directory; never discovers user state or credentials.
use anyhow::{Context, anyhow};
use loomex_runner::{presentation::PresentationStore, state};
use serde_json::{Value, json};
use std::io::{self, BufRead, Write};
fn main() -> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let store = PresentationStore::open(directory.path())?;
    for line in io::stdin().lock().lines() {
        let request: Value = serde_json::from_str(&line?)?;
        let org = request["org"].as_str().unwrap_or("fixture-org");
        let method = request["method"].as_str().unwrap_or("");
        let params = &request["params"];
        let result = match method {
            // Test-only boundaries around runner-owned side effects of an
            // accepted response. The production store remains unchanged.
            "fixture.entities.retire" => (|| {
                let entity_type = params["entityType"].as_str().context("INVALID_REQUEST")?;
                let ids = params["ids"]
                    .as_array()
                    .context("INVALID_REQUEST")?
                    .iter()
                    .map(|id| id.as_str().ok_or_else(|| anyhow!("INVALID_REQUEST")))
                    .collect::<anyhow::Result<Vec<_>>>()?;
                store.delete_entities(org, "fixture-account", entity_type, &ids)?;
                Ok(json!({"retired": ids.len()}))
            })(),
            "fixture.delivery.register" => store.register_delivery(
                org,
                "fixture-account",
                params["identity"].as_str().unwrap_or(""),
                &params["continuation"],
            ),
            _ => store.dispatch(org, "fixture-account", method, params),
        };
        let response = match result {
            Ok(value) => json!({"result":value}),
            Err(error) => json!({"error":state::safe_error(&error.to_string(),false)}),
        };
        println!("{response}");
        io::stdout().flush()?;
    }
    Ok(())
}
