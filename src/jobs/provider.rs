use super::*;

pub(super) fn validate_job_kind(kind: &str) -> Result<()> {
    match kind {
        "shell.exec" | "command.run" | "http.request" => Ok(()),
        // Reserve an explicit compatibility result for callers that try to
        // advance the HTTP payload version before this runner supports it.
        "http.request/v1" => bail!("HTTP_REQUEST_SCHEMA_UNSUPPORTED"),
        _ => bail!("UNSUPPORTED_JOB_KIND"),
    }
}

pub(super) const PROVIDER_ADAPTER_SCHEMA: &str = "loomex.provider-adapter/v1";
pub(super) const CODEX_OUTPUT_TRANSPORTS: &[&str] = &["codex.native-json/v2", "codex.json-tree/v2"];

/// The runner admits only the exact, prepared host-provider identities.  The
/// command arguments themselves remain backend-owned bound data; this checks
/// the provider adapter and output transport that select their local meaning.
pub(super) fn canonical_provider_adapter(provider: &str) -> Option<Value> {
    Some(match provider {
        "codex" => json!({
            "schemaVersion": PROVIDER_ADAPTER_SCHEMA,
            "provider": "codex",
            "adapter": "codex",
            "executable": "codex",
        }),
        "claude" => json!({
            "schemaVersion": PROVIDER_ADAPTER_SCHEMA,
            "provider": "claude",
            "adapter": "claude",
            "executable": "claude",
            "outputTransport": "claude.stream-json/v1",
        }),
        // Historic Gemini records remain bound to the official Gemini CLI.
        // Antigravity is a separate provider bound to the agy executable.
        "gemini" => json!({
            "schemaVersion": PROVIDER_ADAPTER_SCHEMA,
            "provider": "gemini",
            "adapter": "gemini",
            "executable": "gemini",
            "outputTransport": "gemini.stream-json/v1",
        }),
        "antigravity" => json!({
            "schemaVersion": PROVIDER_ADAPTER_SCHEMA,
            "provider": "antigravity",
            "adapter": "antigravity",
            "executable": "agy",
            "outputTransport": "antigravity.json/v1",
        }),
        _ => return None,
    })
}

pub(super) fn validate_provider_adapter(payload: &Value, argv: &[String]) -> Result<()> {
    let provider = payload["provider"]
        .as_str()
        .context("PROVIDER_ADAPTER_INVALID")?;
    let expected = canonical_provider_adapter(provider).context("PROVIDER_ADAPTER_INVALID")?;
    let adapter = payload
        .get("providerAdapter")
        .context("PROVIDER_ADAPTER_INVALID")?;
    let executable = expected["executable"].as_str().unwrap();
    if adapter != &expected || argv.first().is_none_or(|arg| arg != executable) {
        bail!("PROVIDER_ADAPTER_INVALID")
    }
    let transport = payload["providerOutputTransport"]
        .as_str()
        .context("PROVIDER_ADAPTER_INVALID")?;
    let valid_transport = match provider {
        "codex" => CODEX_OUTPUT_TRANSPORTS.contains(&transport),
        "claude" => transport == "claude.stream-json/v1",
        "gemini" => transport == "gemini.stream-json/v1",
        "antigravity" => transport == "antigravity.json/v1",
        _ => false,
    };
    if !valid_transport {
        bail!("PROVIDER_ADAPTER_INVALID")
    }
    Ok(())
}

pub(super) fn provider_contract_fields(payload: &Value) -> bool {
    [
        "providerAdapter",
        "providerInput",
        "providerInputDigest",
        "providerOutputTransport",
        "providerOutputSchema",
        "providerOutputSchemaDigest",
    ]
    .iter()
    .any(|field| payload.get(*field).is_some())
}

pub(super) fn validate_provider_input(payload: &Value, argv: &[String]) -> Result<()> {
    let provider = payload["provider"]
        .as_str()
        .context("PROVIDER_ADAPTER_INVALID")?;
    let input = payload["providerInput"]
        .as_str()
        .context("PROVIDER_INPUT_MISSING")?;
    if payload["providerInputDigest"] != state::digest(input.as_bytes()) {
        bail!("PROVIDER_INPUT_DIGEST_MISMATCH")
    }
    let exact = match provider {
        "codex" => argv.last().is_some_and(|arg| arg == input),
        "claude" | "gemini" | "antigravity" => argv
            .windows(2)
            .any(|args| args[0] == "-p" && args[1] == input),
        _ => false,
    };
    if !exact {
        bail!("PROVIDER_INPUT_ARGV_MISMATCH")
    }
    validate_provider_adapter(payload, argv)
}

pub(super) fn materialize_provider_output_schema(
    payload: &Value,
    argv: &mut [String],
    output_dir: &Path,
) -> Result<()> {
    let has_schema = payload.get("providerOutputSchema").is_some()
        || payload.get("providerOutputSchemaDigest").is_some()
        || argv.iter().any(|arg| arg == "{loomex:provider-schema}");
    if payload["provider"] != "codex" {
        if has_schema {
            bail!("PROVIDER_SCHEMA_INVALID")
        }
        return Ok(());
    }
    let schema = payload
        .get("providerOutputSchema")
        .filter(|schema| schema.is_object())
        .context("PROVIDER_SCHEMA_INVALID")?;
    if payload["providerOutputSchemaDigest"] != state::json_digest(schema) {
        bail!("PROVIDER_SCHEMA_INVALID")
    }
    let mut placeholders = argv
        .iter_mut()
        .filter(|arg| arg.as_str() == "{loomex:provider-schema}");
    let Some(placeholder) = placeholders.next() else {
        bail!("PROVIDER_SCHEMA_INVALID")
    };
    if placeholders.next().is_some() {
        bail!("PROVIDER_SCHEMA_INVALID")
    }
    let schema_path = output_dir.join("provider-schema.json");
    state::write_json(&schema_path, schema)?;
    *placeholder = schema_path.to_string_lossy().into_owned();
    Ok(())
}

pub(super) async fn execute_authorized_command(
    job: &AuthorizedJob,
    request: ExecutionRequest,
    cancel: Arc<AtomicBool>,
) -> Result<executor::ExecutionOutcome> {
    if request.workspace != job.workspace() {
        bail!("WORKSPACE_DENIED");
    }
    executor::execute(request, cancel).await
}

pub(super) fn command_request(
    authorized: &AuthorizedJob,
    id: &str,
    path: &Path,
    journal: Arc<Mutex<Journal>>,
) -> Result<ExecutionRequest> {
    let payload = authorized.payload();
    let output_dir = path.parent().context("journal parent")?.to_path_buf();
    let mut argv: Vec<String> = if let Some(items) = payload["command"].as_array() {
        items
            .iter()
            .map(|v| v.as_str().map(String::from).context("INVALID_COMMAND"))
            .collect::<Result<_>>()?
    } else {
        bail!("INVALID_COMMAND")
    };
    if argv.is_empty() {
        bail!("INVALID_COMMAND")
    };

    argv[0] = find_executable(&argv[0])
        .context("PROVIDER_UNAVAILABLE")?
        .to_string_lossy()
        .into_owned();
    if payload.get("provider").is_some() {
        materialize_provider_output_schema(payload, &mut argv, &output_dir)?;
    }
    let requested_env: BTreeMap<String, String> = match payload["env"].as_object() {
        Some(map) => map
            .iter()
            .map(|(k, v)| Ok((k.clone(), v.as_str().context("INVALID_COMMAND_ENV")?.into())))
            .collect::<Result<_>>()?,
        None => BTreeMap::new(),
    };
    let mut env = BTreeMap::new();
    for name in ["HOME", "USER", "LOGNAME", "TMPDIR", "LANG", "LC_ALL"] {
        if let Ok(value) = std::env::var(name) {
            env.insert(name.into(), value);
        }
    }
    let base_path = std::env::var("PATH").unwrap_or_default();
    env.insert(
        "PATH".into(),
        format!("{base_path}:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin"),
    );
    env.extend(requested_env);
    let observer = Arc::new(Observer {
        path: path.to_owned(),
        journal,
    });
    Ok(ExecutionRequest {
        job_id: id.into(),
        workspace: authorized.workspace().to_path_buf(),
        cwd: payload["cwd"].as_str().map(PathBuf::from),
        argv,
        env,
        output_dir,
        policy: "host_user/v1".into(),
        observer,
    })
}
