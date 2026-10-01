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
pub(super) const CODEX_NATIVE_PROJECTED_TRANSPORT: &str = "codex.native-projected-json/v3";
pub(super) const CODEX_OUTPUT_TRANSPORTS: &[&str] = &[
    "codex.native-json/v2",
    "codex.json-tree/v2",
    CODEX_NATIVE_PROJECTED_TRANSPORT,
];

/// Mirror the backend's deliberately narrow projection. The projected schema
/// may omit a string length assertion, but it must retain every field/type.
/// The backend still validates the unchanged authored schema after decoding.
pub(super) fn project_codex_native_hint(node: &mut Value) -> Result<()> {
    let map = node.as_object_mut().context("PROVIDER_SCHEMA_INVALID")?;
    if let Some(length) = map.get("minLength") {
        if map.get("type").and_then(Value::as_str) != Some("string") || length.as_u64().is_none() {
            bail!("PROVIDER_SCHEMA_INVALID");
        }
        map.remove("minLength");
    }
    if let Some(constant) = map.get("const") {
        if map.get("type").and_then(Value::as_str) != Some("string")
            || !constant.is_string()
            || map.contains_key("enum")
        {
            bail!("PROVIDER_SCHEMA_INVALID");
        }
        let constant = map.remove("const").context("PROVIDER_SCHEMA_INVALID")?;
        map.insert("enum".into(), json!([constant]));
    }
    for field in ["properties", "$defs"] {
        if let Some(children) = map.get_mut(field) {
            for child in children
                .as_object_mut()
                .context("PROVIDER_SCHEMA_INVALID")?
                .values_mut()
            {
                project_codex_native_hint(child)?;
            }
        }
    }
    if let Some(items) = map.get_mut("items") {
        project_codex_native_hint(items)?;
    }
    if let Some(branches) = map.get_mut("anyOf") {
        for branch in branches.as_array_mut().context("PROVIDER_SCHEMA_INVALID")? {
            project_codex_native_hint(branch)?;
        }
    }
    Ok(())
}

#[derive(Default)]
struct NativeSchemaCounts {
    properties: usize,
    enums: usize,
    strings: usize,
}

/// A pre-spawn subset fence matching the backend compiler's supported shape.
/// This never projects unknown constraints or rewrites an authored contract.
pub(super) fn validate_native_hint_schema(schema: &Value) -> Result<()> {
    if schema["type"] != "object" || schema.get("anyOf").is_some() {
        bail!("PROVIDER_SCHEMA_INVALID");
    }
    let mut counts = NativeSchemaCounts::default();
    let mut checked_refs = HashSet::new();
    validate_native_hint_node(schema, schema, 1, &[], true, &mut checked_refs, &mut counts)?;
    if counts.properties > 5_000 || counts.enums > 1_000 || counts.strings > 120_000 {
        bail!("PROVIDER_SCHEMA_INVALID");
    }
    Ok(())
}

fn validate_native_hint_node(
    node: &Value,
    root: &Value,
    depth: usize,
    refs: &[String],
    count: bool,
    checked_refs: &mut HashSet<(String, usize)>,
    counts: &mut NativeSchemaCounts,
) -> Result<()> {
    const KEYWORDS: &[&str] = &[
        "title",
        "description",
        "$defs",
        "type",
        "properties",
        "required",
        "additionalProperties",
        "items",
        "enum",
        "anyOf",
        "$ref",
        "pattern",
        "format",
        "minimum",
        "maximum",
        "exclusiveMinimum",
        "exclusiveMaximum",
        "multipleOf",
        "minItems",
        "maxItems",
    ];
    const TYPES: &[&str] = &[
        "object", "array", "string", "integer", "number", "boolean", "null",
    ];
    const FORMATS: &[&str] = &[
        "date-time",
        "time",
        "date",
        "duration",
        "email",
        "hostname",
        "ipv4",
        "ipv6",
        "uuid",
    ];
    let map = node.as_object().context("PROVIDER_SCHEMA_INVALID")?;
    if depth > 10 || map.keys().any(|key| !KEYWORDS.contains(&key.as_str())) {
        bail!("PROVIDER_SCHEMA_INVALID");
    }
    let definitions = match map.get("$defs") {
        Some(value) => value.as_object().context("PROVIDER_SCHEMA_INVALID")?,
        None => {
            static EMPTY: std::sync::LazyLock<serde_json::Map<String, Value>> =
                std::sync::LazyLock::new(serde_json::Map::new);
            &EMPTY
        }
    };
    if count {
        counts.strings += definitions
            .keys()
            .map(|name| name.chars().count())
            .sum::<usize>();
    }
    for definition in definitions.values() {
        validate_native_hint_node(definition, root, 0, refs, count, checked_refs, counts)?;
    }
    if let Some(reference) = map.get("$ref") {
        let reference = reference.as_str().context("PROVIDER_SCHEMA_INVALID")?;
        if map
            .keys()
            .any(|key| !["title", "description", "$defs", "$ref"].contains(&key.as_str()))
            || !reference.starts_with("#/$defs/")
            || refs.iter().any(|seen| seen == reference)
        {
            bail!("PROVIDER_SCHEMA_INVALID");
        }
        let ref_key = (reference.to_owned(), depth);
        if !checked_refs.contains(&ref_key) {
            let target = root
                .pointer(&reference[1..])
                .context("PROVIDER_SCHEMA_INVALID")?;
            let mut next_refs = refs.to_vec();
            next_refs.push(reference.to_owned());
            validate_native_hint_node(
                target,
                root,
                depth,
                &next_refs,
                false,
                checked_refs,
                counts,
            )?;
            checked_refs.insert(ref_key);
        }
        return Ok(());
    }
    if let Some(branches) = map.get("anyOf") {
        if map
            .keys()
            .any(|key| !["title", "description", "$defs", "anyOf"].contains(&key.as_str()))
        {
            bail!("PROVIDER_SCHEMA_INVALID");
        }
        let branches = branches
            .as_array()
            .filter(|branches| !branches.is_empty())
            .context("PROVIDER_SCHEMA_INVALID")?;
        for branch in branches {
            validate_native_hint_node(branch, root, depth, refs, count, checked_refs, counts)?;
        }
        return Ok(());
    }
    let types: HashSet<&str> = match map.get("type") {
        Some(Value::String(kind)) => [kind.as_str()].into_iter().collect(),
        Some(Value::Array(kinds)) => kinds
            .iter()
            .map(|kind| kind.as_str().context("PROVIDER_SCHEMA_INVALID"))
            .collect::<Result<_>>()?,
        _ => bail!("PROVIDER_SCHEMA_INVALID"),
    };
    if types.is_empty()
        || types.iter().any(|kind| !TYPES.contains(kind))
        || (types.len() > 1 && (types.len() != 2 || !types.contains("null")))
    {
        bail!("PROVIDER_SCHEMA_INVALID");
    }
    for (applicable, keywords) in [
        (
            &["object"][..],
            &["properties", "required", "additionalProperties"][..],
        ),
        (&["array"][..], &["items", "minItems", "maxItems"][..]),
        (&["string"][..], &["pattern", "format"][..]),
        (
            &["integer", "number"][..],
            &[
                "minimum",
                "maximum",
                "exclusiveMinimum",
                "exclusiveMaximum",
                "multipleOf",
            ][..],
        ),
    ] {
        if keywords.iter().any(|key| map.contains_key(*key))
            && !applicable.iter().any(|kind| types.contains(kind))
        {
            bail!("PROVIDER_SCHEMA_INVALID");
        }
    }
    if types.contains("object") {
        let properties = match map.get("properties") {
            Some(value) => value.as_object().context("PROVIDER_SCHEMA_INVALID")?,
            None => {
                static EMPTY: std::sync::LazyLock<serde_json::Map<String, Value>> =
                    std::sync::LazyLock::new(serde_json::Map::new);
                &EMPTY
            }
        };
        let required_values: &[Value] = match map.get("required") {
            Some(value) => value
                .as_array()
                .context("PROVIDER_SCHEMA_INVALID")?
                .as_slice(),
            None => &[],
        };
        let required: HashSet<&str> = required_values
            .iter()
            .map(|item| item.as_str().context("PROVIDER_SCHEMA_INVALID"))
            .collect::<Result<_>>()?;
        if map.get("additionalProperties") != Some(&json!(false))
            || required.len() != properties.len()
            || properties
                .keys()
                .any(|name| !required.contains(name.as_str()))
        {
            bail!("PROVIDER_SCHEMA_INVALID");
        }
        if count {
            counts.properties += properties.len();
            counts.strings += properties
                .keys()
                .map(|name| name.chars().count())
                .sum::<usize>();
        }
        for child in properties.values() {
            validate_native_hint_node(child, root, depth + 1, refs, count, checked_refs, counts)?;
        }
    }
    if types.contains("array") {
        let items = map.get("items").context("PROVIDER_SCHEMA_INVALID")?;
        validate_native_hint_node(items, root, depth + 1, refs, count, checked_refs, counts)?;
    }
    if let Some(format) = map.get("format") {
        if !FORMATS.contains(&format.as_str().context("PROVIDER_SCHEMA_INVALID")?) {
            bail!("PROVIDER_SCHEMA_INVALID");
        }
    }
    let values: &[Value] = match map.get("enum") {
        Some(value) => value
            .as_array()
            .context("PROVIDER_SCHEMA_INVALID")?
            .as_slice(),
        None => &[],
    };
    if values
        .iter()
        .any(|value| value.is_array() || value.is_object())
    {
        bail!("PROVIDER_SCHEMA_INVALID");
    }
    let string_size: usize = values
        .iter()
        .filter_map(Value::as_str)
        .map(|s| s.chars().count())
        .sum();
    if values.len() > 250 && string_size > 15_000 {
        bail!("PROVIDER_SCHEMA_INVALID");
    }
    if count {
        counts.enums += values.len();
        counts.strings += string_size;
    }
    Ok(())
}

fn validate_projected_codex_binding(payload: &Value) -> Result<()> {
    let has_authored = payload.get("providerAuthoredOutputSchema").is_some()
        || payload.get("providerAuthoredOutputSchemaDigest").is_some();
    if payload["providerOutputTransport"] != CODEX_NATIVE_PROJECTED_TRANSPORT {
        if has_authored {
            bail!("PROVIDER_SCHEMA_INVALID");
        }
        return Ok(());
    }
    if payload["provider"] != "codex" {
        bail!("PROVIDER_SCHEMA_INVALID");
    }
    let authored = payload
        .get("providerAuthoredOutputSchema")
        .filter(|schema| schema.is_object())
        .context("PROVIDER_SCHEMA_INVALID")?;
    let hint = payload
        .get("providerOutputSchema")
        .filter(|schema| schema.is_object())
        .context("PROVIDER_SCHEMA_INVALID")?;
    if payload["providerAuthoredOutputSchemaDigest"] != state::json_digest(authored)
        || payload["providerOutputSchemaDigest"] != state::json_digest(hint)
    {
        bail!("PROVIDER_SCHEMA_INVALID");
    }
    let input: Value = serde_json::from_str(
        payload["providerInput"]
            .as_str()
            .context("PROVIDER_SCHEMA_INVALID")?,
    )
    .context("PROVIDER_SCHEMA_INVALID")?;
    if input["schemaVersion"] != "loomex.provider-input/v1"
        || input.pointer("/context/outputSchema") != Some(authored)
        || input["outputContract"]
            != "Return exactly the result JSON object requested by the prompt and context.outputSchema as native structured output."
    {
        bail!("PROVIDER_SCHEMA_INVALID");
    }
    let mut projected = authored.clone();
    project_codex_native_hint(&mut projected)?;
    if projected != *hint {
        bail!("PROVIDER_SCHEMA_INVALID");
    }
    validate_native_hint_schema(hint)
}

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
        "providerAuthoredOutputSchema",
        "providerAuthoredOutputSchemaDigest",
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
    validate_provider_adapter(payload, argv)?;
    validate_projected_codex_binding(payload)
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
    validate_projected_codex_binding(payload)?;
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
