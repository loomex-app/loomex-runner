use super::*;

pub(super) const HTTP_REQUEST_SCHEMA: &str = "loomex.http-request/v1";
/// The terminal result is carried in a runner-control frame. Keep a margin
/// below the 1 MiB transport limit and make the inline-versus-artifact choice
/// from the serialized result, rather than an untrusted Content-Length.
pub(super) const MAX_INLINE_HTTP_RESULT_BYTES: usize = 256 * 1024;
pub(super) const HTTP_RESULT_SCHEMA: &str = "loomex.http-result/v1";
pub(super) const HTTP_BODY_REF_SCHEMA: &str = "loomex.http-response-artifact/v1";

#[derive(Debug)]
pub(super) struct HttpFailure {
    pub(super) code: &'static str,
    pub(super) stage: &'static str,
    pub(super) dispatched: bool,
}

impl std::fmt::Display for HttpFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.code)
    }
}

impl std::error::Error for HttpFailure {}

pub(super) fn http_failure(
    code: &'static str,
    stage: &'static str,
    dispatched: bool,
) -> anyhow::Error {
    HttpFailure {
        code,
        stage,
        dispatched,
    }
    .into()
}

#[derive(Debug)]
pub(super) enum HttpBody {
    Utf8(String),
    Json(Value),
}

#[derive(Debug)]
pub(super) struct HttpRequest {
    pub(super) method: Method,
    pub(super) url: Url,
    pub(super) headers: reqwest::header::HeaderMap,
    pub(super) body: Option<HttpBody>,
    pub(super) timeout: Duration,
}

pub(super) fn http_request(payload: &Value) -> Result<HttpRequest> {
    use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
    if payload["schemaVersion"] != HTTP_REQUEST_SCHEMA {
        bail!("HTTP_REQUEST_SCHEMA_UNSUPPORTED")
    }
    if payload["resultContract"]
        != json!({"schemaVersion":HTTP_RESULT_SCHEMA,"artifactRefSchemaVersion":HTTP_BODY_REF_SCHEMA})
    {
        bail!("HTTP_RESULT_SCHEMA_UNSUPPORTED")
    }
    let method = payload["method"]
        .as_str()
        .and_then(|method| Method::from_bytes(method.as_bytes()).ok())
        .filter(|method| {
            matches!(
                *method,
                Method::GET | Method::POST | Method::PUT | Method::PATCH | Method::DELETE
            )
        })
        .context("HTTP_REQUEST_INVALID")?;
    let url = Url::parse(payload["url"].as_str().context("HTTP_REQUEST_INVALID")?)
        .map_err(|_| anyhow::anyhow!("HTTP_REQUEST_INVALID"))?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        bail!("HTTP_REQUEST_INVALID")
    }
    let mut headers = HeaderMap::new();
    for (name, value) in payload["headers"]
        .as_object()
        .context("HTTP_REQUEST_INVALID")?
    {
        let name = HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| anyhow::anyhow!("HTTP_REQUEST_INVALID"))?;
        let value = HeaderValue::from_str(value.as_str().context("HTTP_REQUEST_INVALID")?)
            .map_err(|_| anyhow::anyhow!("HTTP_REQUEST_INVALID"))?;
        headers.append(name, value);
    }
    if let Some(key) = payload["idempotencyKey"]
        .as_str()
        .filter(|key| !key.is_empty())
        && !headers.contains_key("idempotency-key")
    {
        headers.insert(
            "idempotency-key",
            HeaderValue::from_str(key).map_err(|_| anyhow::anyhow!("HTTP_REQUEST_INVALID"))?,
        );
    }
    let body = match payload.get("body").filter(|body| !body.is_null()) {
        None => None,
        Some(body) => match body["encoding"].as_str() {
            Some("utf8") => Some(HttpBody::Utf8(
                body["value"]
                    .as_str()
                    .map(str::to_owned)
                    .context("HTTP_REQUEST_INVALID")?,
            )),
            Some("json") if body.get("value").is_some() => {
                Some(HttpBody::Json(body["value"].clone()))
            }
            _ => bail!("HTTP_REQUEST_INVALID"),
        },
    };
    let timeout_seconds = payload["timeoutSeconds"].as_u64().unwrap_or(10);
    if !(1..=60).contains(&timeout_seconds) {
        bail!("HTTP_REQUEST_INVALID")
    }
    if let Some(statuses) = payload.get("expectedStatusCodes") {
        let statuses = statuses.as_array().context("HTTP_REQUEST_INVALID")?;
        if statuses.is_empty()
            || statuses
                .iter()
                .any(|status| !matches!(status.as_u64(), Some(100..=599)))
        {
            bail!("HTTP_REQUEST_INVALID")
        }
    }
    Ok(HttpRequest {
        method,
        url,
        headers,
        body,
        timeout: Duration::from_secs(timeout_seconds),
    })
}

pub(super) fn local_or_private(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            address.is_private() || address.is_loopback() || address.is_link_local()
        }
        IpAddr::V6(address) => {
            address.is_loopback() || address.is_unique_local() || address.is_unicast_link_local()
        }
    }
}

pub(super) async fn resolve_private_http_addresses(
    request: &HttpRequest,
    cancel: Arc<AtomicBool>,
    deadline: TokioInstant,
) -> Result<Vec<SocketAddr>> {
    let host = request
        .url
        .host_str()
        .context("HTTP_REQUEST_INVALID")?
        .to_owned();
    let port = request
        .url
        .port_or_known_default()
        .context("HTTP_REQUEST_INVALID")?;
    resolve_private_http_addresses_with(cancel, deadline, async move {
        tokio::net::lookup_host((host.as_str(), port))
            .await
            .map_err(|_| anyhow::anyhow!("HTTP_REQUEST_URL_DENIED"))
            .map(|addresses| addresses.collect())
    })
    .await
}

pub(super) fn validate_private_http_addresses(
    resolved: Vec<SocketAddr>,
) -> Result<Vec<SocketAddr>> {
    if resolved.is_empty()
        || resolved
            .iter()
            .any(|address| !local_or_private(address.ip()))
    {
        bail!("HTTP_REQUEST_URL_DENIED")
    }
    Ok(resolved)
}

// Keeping resolution as an injected future makes the phase boundary explicit:
// cancellation and the absolute deadline can settle before any request future
// is created or polled. The production caller supplies Tokio DNS resolution.
pub(super) async fn resolve_private_http_addresses_with<F>(
    cancel: Arc<AtomicBool>,
    deadline: TokioInstant,
    resolver: F,
) -> Result<Vec<SocketAddr>>
where
    F: Future<Output = Result<Vec<SocketAddr>>>,
{
    let resolved: Vec<SocketAddr> = tokio::select! {
        // A cancellation observed before send is known not to have reached the
        // target, so it is a cancellation rather than an indeterminate request.
        biased;
        _ = wait_for_cancellation(cancel) => bail!("JOB_CANCELED"),
        // Nothing capable of writing to the target has been constructed or
        // polled while resolving. A deadline here is a known non-dispatch.
        _ = tokio::time::sleep_until(deadline) => return Err(http_failure("HTTP_REQUEST_TIMEOUT", "resolve", false)),
        result = resolver => result?,
    };
    validate_private_http_addresses(resolved)
}

pub(super) fn private_http_client(
    request: &HttpRequest,
    resolved: Vec<SocketAddr>,
    deadline: TokioInstant,
) -> Result<Client> {
    let remaining = deadline.saturating_duration_since(TokioInstant::now());
    if remaining.is_zero() {
        return Err(http_failure("HTTP_REQUEST_TIMEOUT", "prepare", false));
    }
    let host = request.url.host_str().context("HTTP_REQUEST_INVALID")?;
    let mut client = Client::builder()
        .redirect(Policy::none())
        .no_proxy()
        // A send may have reached the target even when its result is an
        // error, so the runner must never let the HTTP client replay it.
        .retry(reqwest::retry::never())
        // The client timeout is only a backstop; the same absolute deadline is
        // also selected below while sending and reading the response.
        .timeout(remaining);
    for address in resolved {
        client = client.resolve(host, address);
    }
    client
        .build()
        .map_err(|_| anyhow::anyhow!("HTTP_REQUEST_INVALID"))
}

pub(super) async fn wait_for_cancellation(cancel: Arc<AtomicBool>) {
    while !cancel.load(Ordering::SeqCst) {
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

pub(super) fn inline_http_content_type(content_type: &str) -> bool {
    let media_type = content_type
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    media_type.starts_with("text/")
        || media_type.contains("json")
        || media_type.ends_with("+json")
        || matches!(
            media_type.as_str(),
            "application/xml"
                | "text/xml"
                | "application/javascript"
                | "application/x-www-form-urlencoded"
        )
        // Historic responses without a Content-Type remain inline when they
        // are valid UTF-8 and fit. Invalid UTF-8 is always retained as bytes.
        || media_type.is_empty()
}

pub(super) fn http_body_value(bytes: Vec<u8>, content_type: &str) -> Option<Value> {
    if !inline_http_content_type(content_type) {
        return None;
    }
    let text = String::from_utf8(bytes).ok()?;
    Some(
        if content_type.to_ascii_lowercase().contains("json")
            || text.trim_start().starts_with(['{', '['])
        {
            serde_json::from_str(&text).unwrap_or_else(|_| json!(text))
        } else {
            json!(text)
        },
    )
}

pub(super) fn sensitive_http_header(name: &str) -> bool {
    let normalized = name.to_ascii_lowercase().replace('-', "_");
    matches!(
        normalized.as_str(),
        "authorization" | "cookie" | "proxy_authorization" | "set_cookie" | "x_api_key"
    ) || [
        "authorization",
        "password",
        "secret",
        "token",
        "api_key",
        "apikey",
        "access_key",
    ]
    .iter()
    .any(|part| normalized.contains(part))
}

pub(super) fn safe_http_headers(headers: &reqwest::header::HeaderMap) -> Value {
    let mut safe = serde_json::Map::new();
    let mut size = 0usize;
    for (name, value) in headers.iter().take(100) {
        if !sensitive_http_header(name.as_str()) {
            if let Ok(value) = value.to_str() {
                let entry_size = name.as_str().len().saturating_add(value.len());
                // Header values are remote-controlled too. Preserve a useful
                // bounded projection so a large header cannot force an
                // otherwise artifact-backed terminal result over its frame.
                if entry_size > 4096 || size.saturating_add(entry_size) > 16 * 1024 {
                    continue;
                }
                size = size.saturating_add(entry_size);
                safe.insert(name.as_str().to_owned(), json!(value));
            }
        }
    }
    Value::Object(safe)
}

async fn execute_http_request(
    payload: &Value,
    cancel: Arc<AtomicBool>,
    body_path: &Path,
) -> Result<Value> {
    let request = http_request(payload)
        .map_err(|_| http_failure("HTTP_REQUEST_INVALID", "validate", false))?;
    if cancel.load(Ordering::SeqCst) {
        return Err(http_failure("JOB_CANCELED", "prepare", false));
    }
    let deadline = TokioInstant::now() + request.timeout;
    let resolved = resolve_private_http_addresses(&request, cancel.clone(), deadline)
        .await
        .map_err(|error| match error.to_string().as_str() {
            "JOB_CANCELED" => http_failure("JOB_CANCELED", "resolve", false),
            "HTTP_REQUEST_URL_DENIED" => http_failure("HTTP_REQUEST_URL_DENIED", "resolve", false),
            _ => error,
        })?;
    // Resolution establishes the pin set, but cancellation may arrive while it
    // is in progress.  Check again before constructing a sendable request.
    if cancel.load(Ordering::SeqCst) {
        return Err(http_failure("JOB_CANCELED", "prepare", false));
    }
    let client = private_http_client(&request, resolved, deadline).map_err(|error| {
        if error.downcast_ref::<HttpFailure>().is_some() {
            error
        } else {
            http_failure("HTTP_REQUEST_INVALID", "prepare", false)
        }
    })?;
    let mut outbound = client
        .request(request.method, request.url)
        .headers(request.headers);
    if let Some(body) = request.body {
        outbound = match body {
            HttpBody::Utf8(body) => outbound.body(body),
            HttpBody::Json(body) => outbound.json(&body),
        };
    }
    // Do not poll reqwest's send future after a cancellation that was observed
    // before dispatch.  Once it has been polled, cancellation remains
    // indeterminate because the target may have received the request.
    if cancel.load(Ordering::SeqCst) {
        return Err(http_failure("JOB_CANCELED", "prepare", false));
    }
    let started = Instant::now();
    let dispatched = Arc::new(AtomicBool::new(false));
    let send_dispatched = dispatched.clone();
    let mut response = tokio::select! {
        biased;
        _ = wait_for_cancellation(cancel.clone()) => return Err(if dispatched.load(Ordering::SeqCst) { http_failure("HTTP_REQUEST_INDETERMINATE", "send", true) } else { http_failure("JOB_CANCELED", "prepare", false) }),
        _ = tokio::time::sleep_until(deadline) => return Err(if dispatched.load(Ordering::SeqCst) { http_failure("HTTP_REQUEST_INDETERMINATE", "send", true) } else { http_failure("HTTP_REQUEST_TIMEOUT", "prepare", false) }),
        // Setting this flag is the first operation performed when this future
        // is polled. From that precise point a target might have received the
        // request, including when reqwest returns an error.
        response = async move {
            send_dispatched.store(true, Ordering::SeqCst);
            outbound.send().await
        } => response.map_err(|_| http_failure("HTTP_REQUEST_INDETERMINATE", "send", true))?,
    };
    let status = response.status().as_u16();
    let headers = safe_http_headers(response.headers());
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    let output = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(body_path)
        .map_err(|_| http_failure("HTTP_REQUEST_INDETERMINATE", "response", true))?;
    let mut output = tokio::fs::File::from_std(output);
    let mut body_size = 0u64;
    loop {
        let chunk = tokio::select! {
            biased;
            _ = wait_for_cancellation(cancel.clone()) => return Err(http_failure("HTTP_REQUEST_INDETERMINATE", "response", dispatched.load(Ordering::SeqCst))),
            _ = tokio::time::sleep_until(deadline) => return Err(http_failure("HTTP_REQUEST_INDETERMINATE", "response", dispatched.load(Ordering::SeqCst))),
            chunk = response.chunk() => chunk.map_err(|_| http_failure("HTTP_REQUEST_INDETERMINATE", "response", dispatched.load(Ordering::SeqCst)))?,
        };
        let Some(chunk) = chunk else { break };
        output
            .write_all(&chunk)
            .await
            .map_err(|_| http_failure("HTTP_REQUEST_INDETERMINATE", "response", true))?;
        body_size = body_size.saturating_add(chunk.len() as u64);
    }
    output
        .sync_all()
        .await
        .map_err(|_| http_failure("HTTP_REQUEST_INDETERMINATE", "response", true))?;
    drop(output);

    if body_size <= MAX_INLINE_HTTP_RESULT_BYTES as u64 {
        let bytes = tokio::fs::read(body_path)
            .await
            .map_err(|_| http_failure("HTTP_REQUEST_INDETERMINATE", "response", true))?;
        if let Some(body) = http_body_value(bytes, &content_type) {
            let result = json!({
                "schemaVersion": HTTP_RESULT_SCHEMA,
                "statusCode": status,
                "headers": headers,
                "bodyStorage": "inline",
                "body": body,
                "durationMs": started.elapsed().as_millis() as u64,
            });
            if serde_json::to_vec(&result)
                .map_err(|_| http_failure("HTTP_REQUEST_INDETERMINATE", "response", true))?
                .len()
                < MAX_INLINE_HTTP_RESULT_BYTES
            {
                tokio::fs::remove_file(body_path)
                    .await
                    .map_err(|_| http_failure("HTTP_REQUEST_INDETERMINATE", "response", true))?;
                return Ok(result);
            }
        }
    }
    Ok(json!({
        "schemaVersion": HTTP_RESULT_SCHEMA,
        "statusCode": status,
        "headers": headers,
        "bodyPath": body_path,
        "bodyContentType": content_type,
        "bodySizeBytes": body_size,
        "durationMs": started.elapsed().as_millis() as u64,
    }))
}

pub(super) async fn execute_authorized_http(
    job: &AuthorizedJob,
    cancel: Arc<AtomicBool>,
    path: &Path,
) -> Result<Value> {
    execute_http_request(job.payload(), cancel, path).await
}

#[cfg(test)]
pub(super) async fn execute_test_http(
    payload: &Value,
    cancel: Arc<AtomicBool>,
    path: &Path,
) -> Result<Value> {
    execute_http_request(payload, cancel, path).await
}
