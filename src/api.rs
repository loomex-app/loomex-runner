use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fmt,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use url::Url;

const BASE: &str = "/api/v1/runner-control/runner/";
#[derive(Clone)]
pub struct SignedCredential {
    pub(crate) token: String,
    pub(crate) subject: String,
    pub(crate) private_key: [u8; 32],
}
#[derive(Clone)]
pub struct Api {
    client: reqwest::Client,
    origin: Url,
}
#[derive(Debug)]
pub struct ApiError {
    pub code: String,
    pub retryable: bool,
    pub data: Option<Value>,
}
impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.code)
    }
}
impl std::error::Error for ApiError {}
impl ApiError {
    fn new(code: &str, retryable: bool) -> Self {
        Self {
            code: code.into(),
            retryable,
            data: None,
        }
    }
}

const MAX_VALIDATION_ISSUES: usize = 32;
const MAX_AUTHORING_ERROR_MESSAGE_BYTES: usize = 4_096;

fn validation_issue_contract(code: &str) -> Option<(&'static str, &'static str)> {
    match code {
        "RUN_INPUT_SCHEMA_INVALID" => Some((
            "Workflow inputs do not match the required schema.",
            "correct_workflow_inputs",
        )),
        "RUN_VALIDATION_EXECUTION_POLICY_INVALID" | "UNSUPPORTED_CAPABILITY" => Some((
            "The workflow execution policy does not support a required capability.",
            "update_workflow_definition",
        )),
        "RUN_VALIDATION_EXECUTION_ROOT_REQUIRED" => Some((
            "This workflow requires a prepared local runner execution root.",
            "prepare_runner_execution",
        )),
        "RUN_VALIDATION_RUNNER_UNAVAILABLE" => Some((
            "The required local runner is not connected.",
            "connect_runner",
        )),
        "RUN_VALIDATION_PROVIDER_UNSUPPORTED" => Some((
            "The selected provider does not support a required workflow capability.",
            "choose_supported_provider",
        )),
        "RUN_VALIDATION_PROVIDER_INVALID" => Some((
            "The workflow selects a provider that cannot run this work.",
            "choose_supported_provider",
        )),
        "RUN_VALIDATION_POLICY_DENIED" => Some((
            "The execution policy does not allow a required workflow capability.",
            "allow_capability",
        )),
        "RUN_VALIDATION_POLICY_REQUIRED" => Some((
            "A required workflow capability policy has not been configured.",
            "configure_capability_policy",
        )),
        "RUN_VALIDATION_FAILED" => Some((
            "The workflow has a validation issue that must be reviewed.",
            "review_workflow_validation",
        )),
        _ => None,
    }
}

fn safe_node_index(value: &Value) -> Option<u64> {
    value
        .as_u64()
        .filter(|index| (1..=1_000_000).contains(index))
}

fn safe_validation_data(payload: &Value) -> Option<Value> {
    if payload
        .pointer("/error/details/validationIssueVersion")
        .and_then(Value::as_str)
        != Some("v1")
    {
        return None;
    }
    let raw = payload
        .pointer("/error/details/validationIssues")?
        .as_array()?;
    let issues = raw
        .iter()
        .filter_map(|issue| {
            let issue = issue.as_object()?;
            let code = issue.get("code")?.as_str()?;
            let (message, next_action) = validation_issue_contract(code)?;
            let mut projected = serde_json::Map::from_iter([
                ("code".into(), json!(code)),
                ("message".into(), json!(message)),
                ("nextAction".into(), json!(next_action)),
            ]);
            if let Some(index) = issue.get("nodeIndex").and_then(safe_node_index) {
                projected.insert("nodeIndex".into(), json!(index));
            }
            Some(Value::Object(projected))
        })
        .take(MAX_VALIDATION_ISSUES)
        .collect::<Vec<_>>();
    (!issues.is_empty()).then(|| json!({"validationIssueVersion":"v1","validationIssues":issues}))
}

/// Creation-time definition failures are user-correctable authoring feedback,
/// rather than execution-policy advice.  The backend deliberately supplies a
/// single canonical message for these codes; preserve only that bounded field
/// so a local client can surface the validation outcome without exposing an
/// arbitrary backend error envelope.
fn safe_authoring_error_data(code: &str, payload: &Value) -> Option<Value> {
    if !matches!(
        code,
        "WORKFLOW_DEFINITION_REQUIRED" | "WORKFLOW_NOTES_INVALID" | "WORKFLOW_GRAPH_INVALID"
    ) {
        return None;
    }
    let message = payload.pointer("/error/details/message")?.as_str()?;
    (!message.is_empty() && message.len() <= MAX_AUTHORING_ERROR_MESSAGE_BYTES)
        .then(|| json!({"message": message}))
}
pub(crate) fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
pub(crate) fn hash(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
pub(crate) fn sign(key: &[u8; 32], message: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(SigningKey::from_bytes(key).sign(message).to_bytes())
}
pub(crate) fn key_proof(key: &[u8; 32], purpose: &str, secret: &str) -> String {
    let nonce = uuid::Uuid::new_v4().to_string();
    format!(
        "{}.{}",
        sign(
            key,
            format!("{purpose}:{}:{nonce}", hash(secret.as_bytes())).as_bytes()
        ),
        nonce
    )
}
fn request_proof(
    credential: &SignedCredential,
    method: &str,
    path: &str,
    body: &[u8],
    timestamp: u64,
    nonce: &str,
) -> Result<String, ApiError> {
    let prefix = credential
        .token
        .split('_')
        .nth(1)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| ApiError::new("AUTH_REQUIRED", false))?;
    let message = format!(
        "{method}|{path}|{}|{timestamp}|{nonce}|{prefix}|{}",
        hash(body),
        credential.subject
    );
    Ok(format!(
        "{timestamp}.{nonce}.{}",
        sign(&credential.private_key, message.as_bytes())
    ))
}
fn validate_origin(raw: &str, development: bool) -> anyhow::Result<Url> {
    let origin = Url::parse(raw).map_err(|_| anyhow::anyhow!("INVALID_API_ORIGIN"))?;
    let loopback = match origin.host() {
        Some(url::Host::Domain("localhost")) => true,
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        _ => false,
    };
    anyhow::ensure!(
        origin.username().is_empty()
            && origin.password().is_none()
            && origin.query().is_none()
            && origin.fragment().is_none()
            && origin.path() == "/"
            && origin.host().is_some(),
        "INVALID_API_ORIGIN"
    );
    anyhow::ensure!(
        if development {
            loopback && matches!(origin.scheme(), "http" | "https")
        } else {
            origin.scheme() == "https"
        },
        "INVALID_API_ORIGIN"
    );
    Ok(origin)
}
fn request_timeout(method: &str, route: &str) -> Duration {
    let path = route.split('?').next().unwrap_or(route);
    let resource_get = method == "GET"
        && ["v1/executions/", "v1/workflow-builder/sessions/"]
            .iter()
            .any(|prefix| {
                path.strip_prefix(prefix)
                    .and_then(|tail| tail.strip_suffix('/'))
                    .is_some_and(|id| !id.is_empty() && !id.contains('/'))
            });
    // This is the HTTP transport budget, never a deadline for executing a job.
    if (method == "POST" && path == "v1/jobs/lease/") || resource_get {
        Duration::from_secs(60)
    } else {
        Duration::from_secs(12)
    }
}
fn select_origin(
    compiled_origin: Option<&str>,
    development_origin: Option<&str>,
    debug_build: bool,
) -> anyhow::Result<Url> {
    if let Some(origin) = compiled_origin {
        anyhow::ensure!(development_origin.is_none(), "DEV_API_ORIGIN_FORBIDDEN");
        return validate_origin(origin, false);
    }
    anyhow::ensure!(debug_build, "CONFIGURATION_REQUIRED");
    validate_origin(
        development_origin.ok_or_else(|| anyhow::anyhow!("CONFIGURATION_REQUIRED"))?,
        true,
    )
}
impl Api {
    /// Explicit product destination; an API origin does not imply a web UI.
    pub fn web_app_url(&self) -> Option<String> {
        option_env!("LOOMEX_WEB_APP_ORIGIN")
            .and_then(|value| validate_origin(value, false).ok())
            .map(|url| url.to_string())
    }

    #[cfg(test)]
    pub(crate) fn for_test_origin(origin: &str) -> anyhow::Result<Self> {
        Self::with_origin(validate_origin(origin, true)?)
    }
    pub fn new() -> anyhow::Result<Self> {
        let development_origin = match std::env::var("LOOMEX_DEV_API_ORIGIN") {
            Ok(value) => Some(value),
            Err(std::env::VarError::NotPresent) => None,
            Err(_) => anyhow::bail!("INVALID_API_ORIGIN"),
        };
        let origin = select_origin(
            option_env!("LOOMEX_API_ORIGIN"),
            development_origin.as_deref(),
            cfg!(debug_assertions),
        )?;
        Self::with_origin(origin)
    }
    pub(crate) fn with_origin(origin: Url) -> anyhow::Result<Self> {
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .timeout(Duration::from_secs(12))
            .build()
            .map_err(|_| anyhow::anyhow!("API_CLIENT_UNAVAILABLE"))?;
        Ok(Self { client, origin })
    }
    pub(crate) fn verification_uri(&self, path: &str, user_code: &str) -> anyhow::Result<String> {
        anyhow::ensure!(
            path.starts_with('/') && !path.starts_with("//") && !path.contains('\\'),
            "INVALID_VERIFICATION_URI"
        );
        let mut url = self
            .origin
            .join(path)
            .map_err(|_| anyhow::anyhow!("INVALID_VERIFICATION_URI"))?;
        anyhow::ensure!(
            url.origin() == self.origin.origin(),
            "INVALID_VERIFICATION_URI"
        );
        url.query_pairs_mut().append_pair("userCode", user_code);
        Ok(url.into())
    }
    pub async fn request(
        &self,
        method: &str,
        route: &str,
        body: Option<Value>,
        credential: Option<&SignedCredential>,
        idempotency_key: Option<&str>,
    ) -> Result<Value, ApiError> {
        if !(route.starts_with("v1/") || route.starts_with("v2/"))
            || route.contains(['\\', '#'])
            || route
                .split('?')
                .next()
                .unwrap_or("")
                .split('/')
                .any(|s| s == ".." || s == "." || s.contains('%'))
        {
            return Err(ApiError::new("INVALID_API_ROUTE", false));
        }
        let url = self
            .origin
            .join(&format!("{BASE}{route}"))
            .map_err(|_| ApiError::new("INVALID_API_ROUTE", false))?;
        if url.origin() != self.origin.origin() || !url.path().starts_with(BASE) {
            return Err(ApiError::new("INVALID_API_ROUTE", false));
        }
        let method = reqwest::Method::from_bytes(method.as_bytes())
            .map_err(|_| ApiError::new("INVALID_API_METHOD", false))?;
        let bytes = body
            .map(|b| serde_json::to_vec(&b))
            .transpose()
            .map_err(|_| ApiError::new("INVALID_REQUEST_BODY", false))?
            .unwrap_or_default();
        let mut request = self
            .client
            .request(method.clone(), url.clone())
            .timeout(request_timeout(method.as_str(), route))
            .header("Accept", "application/json");
        if let Some(key) = idempotency_key {
            request = request.header("Idempotency-Key", key);
        }
        if let Some(credential) = credential {
            let path = match url.query() {
                Some(query) => format!("{}?{query}", url.path()),
                None => url.path().into(),
            };
            request = request.bearer_auth(&credential.token).header(
                "X-Loomex-Runner-Proof",
                request_proof(
                    credential,
                    method.as_str(),
                    &path,
                    &bytes,
                    now(),
                    &uuid::Uuid::new_v4().to_string(),
                )?,
            );
        }
        if !bytes.is_empty() {
            request = request
                .header("Content-Type", "application/json")
                .body(bytes);
        }
        let response = request
            .send()
            .await
            .map_err(|_| ApiError::new("NETWORK_UNAVAILABLE", true))?;
        let status = response.status().as_u16();
        if status == 202 {
            return Ok(json!({"pending":true}));
        }
        let payload = response.json::<Value>().await.map_err(|_| {
            ApiError::new(
                "INVALID_API_RESPONSE",
                status >= 500 || (200..300).contains(&status),
            )
        })?;
        parse_envelope(status, payload)
    }
}
fn parse_envelope(status: u16, payload: Value) -> Result<Value, ApiError> {
    if (200..300).contains(&status) {
        return payload
            .get("data")
            .cloned()
            .ok_or_else(|| ApiError::new("INVALID_API_RESPONSE", true));
    }
    let code = payload
        .pointer("/error/code")
        .or_else(|| payload.pointer("/errors/0/code"))
        .and_then(Value::as_str)
        .filter(|s| {
            !s.is_empty()
                && s.len() <= 100
                && s.bytes()
                    .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
        })
        .unwrap_or("API_REQUEST_FAILED");
    let mut error = ApiError::new(code, status >= 500 || status == 429 || status == 408);
    error.data = if code == "RUN_VALIDATION_FAILED" {
        safe_validation_data(&payload)
    } else {
        safe_authoring_error_data(code, &payload)
    };
    Err(error)
}
#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signature, Verifier};
    #[test]
    fn transport_timeout_allows_long_poll_without_extending_auth_recovery() {
        for (method, route) in [
            ("POST", "v1/jobs/lease/"),
            ("GET", "v1/executions/run-id/?timeoutSeconds=45"),
            (
                "GET",
                "v1/workflow-builder/sessions/session-id/?timeoutSeconds=45",
            ),
        ] {
            assert_eq!(request_timeout(method, route), Duration::from_secs(60));
        }
        for (method, route) in [
            ("POST", "v2/device-authorities/bootstrap/"),
            ("POST", "v2/device-authorities/refresh/"),
            ("POST", "v1/delegations/refresh/"),
            ("POST", "v2/organizations/org/enroll/"),
            ("GET", "v1/jobs/lease/"),
            ("POST", "v1/executions/run-id/cancel/"),
            ("GET", "v1/executions/run-id/human-requests/"),
            ("GET", "v2/executions/"),
        ] {
            assert_eq!(request_timeout(method, route), Duration::from_secs(12));
        }
    }
    #[test]
    fn production_origin_is_pinned_and_development_requires_debug_build() {
        for debug in [false, true] {
            let pinned = select_origin(Some("https://api.example.com"), None, debug).unwrap();
            assert_eq!(pinned.as_str(), "https://api.example.com/");
            assert_eq!(
                select_origin(
                    Some("https://api.example.com"),
                    Some("http://127.0.0.1:9000"),
                    debug
                )
                .unwrap_err()
                .to_string(),
                "DEV_API_ORIGIN_FORBIDDEN"
            );
            assert!(select_origin(Some("http://api.example.com"), None, debug).is_err());
            assert_eq!(
                select_origin(None, None, debug).unwrap_err().to_string(),
                "CONFIGURATION_REQUIRED"
            );
        }
        assert_eq!(
            select_origin(None, Some("http://127.0.0.1:9000"), false)
                .unwrap_err()
                .to_string(),
            "CONFIGURATION_REQUIRED"
        );
        assert!(select_origin(None, Some("http://127.0.0.1:9000"), true).is_ok());
        assert!(select_origin(None, Some("https://external.example.com"), true).is_err());
    }
    #[test]
    fn proof_binds_exact_request() {
        let credential = SignedCredential {
            token: "lmxda_PREFIX_SECRET".into(),
            subject: "device".into(),
            private_key: [7; 32],
        };
        let proof = request_proof(&credential, "POST", "/x/?b=2&a=1", b"{}", 123, "nonce").unwrap();
        let signature = Signature::from_slice(
            &URL_SAFE_NO_PAD
                .decode(proof.split('.').nth(2).unwrap())
                .unwrap(),
        )
        .unwrap();
        let expected = format!("POST|/x/?b=2&a=1|{}|123|nonce|PREFIX|device", hash(b"{}"));
        let public = SigningKey::from_bytes(&credential.private_key).verifying_key();
        public.verify(expected.as_bytes(), &signature).unwrap();
        assert!(
            public
                .verify(
                    expected.replace("b=2&a=1", "a=1&b=2").as_bytes(),
                    &signature
                )
                .is_err()
        );
    }
    #[test]
    fn origin_restrictions() {
        assert!(validate_origin("http://example.com", false).is_err());
        assert!(validate_origin("https://example.com", true).is_err());
        assert!(validate_origin("http://127.0.0.1:8080", true).is_ok());
        assert!(validate_origin("https://user:pass@example.com", false).is_err());
    }
    #[test]
    fn envelope_and_safe_error() {
        assert_eq!(
            parse_envelope(200, json!({"data":{"a":1},"meta":{}})).unwrap(),
            json!({"a":1})
        );
        assert!(parse_envelope(200, json!({"a":1})).unwrap_err().retryable);
        assert_eq!(
            parse_envelope(401, json!({"error":{"code":"secret token"}}))
                .unwrap_err()
                .code,
            "API_REQUEST_FAILED"
        );
    }

    #[test]
    fn run_validation_errors_project_only_allowlisted_actionable_issues() {
        let node_id = "11111111-1111-4111-8111-111111111111";
        let error = parse_envelope(
            422,
            json!({
                "error": {
                    "code": "RUN_VALIDATION_FAILED",
                    "message": "Bearer backend-message-must-not-cross",
                    "details": {
                        "validationIssueVersion": "v1",
                        "validationIssues": [
                            {
                                "code": "RUN_VALIDATION_PROVIDER_UNSUPPORTED",
                                "message": "Bearer issue-message-must-not-cross",
                                "nextAction": "exfiltrate_credentials",
                                "nodeId": node_id,
                                "nodeIndex": 2,
                                "nodeName": "Bearer arbitrary-node-name"
                            },
                            {
                                "code": "RUN_VALIDATION_POLICY_DENIED",
                                "nodeName": "Bearer secret-node-name"
                            },
                            {
                                "code": "BACKEND_PRIVATE_VALIDATION_CODE",
                                "message": "private detail"
                            }
                        ],
                        "authorization": "Bearer never-print-this-token",
                        "providerConfig": {"apiKey": "sk-never-print-this"}
                    }
                }
            }),
        )
        .unwrap_err();

        assert_eq!(error.code, "RUN_VALIDATION_FAILED");
        assert!(!error.retryable);
        assert_eq!(
            error.data,
            Some(json!({
                "validationIssueVersion": "v1",
                "validationIssues": [
                    {
                        "code": "RUN_VALIDATION_PROVIDER_UNSUPPORTED",
                        "message": "The selected provider does not support a required workflow capability.",
                        "nextAction": "choose_supported_provider",
                        "nodeIndex": 2
                    },
                    {
                        "code": "RUN_VALIDATION_POLICY_DENIED",
                        "message": "The execution policy does not allow a required workflow capability.",
                        "nextAction": "allow_capability"
                    }
                ]
            }))
        );
        let serialized = serde_json::to_string(&error.data).unwrap();
        assert!(!serialized.contains("never-print"));
        assert!(!serialized.contains("exfiltrate"));
        assert!(!serialized.contains("private detail"));
        assert!(!serialized.contains(node_id));
        assert!(!serialized.contains("arbitrary-node-name"));
        assert!(!serialized.contains("secret-node-name"));
    }

    #[test]
    fn non_validation_errors_never_project_backend_details() {
        let error = parse_envelope(
            503,
            json!({
                "error": {
                    "code": "BACKEND_UNAVAILABLE",
                    "details": {
                        "validationIssueVersion": "v1",
                        "validationIssues": [{
                            "code": "RUN_VALIDATION_PROVIDER_UNSUPPORTED",
                            "message": "Bearer never-print-this-token"
                        }],
                        "credential": "secret-never-print"
                    }
                }
            }),
        )
        .unwrap_err();
        assert!(error.data.is_none());
    }

    #[test]
    fn run_validation_issue_projection_requires_the_known_issue_version() {
        for version in [None, Some("v2")] {
            let mut details = json!({
                "validationIssues": [{
                    "code": "RUN_VALIDATION_PROVIDER_UNSUPPORTED",
                    "nodeIndex": 2,
                    "nodeName": "Bearer arbitrary-node-name"
                }]
            });
            if let Some(version) = version {
                details["validationIssueVersion"] = json!(version);
            }
            let error = parse_envelope(
                422,
                json!({
                    "error": {
                        "code": "RUN_VALIDATION_FAILED",
                        "details": details
                    }
                }),
            )
            .unwrap_err();
            assert!(error.data.is_none());
        }
    }

    #[test]
    fn workflow_authoring_errors_preserve_only_the_canonical_message() {
        for code in [
            "WORKFLOW_DEFINITION_REQUIRED",
            "WORKFLOW_NOTES_INVALID",
            "WORKFLOW_GRAPH_INVALID",
        ] {
            let error = parse_envelope(
                422,
                json!({
                    "error": {
                        "code": code,
                        "message": "untrusted backend summary",
                        "details": {
                            "message": "The workflow graph has an invalid transition.",
                            "authorization": "Bearer never-print-this-token",
                            "definition": {"secret": "never-forward"}
                        }
                    }
                }),
            )
            .unwrap_err();
            assert_eq!(error.code, code);
            assert_eq!(
                error.data,
                Some(json!({"message": "The workflow graph has an invalid transition."}))
            );
        }

        let error = parse_envelope(
            422,
            json!({"error": {"code": "WORKFLOW_GRAPH_INVALID", "details": {"message": "x".repeat(MAX_AUTHORING_ERROR_MESSAGE_BYTES + 1)}}}),
        )
        .unwrap_err();
        assert!(error.data.is_none());
    }
}
