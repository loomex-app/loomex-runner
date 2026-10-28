//! W3 typed fingerprints; never fingerprint serialized JSON text.
use anyhow::{Result, ensure};
use serde_json::Value;
use sha2::{Digest, Sha256};

fn append(value: &Value, depth: usize, out: &mut Vec<u8>) -> Result<()> {
    ensure!(depth <= 64, "SHIKA_INVALID_REQUEST");
    match value {
        Value::Null => out.extend_from_slice(b"n;"),
        Value::Bool(value) => out.extend_from_slice(if *value { b"t;" } else { b"f;" }),
        Value::Number(number) => {
            let mut n = number
                .as_f64()
                .ok_or_else(|| anyhow::anyhow!("SHIKA_INVALID_REQUEST"))?;
            ensure!(
                n.is_finite() && n.abs() <= 9_007_199_254_740_991.0,
                "SHIKA_INVALID_REQUEST"
            );
            if n == 0.0 {
                n = 0.0;
            }
            out.push(b'd');
            out.extend_from_slice(hex::encode(n.to_bits().to_be_bytes()).as_bytes());
            out.push(b';');
        }
        Value::String(value) => {
            out.extend_from_slice(format!("s{}:", value.len()).as_bytes());
            out.extend_from_slice(value.as_bytes());
        }
        Value::Array(values) => {
            out.extend_from_slice(format!("a{}:[", values.len()).as_bytes());
            for child in values {
                append(child, depth + 1, out)?;
            }
            out.push(b']');
        }
        Value::Object(values) => {
            out.extend_from_slice(format!("o{}:{{", values.len()).as_bytes());
            let mut keys: Vec<_> = values.keys().collect();
            keys.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
            for key in keys {
                append(&Value::String(key.clone()), depth + 1, out)?;
                append(&values[key], depth + 1, out)?;
            }
            out.push(b'}');
        }
    }
    Ok(())
}
pub(super) fn encode(value: &Value) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    append(value, 0, &mut out)?;
    Ok(out)
}
pub(super) fn fingerprint(value: &Value) -> Result<String> {
    Ok(hex::encode(Sha256::digest(encode(value)?)))
}

pub(super) fn operation_fingerprint(operation: &super::journal::Operation) -> Result<String> {
    use super::journal::Kind;
    use serde_json::json;
    ensure!(
        operation.method == "POST" && operation.body.len() <= 16384,
        "SHIKA_STORE_INVALID"
    );
    let body: Value = serde_json::from_slice(&operation.body)
        .map_err(|_| anyhow::anyhow!("SHIKA_STORE_INVALID"))?;
    ensure!(
        body["operationKey"].as_str() == Some(operation.operation_key.to_string().as_str()),
        "SHIKA_STORE_INVALID"
    );
    let mut preconditions = serde_json::Map::new();
    match operation.kind {
        Kind::Start => ensure!(
            operation.target == "/api/v2/pairings/" && operation.if_match.is_none(),
            "SHIKA_STORE_INVALID"
        ),
        Kind::Cancel | Kind::Exchange | Kind::Refresh | Kind::Revoke => {
            let (prefix, suffix, resource) = match operation.kind {
                Kind::Cancel => ("/api/v2/pairings/", "/cancel/", "pairing"),
                Kind::Exchange => ("/api/v2/pairings/", "/exchange/", "pairing"),
                Kind::Refresh => ("/api/v2/connections/", "/refresh/", "connection"),
                Kind::Revoke => ("/api/v2/connections/", "/revoke/", "connection"),
                Kind::Start => unreachable!(),
            };
            let id = operation
                .target
                .strip_prefix(prefix)
                .and_then(|v| v.strip_suffix(suffix))
                .ok_or_else(|| anyhow::anyhow!("SHIKA_STORE_INVALID"))?;
            let parsed =
                uuid::Uuid::parse_str(id).map_err(|_| anyhow::anyhow!("SHIKA_STORE_INVALID"))?;
            let revision = body["expectedRevision"]
                .as_u64()
                .filter(|v| *v > 0 && *v <= 9_007_199_254_740_991)
                .ok_or_else(|| anyhow::anyhow!("SHIKA_STORE_INVALID"))?;
            ensure!(
                parsed.to_string() == id
                    && operation.if_match.as_deref()
                        == Some(format!("\"{resource}:{id}:{revision}\"").as_str()),
                "SHIKA_STORE_INVALID"
            );
            preconditions.insert(format!("{resource}:{id}"), json!(revision));
        }
    }
    fingerprint(
        &json!({"method":operation.method,"path":operation.target,"query":{},"preconditions":preconditions,"body":body}),
    )
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DenialResponse {
    schema_version: String,
    status: u16,
    code: String,
    message: String,
    request_id: String,
    violations: Vec<Violation>,
    current_revision: Option<u64>,
    details: DenialDetails,
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Violation {
    path: String,
    code: String,
    message: String,
}
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DenialDetails {
    operation_receipt: DenialReceipt,
}
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DenialReceipt {
    schema_version: String,
    operation_kind: String,
    operation_key: String,
    request_hash: String,
    terminal: bool,
    committed: bool,
    error_code: String,
}

/// A receipt is definitive only when its complete closed schema and the
/// locally computed typed request fingerprint match the retained operation.
pub(super) fn verified_denial(
    status: u16,
    bytes: &[u8],
    operation: &super::journal::Operation,
) -> Result<Option<(String, String)>> {
    use super::journal::Kind;
    if !matches!(status, 409 | 412) {
        return Ok(None);
    }
    let Ok(error) = serde_json::from_slice::<DenialResponse>(bytes) else {
        return Ok(None);
    };
    let receipt = error.details.operation_receipt;
    let allowed = match status {
        409 => matches!(
            error.code.as_str(),
            "approval_snapshot_changed" | "needs_attention" | "active_execution"
        ),
        412 => matches!(error.code.as_str(), "revision_conflict" | "context_changed"),
        _ => false,
    };
    let kind = match operation.kind {
        Kind::Start => "pairing_start",
        Kind::Cancel => "pairing_cancel",
        Kind::Exchange => "pairing_exchange",
        Kind::Refresh => "connection_refresh",
        Kind::Revoke => "connection_revoke",
    };
    let valid_request_id =
        uuid::Uuid::parse_str(&error.request_id).is_ok_and(|id| id.to_string() == error.request_id);
    let valid_violations = error.violations.iter().all(|v| {
        !v.code.is_empty()
            && v.code.len() <= 80
            && v.code.bytes().enumerate().all(|(i, c)| {
                if i == 0 {
                    c.is_ascii_lowercase()
                } else {
                    c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_'
                }
            })
            && v.path.is_char_boundary(v.path.len())
            && v.message.is_char_boundary(v.message.len())
    });
    let hash = operation_fingerprint(operation)?;
    let valid = error.schema_version == "2.0"
        && error.status == status
        && allowed
        && valid_request_id
        && valid_violations
        && error
            .current_revision
            .is_none_or(|v| status == 412 && v > 0 && v <= 9_007_199_254_740_991)
        && receipt.schema_version == "shika.pairing-denial/v1"
        && receipt.operation_kind == kind
        && receipt.operation_key == operation.operation_key.to_string()
        && receipt.request_hash == hash
        && receipt.terminal
        && !receipt.committed
        && receipt.error_code == error.code
        && (error.code != "approval_snapshot_changed" || matches!(operation.kind, Kind::Exchange));
    let _ = error.message;
    if valid {
        Ok(Some((error.code, hash)))
    } else {
        Ok(None)
    }
}
