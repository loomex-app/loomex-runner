//! Strict server projections; no secret or proof is serializable here.
use super::{Origin, PendingPairing, journal::Binding};
use anyhow::{Result, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Pairing {
    pub schema_version: String,
    pub pairing_id: String,
    pub operation_key: String,
    pub origin: String,
    pub device_id: String,
    pub installation_id: String,
    pub proof_key_thumbprint: String,
    pub code_challenge: String,
    pub created_at: String,
    pub expires_at: String,
    pub status: String,
    #[serde(deserialize_with = "required_optional")]
    pub actor_id: Option<String>,
    #[serde(deserialize_with = "required_optional")]
    pub workspace_id: Option<String>,
    #[serde(deserialize_with = "required_optional")]
    pub exchange_operation_key: Option<String>,
}
fn required_optional<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Option<String>, D::Error> {
    Option::<String>::deserialize(deserializer)
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct PairingEnvelope {
    pub pairing: Pairing,
    pub revision: u64,
    pub ui_origin: String,
    pub requested_scopes: Vec<String>,
    #[serde(deserialize_with = "required_optional_revision")]
    pub approval_revision: Option<u64>,
    pub reapproval_required: bool,
}
fn required_optional_revision<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Option<u64>, D::Error> {
    Option::<u64>::deserialize(deserializer)
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Connection {
    pub schema_version: String,
    pub connection_id: String,
    pub revision: u64,
    pub origin: String,
    pub actor_id: String,
    pub workspace_id: String,
    pub device_id: String,
    pub installation_id: String,
    pub proof_key_thumbprint: String,
    pub credential_revision: u64,
    pub status: String,
    pub scopes: Vec<String>,
}
fn uuid(value: &str) -> bool {
    uuid::Uuid::parse_str(value).is_ok_and(|v| v.to_string() == value)
}
fn scopes(value: &[String]) -> bool {
    !value.is_empty()
        && value.len() <= 3
        && value
            .iter()
            .all(|s| matches!(s.as_str(), "shika.read" | "shika.write" | "shika.execute"))
        && value
            .iter()
            .enumerate()
            .all(|(i, s)| !value[..i].contains(s))
}
pub(super) fn same_scopes(left: &[String], right: &[String]) -> bool {
    scopes(left)
        && scopes(right)
        && left.len() == right.len()
        && left.iter().all(|s| right.contains(s))
}
fn hex_hash(public_key: &[u8; 32]) -> String {
    hex::encode(Sha256::digest(public_key))
}
fn second(s: &str) -> Option<time::OffsetDateTime> {
    if s.len() != 20 || !s.ends_with('Z') {
        return None;
    }
    time::OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339).ok()
}
impl PairingEnvelope {
    pub(super) fn validate(
        &self,
        pending: &PendingPairing,
        api: &Origin,
        ui: &Origin,
        installation: &str,
        requested: &[String],
    ) -> Result<()> {
        let p = &self.pairing;
        ensure!(
            p.schema_version == "shika.pairing/v1"
                && uuid(&p.pairing_id)
                && uuid(&p.operation_key)
                && p.operation_key == pending.operation_key.to_string()
                && p.device_id == pending.device_id.to_string()
                && p.origin == api.0
                && self.ui_origin == ui.0
                && p.installation_id == installation
                && p.proof_key_thumbprint == hex_hash(&pending.public_key())
                && p.code_challenge == pending.challenge()
                && self.revision > 0
                && self.revision <= 9_007_199_254_740_991
                && same_scopes(&self.requested_scopes, requested)
                && matches!(
                    p.status.as_str(),
                    "pending" | "approved" | "consumed" | "cancelled" | "expired"
                )
                && p.actor_id.as_deref().is_none_or(uuid)
                && p.workspace_id.as_deref().is_none_or(uuid)
                && p.actor_id.is_some() == p.workspace_id.is_some()
                && p.exchange_operation_key.as_deref().is_none_or(uuid),
            "SHIKA_RESPONSE_INVALID"
        );
        let created =
            second(&p.created_at).ok_or_else(|| anyhow::anyhow!("SHIKA_RESPONSE_INVALID"))?;
        let expires =
            second(&p.expires_at).ok_or_else(|| anyhow::anyhow!("SHIKA_RESPONSE_INVALID"))?;
        ensure!(
            expires - created == time::Duration::seconds(600),
            "SHIKA_RESPONSE_INVALID"
        );
        ensure!(
            self.approval_revision
                .is_none_or(|r| r > 0 && r <= self.revision)
                && (!matches!(p.status.as_str(), "approved" | "consumed")
                    || self.approval_revision.is_some())
                && (!matches!(p.status.as_str(), "approved" | "consumed") || p.actor_id.is_some())
                && (p.status != "pending"
                    || (p.actor_id.is_none() && self.approval_revision.is_none()))
                && (!self.reapproval_required || p.status == "approved"),
            "SHIKA_RESPONSE_INVALID"
        );
        if let Some(id) = pending.pairing_id {
            ensure!(p.pairing_id == id.to_string(), "SHIKA_RESPONSE_INVALID");
        }
        if let Some(created) = &pending.created_at {
            ensure!(&p.created_at == created, "SHIKA_RESPONSE_INVALID");
        }
        if let Some(expires) = &pending.expires_at {
            ensure!(&p.expires_at == expires, "SHIKA_RESPONSE_INVALID");
        }
        if let Some(id) = pending.actor_id {
            ensure!(
                p.actor_id.as_deref() == Some(id.to_string().as_str()),
                "SHIKA_IDENTITY_CHANGED"
            );
        }
        if let Some(id) = pending.workspace_id {
            ensure!(
                p.workspace_id.as_deref() == Some(id.to_string().as_str()),
                "SHIKA_IDENTITY_CHANGED"
            );
        }
        Ok(())
    }
}
impl Connection {
    pub(super) fn validate(
        &self,
        binding: &Binding,
        public_key: &[u8; 32],
        approved_scopes: &[String],
    ) -> Result<()> {
        ensure!(
            self.schema_version == "shika.connection/v1"
                && uuid(&self.connection_id)
                && uuid(&self.actor_id)
                && uuid(&self.workspace_id)
                && self.origin == binding.api_origin
                && self.device_id == binding.device_id.to_string()
                && self.installation_id == binding.installation_id
                && binding
                    .actor_id
                    .is_some_and(|v| v.to_string() == self.actor_id)
                && binding
                    .workspace_id
                    .is_some_and(|v| v.to_string() == self.workspace_id)
                && binding
                    .connection_id
                    .is_none_or(|v| v.to_string() == self.connection_id)
                && self.proof_key_thumbprint == hex_hash(public_key)
                && self.revision > 0
                && self.revision <= 9_007_199_254_740_991
                && self.credential_revision > 0
                && self.credential_revision <= 9_007_199_254_740_991
                && matches!(
                    self.status.as_str(),
                    "active" | "refreshing" | "revoked" | "expired"
                )
                && same_scopes(&self.scopes, approved_scopes),
            "SHIKA_RESPONSE_INVALID"
        );
        Ok(())
    }
}
pub(super) fn public_key_text(key: &[u8; 32]) -> String {
    URL_SAFE_NO_PAD.encode(key)
}
