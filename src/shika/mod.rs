//! Isolated Shika credential primitives. No local RPC is exposed here.
#![allow(dead_code)]

mod journal;
mod proof;
mod service;
mod store;
mod transport;
mod w3;
mod wire;

#[derive(Debug)]
pub(crate) struct LocalDenial {
    data: serde_json::Value,
    code: &'static str,
}
impl std::fmt::Display for LocalDenial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code)
    }
}
impl std::error::Error for LocalDenial {}
impl LocalDenial {
    pub(crate) fn data(&self) -> &serde_json::Value {
        &self.data
    }
    pub(crate) fn code(&self) -> &'static str {
        self.code
    }
}

pub(crate) async fn dispatch(
    method: &str,
    params: &serde_json::Value,
    auth: &crate::auth::Auth,
) -> anyhow::Result<serde_json::Value> {
    service::dispatch(method, params, auth).await
}

use anyhow::{Result, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::SigningKey;
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use url::Url;
use uuid::Uuid;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PendingPairing {
    device_id: Uuid,
    operation_key: Uuid,
    private_key: [u8; 32],
    verifier: String,
    state: String,
    // Exact serialized public request retained before dispatch.
    request: Option<Vec<u8>>,
    pairing_id: Option<Uuid>,
    actor_id: Option<Uuid>,
    workspace_id: Option<Uuid>,
    api_origin: String,
    ui_origin: String,
    created_at: Option<String>,
    expires_at: Option<String>,
}

impl PendingPairing {
    fn generate(device_id: Uuid, operation_key: Uuid) -> Self {
        let mut key = [0; 32];
        let mut verifier = [0; 32];
        let mut state = [0; 32];
        OsRng.fill_bytes(&mut key);
        OsRng.fill_bytes(&mut verifier);
        OsRng.fill_bytes(&mut state);
        Self {
            device_id,
            operation_key,
            private_key: key,
            verifier: URL_SAFE_NO_PAD.encode(verifier),
            state: URL_SAFE_NO_PAD.encode(state),
            request: None,
            pairing_id: None,
            actor_id: None,
            workspace_id: None,
            api_origin: String::new(),
            ui_origin: String::new(),
            created_at: None,
            expires_at: None,
        }
    }
    fn bind_request(&mut self, request: Vec<u8>) -> Result<()> {
        ensure!(self.request.is_none(), "SHIKA_RECOVERY_REQUIRED");
        self.request = Some(request);
        Ok(())
    }
    fn public_key(&self) -> [u8; 32] {
        SigningKey::from_bytes(&self.private_key)
            .verifying_key()
            .to_bytes()
    }
    fn challenge(&self) -> String {
        URL_SAFE_NO_PAD.encode(Sha256::digest(self.verifier.as_bytes()))
    }
    fn state_hash(&self) -> String {
        hex::encode(Sha256::digest(self.state.as_bytes()))
    }
    fn browser_url(&self, ui: &Origin) -> Result<String> {
        let id = self
            .pairing_id
            .ok_or_else(|| anyhow::anyhow!("PAIRING_UNAVAILABLE"))?;
        Ok(format!("{}/#/pairing/{}?state={}", ui.0, id, self.state))
    }
}

// Persist before sending. A caller must load an existing record rather than
// replace it, including after an uncertain response or a failed final save.
fn persist_new(store: &dyn store::Store, state: &journal::Journal) -> Result<()> {
    state.validate()?;
    ensure!(store.load()?.is_none(), "SHIKA_RECOVERY_REQUIRED");
    let bytes = serde_json::to_vec(state).map_err(|_| anyhow::anyhow!("SHIKA_STORE_INVALID"))?;
    store.save(&bytes)
}
fn load_state(store: &dyn store::Store) -> Result<Option<journal::Journal>> {
    store
        .load()?
        .map(|bytes| {
            let state: journal::Journal = serde_json::from_slice(&bytes)
                .map_err(|_| anyhow::anyhow!("SHIKA_STORE_INVALID"))?;
            state.validate()?;
            Ok(state)
        })
        .transpose()
}

/// A canonical origin must be specified exactly, avoiding URL parser normalization
/// that would otherwise make configured trust pairs ambiguous.
#[derive(Clone, PartialEq, Eq)]
struct Origin(String);
impl Origin {
    fn parse(raw: &str, allow_loopback_http: bool) -> Result<Self> {
        ensure!(
            !raw.is_empty() && raw.chars().count() <= 512,
            "INVALID_ORIGIN"
        );
        let url = Url::parse(raw).map_err(|_| anyhow::anyhow!("INVALID_ORIGIN"))?;
        let loopback = match url.host() {
            Some(url::Host::Domain(host)) => host == "localhost",
            Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
            Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
            _ => false,
        };
        ensure!(
            url.username().is_empty()
                && url.password().is_none()
                && url.host().is_some()
                && url.path() == "/"
                && url.query().is_none()
                && url.fragment().is_none()
                && (url.scheme() == "https"
                    || (allow_loopback_http && loopback && url.scheme() == "http"))
                && raw == url.origin().ascii_serialization(),
            "INVALID_ORIGIN"
        );
        Ok(Self(raw.to_owned()))
    }
}

struct TrustedOrigins {
    api: Origin,
    ui: Origin,
}
impl TrustedOrigins {
    fn from_config(api: &str, ui: &str, allow_loopback_http: bool) -> Result<Self> {
        Ok(Self {
            api: Origin::parse(api, allow_loopback_http)?,
            ui: Origin::parse(ui, allow_loopback_http)?,
        })
    }
    fn require_pair(&self, api: &str, ui: &str) -> Result<()> {
        ensure!(
            self.api.0 == api && self.ui.0 == ui,
            "SHIKA_UNTRUSTED_ORIGIN"
        );
        Ok(())
    }
    fn from_environment() -> Result<Self> {
        let api =
            std::env::var("SHIKA_API_ORIGIN").map_err(|_| anyhow::anyhow!("SHIKA_UNAVAILABLE"))?;
        let ui =
            std::env::var("SHIKA_UI_ORIGIN").map_err(|_| anyhow::anyhow!("SHIKA_UNAVAILABLE"))?;
        let allow = match std::env::var("SHIKA_ALLOW_LOOPBACK_HTTP") {
            Ok(v) if v == "true" => true,
            Ok(v) if v == "false" => false,
            _ => return Err(anyhow::anyhow!("SHIKA_UNAVAILABLE")),
        };
        Self::from_config(&api, &ui, allow)
    }
}

#[cfg(test)]
mod tests;

#[cfg(all(test, target_os = "macos"))]
mod native_custody;
