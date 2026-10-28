//! Fixed-route HTTP transport. The caller owns response validation and journal
//! transitions; this transport does not treat an HTTP response as authority.
use super::{Origin, proof};
use anyhow::{Result, ensure};
use std::time::Duration;
use uuid::Uuid;

pub(super) enum Route {
    Start,
    Pairing(Uuid),
    Cancel(Uuid),
    Exchange(Uuid),
    Connection(Uuid),
    Refresh(Uuid),
    Revoke(Uuid),
}
impl Route {
    fn path(&self) -> String {
        match self {
            Self::Start => "/api/v2/pairings/".into(),
            Self::Pairing(id) => format!("/api/v2/pairings/{id}/"),
            Self::Cancel(id) => format!("/api/v2/pairings/{id}/cancel/"),
            Self::Exchange(id) => format!("/api/v2/pairings/{id}/exchange/"),
            Self::Connection(id) => format!("/api/v2/connections/{id}/"),
            Self::Refresh(id) => format!("/api/v2/connections/{id}/refresh/"),
            Self::Revoke(id) => format!("/api/v2/connections/{id}/revoke/"),
        }
    }
    fn method(&self) -> &'static str {
        match self {
            Self::Pairing(_) | Self::Connection(_) => "GET",
            _ => "POST",
        }
    }
}
pub(super) struct Transport {
    client: reqwest::Client,
    origin: Origin,
}
pub(super) struct RequestBody<'a> {
    pub(super) body: &'a [u8],
    pub(super) operation: Option<Uuid>,
    pub(super) if_match: Option<&'a str>,
}
impl Transport {
    pub(super) fn new(origin: Origin) -> Result<Self> {
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .timeout(Duration::from_secs(15))
            .build()
            .map_err(|_| anyhow::anyhow!("SHIKA_UNAVAILABLE"))?;
        Ok(Self { client, origin })
    }
    pub(super) async fn send(
        &self,
        route: Route,
        key: &[u8; 32],
        key_id: &str,
        request: RequestBody<'_>,
        timestamp: u64,
    ) -> Result<(u16, Vec<u8>)> {
        let RequestBody {
            body,
            operation,
            if_match,
        } = request;
        let target = route.path();
        let method = route.method();
        ensure!(
            body.len() <= 16384
                && (method != "GET"
                    || (body.is_empty() && operation.is_none() && if_match.is_none())),
            "SHIKA_INVALID_REQUEST"
        );
        ensure!(
            method == "GET" || operation.is_some(),
            "SHIKA_INVALID_REQUEST"
        );
        ensure!(
            matches!(
                route,
                Route::Start | Route::Pairing(_) | Route::Connection(_)
            ) == if_match.is_none(),
            "SHIKA_INVALID_REQUEST"
        );
        let proof = proof::sign(key, key_id, method, &self.origin, &target, body, timestamp)?;
        let mut req = self
            .client
            .request(
                reqwest::Method::from_bytes(method.as_bytes())
                    .map_err(|_| anyhow::anyhow!("SHIKA_INVALID_REQUEST"))?,
                format!("{}{target}", self.origin.0),
            )
            .header("X-Shika-Key-Id", proof.key_id)
            .header("X-Shika-Proof", proof.value);
        if let Some(id) = operation {
            req = req.header("Idempotency-Key", id.to_string());
        }
        if let Some(value) = if_match {
            req = req.header("If-Match", value);
        }
        if method == "POST" {
            req = req
                .header("Content-Type", "application/json")
                .body(body.to_vec());
        }
        let mut response = req
            .send()
            .await
            .map_err(|_| anyhow::anyhow!("SHIKA_UNAVAILABLE"))?;
        let status = response.status().as_u16();
        ensure!(!(300..400).contains(&status), "SHIKA_UNAVAILABLE");
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| anyhow::anyhow!("SHIKA_UNAVAILABLE"))?
        {
            ensure!(
                bytes.len().saturating_add(chunk.len()) <= 65536,
                "SHIKA_UNAVAILABLE"
            );
            bytes.extend_from_slice(&chunk);
        }
        Ok((status, bytes))
    }
}
