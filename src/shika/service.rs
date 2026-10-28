use super::{
    PendingPairing, TrustedOrigins,
    journal::{Binding, Journal, Kind, Operation},
    store::{self, Store},
    transport::{RequestBody, Route, Transport},
    wire::PairingEnvelope,
};
use anyhow::{Result, ensure};
use serde_json::{Value, json};
use uuid::Uuid;

pub(super) trait Context: Send + Sync {
    fn store(&self) -> &dyn Store;
    fn marker(&self) -> Result<bool>;
    fn ensure_marker(&self) -> Result<()>;
}
struct NativeContext(store::NativeStore);
impl Context for NativeContext {
    fn store(&self) -> &dyn Store {
        &self.0
    }
    fn marker(&self) -> Result<bool> {
        store::enrollment_marker()
    }
    fn ensure_marker(&self) -> Result<()> {
        store::ensure_enrollment_marker()
    }
}

pub(super) async fn dispatch(
    method: &str,
    params: &Value,
    auth: &crate::auth::Auth,
) -> Result<Value> {
    // The account-scoped lock and selected credential snapshot are acquired
    // before awaiting Loomex installation identity, then held until completion.
    let _owner = store::acquire_owner()?;
    let context = NativeContext(store::NativeStore);
    let captured = super::load_state(context.store())?;
    let config = TrustedOrigins::from_environment()?;
    let installation = auth.existing_installation().await?;
    if let Some(state) = captured {
        ensure!(
            state.installation_id == installation.id(),
            "SHIKA_IDENTITY_CHANGED"
        );
    }
    installation.verify().await?;
    let result = match method {
        "shika.v2.pairing.start" => {
            pairing_start_with(&context, config, params, installation.id()).await
        }
        "shika.v2.pairing.get" => {
            pairing_get_with(&context, config, params, installation.id()).await
        }
        "shika.v2.pairing.cancel" => {
            pairing_cancel_with(&context, config, params, installation.id()).await
        }
        "shika.v2.pairing.exchange" => {
            pairing_exchange_with(&context, config, params, installation.id()).await
        }
        "shika.v2.connection.get" => connection_get_with(&context, config, installation.id()).await,
        "shika.v2.connection.revoke" => {
            connection_revoke_with(&context, config, params, installation.id()).await
        }
        "shika.v2.connection.refresh" => {
            connection_refresh_with(&context, config, params, installation.id()).await
        }
        _ => Err(anyhow::anyhow!("METHOD_NOT_FOUND")),
    };
    installation.verify().await?;
    match result {
        Err(error) => match error.downcast_ref::<VerifiedDenial>() {
            Some(denial) => Err(local_denial(method, params, denial)?.into()),
            None => Err(error),
        },
        ok => ok,
    }
}

#[derive(Debug)]
pub(super) struct VerifiedDenial {
    pub(super) kind: Kind,
    pub(super) operation_key: Uuid,
    pub(super) request_hash: String,
    pub(super) error_code: String,
    pub(super) public_params: Value,
}
impl std::fmt::Display for VerifiedDenial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(local_code(&self.error_code))
    }
}
impl std::error::Error for VerifiedDenial {}
fn local_code(code: &str) -> &'static str {
    match code {
        "approval_snapshot_changed" => "SHIKA_APPROVAL_CHANGED",
        "revision_conflict" | "context_changed" => "SHIKA_REVISION_CONFLICT",
        _ => "SHIKA_OPERATION_DENIED",
    }
}
pub(super) fn local_denial(
    method: &str,
    params: &Value,
    denial: &VerifiedDenial,
) -> Result<super::LocalDenial> {
    let backend_kind = match (method, denial.kind) {
        ("shika.v2.pairing.start", Kind::Start) => "pairing_start",
        ("shika.v2.pairing.cancel", Kind::Cancel) => "pairing_cancel",
        ("shika.v2.pairing.exchange", Kind::Exchange) => "pairing_exchange",
        ("shika.v2.connection.refresh", Kind::Refresh) => "connection_refresh",
        ("shika.v2.connection.revoke", Kind::Revoke) => "connection_revoke",
        _ => return Err(anyhow::anyhow!("SHIKA_RECOVERY_REQUIRED")),
    };
    ensure!(
        params == &denial.public_params
            && id(params, "operationKey")? == denial.operation_key
            && matches!(
                denial.error_code.as_str(),
                "approval_snapshot_changed"
                    | "needs_attention"
                    | "active_execution"
                    | "revision_conflict"
                    | "context_changed"
            )
            && (denial.error_code != "approval_snapshot_changed" || denial.kind == Kind::Exchange),
        "SHIKA_RECOVERY_REQUIRED"
    );
    ensure!(
        denial.request_hash.len() == 64
            && denial
                .request_hash
                .bytes()
                .all(|v| v.is_ascii_digit() || (b'a'..=b'f').contains(&v)),
        "SHIKA_RECOVERY_REQUIRED"
    );
    let local_hash = super::w3::fingerprint(&json!({"method":method,"params":params}))?;
    let receipt = json!({"schemaVersion":"shika.pairing-denial/v1","operationKind":backend_kind,"operationKey":denial.operation_key,"requestHash":denial.request_hash,"terminal":true,"committed":false,"errorCode":denial.error_code});
    Ok(super::LocalDenial {
        code: local_code(&denial.error_code),
        data: json!({"schemaVersion":"shika.pairing-local-denial/v1","method":method,"operationKey":denial.operation_key,"localRequestHash":local_hash,"terminal":true,"committed":false,"errorCode":denial.error_code,"backendReceipt":receipt}),
    })
}

fn id(value: &Value, field: &str) -> Result<Uuid> {
    let text = value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("SHIKA_INVALID_REQUEST"))?;
    let parsed = Uuid::parse_str(text).map_err(|_| anyhow::anyhow!("SHIKA_INVALID_REQUEST"))?;
    ensure!(parsed.to_string() == text, "SHIKA_INVALID_REQUEST");
    Ok(parsed)
}
fn now() -> Result<u64> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| anyhow::anyhow!("SHIKA_UNAVAILABLE"))?
        .as_secs())
}
fn parse_envelope(bytes: &[u8]) -> Result<PairingEnvelope> {
    serde_json::from_slice(bytes).map_err(|_| anyhow::anyhow!("SHIKA_RESPONSE_INVALID"))
}
fn key_id(pairing: &PendingPairing) -> String {
    format!(
        "p:{}",
        hex::encode(sha2::Sha256::digest(pairing.public_key()))
    )
}
use sha2::Digest;

fn requested(pairing: &PendingPairing) -> Result<Vec<String>> {
    let request: Value = serde_json::from_slice(
        pairing
            .request
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("SHIKA_STORE_INVALID"))?,
    )
    .map_err(|_| anyhow::anyhow!("SHIKA_STORE_INVALID"))?;
    serde_json::from_value(request["requestedScopes"].clone())
        .map_err(|_| anyhow::anyhow!("SHIKA_STORE_INVALID"))
}
fn local_result(
    pairing: &PendingPairing,
    env: &PairingEnvelope,
    config: &TrustedOrigins,
    installation: &str,
) -> Result<Value> {
    env.validate(
        pairing,
        &config.api,
        &config.ui,
        installation,
        &requested(pairing)?,
    )?;
    let mut completed = pairing.clone();
    completed.pairing_id = Some(
        Uuid::parse_str(&env.pairing.pairing_id)
            .map_err(|_| anyhow::anyhow!("SHIKA_RESPONSE_INVALID"))?,
    );
    let mut result =
        serde_json::to_value(env).map_err(|_| anyhow::anyhow!("SHIKA_RESPONSE_INVALID"))?;
    result["browserUrl"] = json!(completed.browser_url(&config.ui)?);
    Ok(result)
}
fn http_success(status: u16, expected: u16) -> Result<()> {
    ensure!(status == expected, "SHIKA_REMOTE_DENIED");
    Ok(())
}
fn denial_error(op: &Operation, code: &str, hash: &str, params: &Value) -> anyhow::Error {
    VerifiedDenial {
        kind: op.kind,
        operation_key: op.operation_key,
        request_hash: hash.to_owned(),
        error_code: code.to_owned(),
        public_params: params.clone(),
    }
    .into()
}
pub(super) fn settle_denial_if_verified(
    context: &dyn Context,
    journal: &mut Journal,
    op: &Operation,
    status: u16,
    bytes: &[u8],
    params: &Value,
) -> Result<()> {
    if let Some((code, hash)) = super::w3::verified_denial(status, bytes, op)? {
        journal.settle_denial(context.store(), op, &code, &hash)?;
        return Err(denial_error(op, &code, &hash, params));
    }
    Ok(())
}

struct ReplayIntent<'a> {
    kind: Kind,
    operation_key: Uuid,
    resource: Option<Uuid>,
    revision: Option<u64>,
    scopes: Option<&'a [String]>,
    params: &'a Value,
}
async fn replay_denial(
    journal: &Journal,
    config: &TrustedOrigins,
    intent: ReplayIntent<'_>,
) -> Result<()> {
    let ReplayIntent {
        kind,
        operation_key,
        resource,
        revision,
        scopes,
        params,
    } = intent;
    let Some(denial) = journal
        .denied_operations
        .iter()
        .find(|d| d.operation.operation_key == operation_key)
    else {
        return Ok(());
    };
    let op = &denial.operation;
    ensure!(
        op.kind == kind
            && op.binding.api_origin == config.api.0
            && op.binding.ui_origin == config.ui.0,
        "SHIKA_RECOVERY_REQUIRED"
    );
    let (route, target, match_header) = match (kind, resource, revision) {
        (Kind::Start, None, None) => (Route::Start, "/api/v2/pairings/".to_owned(), None),
        (Kind::Cancel, Some(id), Some(rev)) => (
            Route::Cancel(id),
            format!("/api/v2/pairings/{id}/cancel/"),
            Some(format!("\"pairing:{id}:{rev}\"")),
        ),
        (Kind::Exchange, Some(id), Some(rev)) => (
            Route::Exchange(id),
            format!("/api/v2/pairings/{id}/exchange/"),
            Some(format!("\"pairing:{id}:{rev}\"")),
        ),
        (Kind::Refresh, Some(id), Some(rev)) => (
            Route::Refresh(id),
            format!("/api/v2/connections/{id}/refresh/"),
            Some(format!("\"connection:{id}:{rev}\"")),
        ),
        (Kind::Revoke, Some(id), Some(rev)) => (
            Route::Revoke(id),
            format!("/api/v2/connections/{id}/revoke/"),
            Some(format!("\"connection:{id}:{rev}\"")),
        ),
        _ => return Err(anyhow::anyhow!("SHIKA_RECOVERY_REQUIRED")),
    };
    ensure!(
        op.target == target && op.if_match == match_header,
        "SHIKA_RECOVERY_REQUIRED"
    );
    let (private_key, key_id) = match kind {
        Kind::Start | Kind::Cancel | Kind::Exchange => {
            let pairing = denial
                .pairing
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("SHIKA_STORE_INVALID"))?;
            if let Some(scopes) = scopes {
                ensure!(
                    requested(pairing)?.as_slice() == scopes,
                    "SHIKA_RECOVERY_REQUIRED"
                );
            }
            (pairing.private_key, key_id(pairing))
        }
        Kind::Refresh | Kind::Revoke => {
            let credential = journal
                .selected
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("SHIKA_RECOVERY_REQUIRED"))?;
            ensure!(
                credential.binding == op.binding && credential.binding.connection_id == resource,
                "SHIKA_IDENTITY_CHANGED"
            );
            (
                credential.private_key,
                format!(
                    "c:{}:{}",
                    resource.ok_or_else(|| anyhow::anyhow!("SHIKA_STORE_INVALID"))?,
                    credential.revision
                ),
            )
        }
    };
    let transport = Transport::new(config.api.clone())?;
    let (status, bytes) = transport
        .send(
            route,
            &private_key,
            &key_id,
            RequestBody {
                body: &op.body,
                operation: Some(operation_key),
                if_match: op.if_match.as_deref(),
            },
            now()?,
        )
        .await?;
    let receipt = super::w3::verified_denial(status, &bytes, op)?
        .ok_or_else(|| anyhow::anyhow!("SHIKA_RECOVERY_REQUIRED"))?;
    ensure!(
        receipt.0 == denial.error_code && receipt.1 == denial.request_hash,
        "SHIKA_RECOVERY_REQUIRED"
    );
    Err(denial_error(op, &receipt.0, &receipt.1, params))
}

/// Only invoked after local schema validation. The owner file remains held
/// across await so no other process can change the selected protected state.
pub(super) async fn pairing_start_with(
    context: &dyn Context,
    config: TrustedOrigins,
    params: &Value,
    installation: &str,
) -> Result<Value> {
    let api = params["origin"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("SHIKA_INVALID_REQUEST"))?;
    let ui = params["uiOrigin"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("SHIKA_INVALID_REQUEST"))?;
    config.require_pair(api, ui)?;
    let operation_key = id(params, "operationKey")?;
    let scopes: Vec<String> = serde_json::from_value(params["requestedScopes"].clone())
        .map_err(|_| anyhow::anyhow!("SHIKA_INVALID_REQUEST"))?;
    ensure!(
        !scopes.is_empty()
            && scopes.len() <= 3
            && scopes
                .iter()
                .all(|v| matches!(v.as_str(), "shika.read" | "shika.write" | "shika.execute"))
            && scopes
                .iter()
                .enumerate()
                .all(|(i, v)| !scopes[..i].contains(v)),
        "SHIKA_INVALID_REQUEST"
    );
    let marker = context.marker()?;
    let mut journal = match super::load_state(context.store())? {
        Some(state) => {
            ensure!(
                state.installation_id == installation,
                "SHIKA_IDENTITY_CHANGED"
            );
            state
        }
        None => {
            ensure!(!marker, "SHIKA_RECOVERY_REQUIRED");
            let state = Journal {
                version: 1,
                installation_id: installation.to_owned(),
                device_id: Uuid::new_v4(),
                selected: None,
                other_credentials: vec![],
                pending_pairing: None,
                completed_exchanges: vec![],
                completed_cancels: vec![],
                rejected_exchanges: vec![],
                completed_refreshes: vec![],
                denied_operations: vec![],
                tombstones: vec![],
                known_connections: vec![],
                pending: None,
                disconnect_pending: false,
            };
            super::persist_new(context.store(), &state)?;
            state
        }
    };
    // The marker is durable before any operation can reach the server.
    context.ensure_marker()?;
    ensure!(!journal.disconnect_pending, "SHIKA_RECOVERY_REQUIRED");
    replay_denial(
        &journal,
        &config,
        ReplayIntent {
            kind: Kind::Start,
            operation_key,
            resource: None,
            revision: None,
            scopes: Some(&scopes),
            params,
        },
    )
    .await?;
    let transport = Transport::new(config.api.clone())?;
    if let Some(done) = journal
        .completed_exchanges
        .iter()
        .find(|x| x.pairing.operation_key == operation_key)
    {
        let selected = journal
            .selected
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("SHIKA_RECOVERY_REQUIRED"))?;
        let pairing = &done.pairing;
        ensure!(
            selected.private_key == pairing.private_key
                && pairing.api_origin == api
                && pairing.ui_origin == ui
                && requested(pairing)? == scopes,
            "SHIKA_RECOVERY_REQUIRED"
        );
        let body = pairing
            .request
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("SHIKA_STORE_INVALID"))?;
        let (status, bytes) = transport
            .send(
                Route::Start,
                &pairing.private_key,
                &key_id(pairing),
                RequestBody {
                    body,
                    operation: Some(operation_key),
                    if_match: None,
                },
                now()?,
            )
            .await?;
        http_success(status, 201)?;
        let env = parse_envelope(&bytes)?;
        ensure!(env.pairing.status == "pending", "SHIKA_RESPONSE_INVALID");
        let mut original = pairing.clone();
        original.actor_id = None;
        original.workspace_id = None;
        return local_result(&original, &env, &config, installation);
    }
    if journal
        .pending_pairing
        .as_ref()
        .is_some_and(|p| p.operation_key != operation_key)
    {
        ensure!(
            !journal.used_key(operation_key) && journal.pending.is_none(),
            "SHIKA_RECOVERY_REQUIRED"
        );
        let old = journal
            .pending_pairing
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("SHIKA_STORE_INVALID"))?
            .clone();
        let old_id = old
            .pairing_id
            .ok_or_else(|| anyhow::anyhow!("SHIKA_RECOVERY_REQUIRED"))?;
        ensure!(
            old.api_origin == config.api.0 && old.ui_origin == config.ui.0,
            "SHIKA_IDENTITY_CHANGED"
        );
        let (status, bytes) = transport
            .send(
                Route::Pairing(old_id),
                &old.private_key,
                &key_id(&old),
                RequestBody {
                    body: b"",
                    operation: None,
                    if_match: None,
                },
                now()?,
            )
            .await?;
        http_success(status, 200)?;
        let observed = parse_envelope(&bytes)?;
        observed.validate(
            &old,
            &config.api,
            &config.ui,
            installation,
            &requested(&old)?,
        )?;
        ensure!(
            matches!(observed.pairing.status.as_str(), "expired" | "cancelled")
                && observed.pairing.exchange_operation_key.is_none(),
            "SHIKA_RECOVERY_REQUIRED"
        );
        journal.retire_pairing(context.store(), old_id, &observed.pairing.status)?;
    }
    if let Some(pairing) = &journal.pending_pairing {
        ensure!(
            pairing.operation_key == operation_key && requested(pairing)? == scopes,
            "SHIKA_RECOVERY_REQUIRED"
        );
        let request: Value = serde_json::from_slice(
            pairing
                .request
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("SHIKA_STORE_INVALID"))?,
        )
        .map_err(|_| anyhow::anyhow!("SHIKA_STORE_INVALID"))?;
        ensure!(
            request["uiOrigin"] == ui && pairing.api_origin == api && pairing.ui_origin == ui,
            "SHIKA_IDENTITY_CHANGED"
        );
        if pairing.pairing_id.is_some() {
            ensure!(journal.pending.is_none(), "SHIKA_RECOVERY_REQUIRED");
            let (status, bytes) = transport
                .send(
                    Route::Start,
                    &pairing.private_key,
                    &key_id(pairing),
                    RequestBody {
                        body: pairing
                            .request
                            .as_ref()
                            .ok_or_else(|| anyhow::anyhow!("SHIKA_STORE_INVALID"))?,
                        operation: Some(operation_key),
                        if_match: None,
                    },
                    now()?,
                )
                .await?;
            http_success(status, 201)?;
            let envelope = parse_envelope(&bytes)?;
            ensure!(
                envelope.pairing.status == "pending",
                "SHIKA_RESPONSE_INVALID"
            );
            let mut original = pairing.clone();
            original.actor_id = None;
            original.workspace_id = None;
            return local_result(&original, &envelope, &config, installation);
        }
    } else {
        ensure!(!journal.used_key(operation_key), "SHIKA_RECOVERY_REQUIRED");
        let mut pairing = PendingPairing::generate(journal.device_id, operation_key);
        pairing.api_origin = api.into();
        pairing.ui_origin = ui.into();
        let public = pairing.public_key();
        let body = serde_json::to_vec(
            &json!({"deviceId":pairing.device_id,"installationId":installation,"publicKey":super::wire::public_key_text(&public),"proofKeyThumbprint":hex::encode(sha2::Sha256::digest(public)),"codeChallenge":pairing.challenge(),"uiOrigin":ui,"requestedScopes":scopes,"stateHash":pairing.state_hash(),"operationKey":operation_key}),
        )?;
        pairing.bind_request(body.clone())?;
        let binding = Binding {
            api_origin: api.into(),
            ui_origin: ui.into(),
            installation_id: installation.into(),
            device_id: journal.device_id,
            actor_id: None,
            workspace_id: None,
            connection_id: None,
        };
        let op = Operation {
            kind: Kind::Start,
            operation_key,
            binding,
            method: "POST".into(),
            target: "/api/v2/pairings/".into(),
            body,
            if_match: None,
            replacement_key: None,
        };
        journal.begin_pairing(context.store(), pairing, op)?;
    }
    let pairing = journal
        .pending_pairing
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("SHIKA_STORE_INVALID"))?
        .clone();
    let op = journal
        .pending
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("SHIKA_STORE_INVALID"))?
        .clone();
    ensure!(
        matches!(op.kind, Kind::Start) && op.operation_key == operation_key,
        "SHIKA_RECOVERY_REQUIRED"
    );
    let (status, bytes) = transport
        .send(
            Route::Start,
            &pairing.private_key,
            &key_id(&pairing),
            RequestBody {
                body: &op.body,
                operation: Some(operation_key),
                if_match: None,
            },
            now()?,
        )
        .await?;
    settle_denial_if_verified(context, &mut journal, &op, status, &bytes, params)?;
    http_success(status, 201)?;
    let envelope = parse_envelope(&bytes)?;
    ensure!(
        envelope.pairing.status == "pending",
        "SHIKA_RESPONSE_INVALID"
    );
    let result = local_result(&pairing, &envelope, &config, installation)?;
    journal.settle_pairing_start(
        context.store(),
        &op,
        Uuid::parse_str(&envelope.pairing.pairing_id)
            .map_err(|_| anyhow::anyhow!("SHIKA_RESPONSE_INVALID"))?,
        &envelope.pairing.created_at,
        &envelope.pairing.expires_at,
    )?;
    Ok(result)
}

pub(super) async fn pairing_get_with(
    context: &dyn Context,
    config: TrustedOrigins,
    params: &Value,
    installation: &str,
) -> Result<Value> {
    let pairing_id = id(params, "pairingId")?;
    let mut journal = super::load_state(context.store())?
        .ok_or_else(|| anyhow::anyhow!("SHIKA_RECOVERY_REQUIRED"))?;
    ensure!(
        journal.installation_id == installation && context.marker()? && !journal.disconnect_pending,
        "SHIKA_RECOVERY_REQUIRED"
    );
    let current = journal
        .pending_pairing
        .as_ref()
        .filter(|p| p.pairing_id == Some(pairing_id));
    let historical = current.is_none();
    let pairing = if let Some(pairing) = current {
        pairing.clone()
    } else {
        let done = journal
            .completed_exchanges
            .iter()
            .find(|entry| entry.pairing.pairing_id == Some(pairing_id))
            .ok_or_else(|| anyhow::anyhow!("SHIKA_NOT_FOUND"))?;
        let authorized_key = journal
            .selected
            .iter()
            .chain(journal.other_credentials.iter())
            .any(|c| {
                c.private_key == done.pairing.private_key
                    && c.binding.api_origin == done.pairing.api_origin
                    && c.binding.actor_id == done.pairing.actor_id
                    && c.binding.workspace_id == done.pairing.workspace_id
            });
        ensure!(authorized_key, "SHIKA_RECOVERY_REQUIRED");
        done.pairing.clone()
    };
    ensure!(
        pairing.pairing_id == Some(pairing_id)
            && pairing.api_origin == config.api.0
            && pairing.ui_origin == config.ui.0,
        "SHIKA_IDENTITY_CHANGED"
    );
    let transport = Transport::new(config.api.clone())?;
    let (status, bytes) = transport
        .send(
            Route::Pairing(pairing_id),
            &pairing.private_key,
            &key_id(&pairing),
            RequestBody {
                body: b"",
                operation: None,
                if_match: None,
            },
            now()?,
        )
        .await?;
    http_success(status, 200)?;
    let envelope = parse_envelope(&bytes)?;
    let result = local_result(&pairing, &envelope, &config, installation)?;
    if historical {
        ensure!(
            envelope.pairing.status == "consumed",
            "SHIKA_RESPONSE_INVALID"
        );
    }
    if !historical && matches!(envelope.pairing.status.as_str(), "approved" | "consumed") {
        let actor = envelope
            .pairing
            .actor_id
            .as_deref()
            .and_then(|v| Uuid::parse_str(v).ok())
            .ok_or_else(|| anyhow::anyhow!("SHIKA_RESPONSE_INVALID"))?;
        let workspace = envelope
            .pairing
            .workspace_id
            .as_deref()
            .and_then(|v| Uuid::parse_str(v).ok())
            .ok_or_else(|| anyhow::anyhow!("SHIKA_RESPONSE_INVALID"))?;
        journal.observe_assignment(context.store(), actor, workspace)?;
    }
    Ok(result)
}

pub(super) async fn connection_get_with(
    context: &dyn Context,
    config: TrustedOrigins,
    installation: &str,
) -> Result<Value> {
    let Some(journal) = super::load_state(context.store())? else {
        ensure!(!context.marker()?, "SHIKA_RECOVERY_REQUIRED");
        return Ok(json!({"state":"unpaired","connection":null}));
    };
    ensure!(
        journal.installation_id == installation && context.marker()?,
        "SHIKA_RECOVERY_REQUIRED"
    );
    if journal.disconnect_pending {
        return Ok(json!({"state":"disconnect_pending","connection":null}));
    }
    ensure!(
        !journal
            .pending
            .as_ref()
            .is_some_and(|op| matches!(op.kind, Kind::Refresh)),
        "SHIKA_RECOVERY_REQUIRED"
    );
    let Some(credential) = &journal.selected else {
        return Ok(json!({"state":"unpaired","connection":null}));
    };
    ensure!(
        credential.binding.api_origin == config.api.0
            && credential.binding.ui_origin == config.ui.0,
        "SHIKA_IDENTITY_CHANGED"
    );
    let connection_id = credential
        .binding
        .connection_id
        .ok_or_else(|| anyhow::anyhow!("SHIKA_STORE_INVALID"))?;
    let key_id = format!("c:{connection_id}:{}", credential.revision);
    let transport = Transport::new(config.api)?;
    let (status, bytes) = transport
        .send(
            Route::Connection(connection_id),
            &credential.private_key,
            &key_id,
            RequestBody {
                body: b"",
                operation: None,
                if_match: None,
            },
            now()?,
        )
        .await?;
    http_success(status, 200)?;
    let connection: super::wire::Connection =
        serde_json::from_slice(&bytes).map_err(|_| anyhow::anyhow!("SHIKA_RESPONSE_INVALID"))?;
    let public = ed25519_dalek::SigningKey::from_bytes(&credential.private_key)
        .verifying_key()
        .to_bytes();
    connection.validate(&credential.binding, &public, &credential.scopes)?;
    ensure!(
        connection.status == "active" && connection.credential_revision == credential.revision,
        "SHIKA_RESPONSE_INVALID"
    );
    Ok(json!({"state":"active","connection":connection}))
}

pub(super) async fn pairing_exchange_with(
    context: &dyn Context,
    config: TrustedOrigins,
    params: &Value,
    installation: &str,
) -> Result<Value> {
    let pairing_id = id(params, "pairingId")?;
    let operation_key = id(params, "operationKey")?;
    let revision = params["expectedRevision"]
        .as_u64()
        .filter(|r| *r > 0 && *r <= 9_007_199_254_740_991)
        .ok_or_else(|| anyhow::anyhow!("SHIKA_INVALID_REQUEST"))?;
    let mut journal = super::load_state(context.store())?
        .ok_or_else(|| anyhow::anyhow!("SHIKA_RECOVERY_REQUIRED"))?;
    ensure!(
        journal.installation_id == installation && context.marker()? && !journal.disconnect_pending,
        "SHIKA_RECOVERY_REQUIRED"
    );
    replay_denial(
        &journal,
        &config,
        ReplayIntent {
            kind: Kind::Exchange,
            operation_key,
            resource: Some(pairing_id),
            revision: Some(revision),
            scopes: None,
            params,
        },
    )
    .await?;
    let transport = Transport::new(config.api.clone())?;
    if let Some(done) = journal
        .completed_exchanges
        .iter()
        .find(|x| x.operation.operation_key == operation_key)
    {
        let selected = journal
            .selected
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("SHIKA_RECOVERY_REQUIRED"))?;
        ensure!(
            done.pairing.pairing_id == Some(pairing_id)
                && done.operation.if_match.as_deref()
                    == Some(format!("\"pairing:{pairing_id}:{revision}\"").as_str())
                && selected.private_key == done.pairing.private_key
                && selected.binding.api_origin == config.api.0
                && selected.binding.ui_origin == config.ui.0,
            "SHIKA_RECOVERY_REQUIRED"
        );
        let (status, bytes) = transport
            .send(
                Route::Exchange(pairing_id),
                &done.pairing.private_key,
                &key_id(&done.pairing),
                RequestBody {
                    body: &done.operation.body,
                    operation: Some(operation_key),
                    if_match: done.operation.if_match.as_deref(),
                },
                now()?,
            )
            .await?;
        http_success(status, 201)?;
        let connection: super::wire::Connection = serde_json::from_slice(&bytes)
            .map_err(|_| anyhow::anyhow!("SHIKA_RESPONSE_INVALID"))?;
        connection.validate(
            &selected.binding,
            &done.pairing.public_key(),
            &selected.scopes,
        )?;
        ensure!(
            connection.status == "active" && connection.credential_revision == selected.revision,
            "SHIKA_RESPONSE_INVALID"
        );
        return serde_json::to_value(connection)
            .map_err(|_| anyhow::anyhow!("SHIKA_RESPONSE_INVALID"));
    }
    let mut pairing = journal
        .pending_pairing
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("SHIKA_NOT_FOUND"))?
        .clone();
    ensure!(
        pairing.pairing_id == Some(pairing_id)
            && pairing.api_origin == config.api.0
            && pairing.ui_origin == config.ui.0,
        "SHIKA_IDENTITY_CHANGED"
    );
    if journal.pending.is_none() {
        let (status, bytes) = transport
            .send(
                Route::Pairing(pairing_id),
                &pairing.private_key,
                &key_id(&pairing),
                RequestBody {
                    body: b"",
                    operation: None,
                    if_match: None,
                },
                now()?,
            )
            .await?;
        http_success(status, 200)?;
        let env = parse_envelope(&bytes)?;
        env.validate(
            &pairing,
            &config.api,
            &config.ui,
            installation,
            &requested(&pairing)?,
        )?;
        ensure!(
            env.pairing.status == "approved"
                && !env.reapproval_required
                && env.revision == revision,
            "SHIKA_RECOVERY_REQUIRED"
        );
        let target = format!("/api/v2/pairings/{pairing_id}/exchange/");
        for rejected in journal
            .rejected_exchanges
            .iter()
            .filter(|op| op.target == target)
        {
            ensure!(
                rejected.operation_key != operation_key,
                "SHIKA_APPROVAL_CHANGED"
            );
            let body: Value = serde_json::from_slice(&rejected.body)
                .map_err(|_| anyhow::anyhow!("SHIKA_STORE_INVALID"))?;
            let rejected_revision = body["expectedRevision"]
                .as_u64()
                .ok_or_else(|| anyhow::anyhow!("SHIKA_STORE_INVALID"))?;
            ensure!(
                env.approval_revision.is_some_and(|r| r > rejected_revision),
                "SHIKA_RECOVERY_REQUIRED"
            );
        }
        let actor = env
            .pairing
            .actor_id
            .as_deref()
            .and_then(|v| Uuid::parse_str(v).ok())
            .ok_or_else(|| anyhow::anyhow!("SHIKA_RESPONSE_INVALID"))?;
        let workspace = env
            .pairing
            .workspace_id
            .as_deref()
            .and_then(|v| Uuid::parse_str(v).ok())
            .ok_or_else(|| anyhow::anyhow!("SHIKA_RESPONSE_INVALID"))?;
        journal.observe_assignment(context.store(), actor, workspace)?;
        pairing.actor_id = Some(actor);
        pairing.workspace_id = Some(workspace);
        let binding = Binding {
            api_origin: config.api.0.clone(),
            ui_origin: config.ui.0.clone(),
            installation_id: installation.into(),
            device_id: pairing.device_id,
            actor_id: Some(actor),
            workspace_id: Some(workspace),
            connection_id: None,
        };
        let body = serde_json::to_vec(
            &json!({"codeVerifier":pairing.verifier,"expectedRevision":revision,"operationKey":operation_key}),
        )?;
        let op = Operation {
            kind: Kind::Exchange,
            operation_key,
            binding,
            method: "POST".into(),
            target: format!("/api/v2/pairings/{pairing_id}/exchange/"),
            body,
            if_match: Some(format!("\"pairing:{pairing_id}:{revision}\"")),
            replacement_key: None,
        };
        journal.begin(context.store(), op)?;
    }
    let op = journal
        .pending
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("SHIKA_STORE_INVALID"))?
        .clone();
    ensure!(
        matches!(op.kind, Kind::Exchange)
            && op.operation_key == operation_key
            && op.target == format!("/api/v2/pairings/{pairing_id}/exchange/")
            && op.if_match.as_deref()
                == Some(format!("\"pairing:{pairing_id}:{revision}\"").as_str()),
        "SHIKA_RECOVERY_REQUIRED"
    );
    let (status, bytes) = transport
        .send(
            Route::Exchange(pairing_id),
            &pairing.private_key,
            &key_id(&pairing),
            RequestBody {
                body: &op.body,
                operation: Some(operation_key),
                if_match: op.if_match.as_deref(),
            },
            now()?,
        )
        .await?;
    settle_denial_if_verified(context, &mut journal, &op, status, &bytes, params)?;
    http_success(status, 201)?;
    let connection: super::wire::Connection =
        serde_json::from_slice(&bytes).map_err(|_| anyhow::anyhow!("SHIKA_RESPONSE_INVALID"))?;
    connection.validate(&op.binding, &pairing.public_key(), &requested(&pairing)?)?;
    ensure!(connection.status == "active", "SHIKA_RESPONSE_INVALID");
    let mut binding = op.binding.clone();
    binding.connection_id = Some(
        Uuid::parse_str(&connection.connection_id)
            .map_err(|_| anyhow::anyhow!("SHIKA_RESPONSE_INVALID"))?,
    );
    let credential = super::journal::Credential {
        binding,
        private_key: pairing.private_key,
        revision: connection.credential_revision,
        scopes: requested(&pairing)?,
        metadata: connection.clone(),
    };
    journal.finish(context.store(), &op, Some(credential))?;
    serde_json::to_value(connection).map_err(|_| anyhow::anyhow!("SHIKA_RESPONSE_INVALID"))
}

pub(super) async fn pairing_cancel_with(
    context: &dyn Context,
    config: TrustedOrigins,
    params: &Value,
    installation: &str,
) -> Result<Value> {
    let pairing_id = id(params, "resourceId")?;
    let operation_key = id(params, "operationKey")?;
    let revision = params["expectedRevision"]
        .as_u64()
        .filter(|r| *r > 0 && *r <= 9_007_199_254_740_991)
        .ok_or_else(|| anyhow::anyhow!("SHIKA_INVALID_REQUEST"))?;
    let mut journal = super::load_state(context.store())?
        .ok_or_else(|| anyhow::anyhow!("SHIKA_RECOVERY_REQUIRED"))?;
    ensure!(
        journal.installation_id == installation && context.marker()? && !journal.disconnect_pending,
        "SHIKA_RECOVERY_REQUIRED"
    );
    replay_denial(
        &journal,
        &config,
        ReplayIntent {
            kind: Kind::Cancel,
            operation_key,
            resource: Some(pairing_id),
            revision: Some(revision),
            scopes: None,
            params,
        },
    )
    .await?;
    let transport = Transport::new(config.api.clone())?;
    let match_header = format!("\"pairing:{pairing_id}:{revision}\"");
    let archived = journal
        .completed_cancels
        .iter()
        .find(|v| v.operation.operation_key == operation_key)
        .cloned();
    let pairing = if let Some(done) = &archived {
        done.pairing.clone()
    } else {
        journal
            .pending_pairing
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("SHIKA_NOT_FOUND"))?
            .clone()
    };
    ensure!(
        pairing.pairing_id == Some(pairing_id)
            && pairing.api_origin == config.api.0
            && pairing.ui_origin == config.ui.0,
        "SHIKA_IDENTITY_CHANGED"
    );
    if archived.is_none() && journal.pending.is_none() {
        let binding = Binding {
            api_origin: config.api.0.clone(),
            ui_origin: config.ui.0.clone(),
            installation_id: installation.into(),
            device_id: pairing.device_id,
            actor_id: pairing.actor_id,
            workspace_id: pairing.workspace_id,
            connection_id: None,
        };
        let body =
            serde_json::to_vec(&json!({"expectedRevision":revision,"operationKey":operation_key}))?;
        let op = Operation {
            kind: Kind::Cancel,
            operation_key,
            binding,
            method: "POST".into(),
            target: format!("/api/v2/pairings/{pairing_id}/cancel/"),
            body,
            if_match: Some(match_header.clone()),
            replacement_key: None,
        };
        journal.begin(context.store(), op)?;
    }
    let op = archived
        .as_ref()
        .map(|x| x.operation.clone())
        .or_else(|| journal.pending.clone())
        .ok_or_else(|| anyhow::anyhow!("SHIKA_STORE_INVALID"))?;
    ensure!(
        matches!(op.kind, Kind::Cancel)
            && op.operation_key == operation_key
            && op.target == format!("/api/v2/pairings/{pairing_id}/cancel/")
            && op.if_match.as_deref() == Some(match_header.as_str()),
        "SHIKA_RECOVERY_REQUIRED"
    );
    let (status, bytes) = transport
        .send(
            Route::Cancel(pairing_id),
            &pairing.private_key,
            &key_id(&pairing),
            RequestBody {
                body: &op.body,
                operation: Some(operation_key),
                if_match: op.if_match.as_deref(),
            },
            now()?,
        )
        .await?;
    if archived.is_none() {
        settle_denial_if_verified(context, &mut journal, &op, status, &bytes, params)?;
    }
    http_success(status, 200)?;
    let envelope = parse_envelope(&bytes)?;
    ensure!(
        envelope.pairing.status == "cancelled",
        "SHIKA_RESPONSE_INVALID"
    );
    let result = local_result(&pairing, &envelope, &config, installation)?;
    if archived.is_none() {
        journal.settle_cancel(context.store(), &op)?;
    }
    Ok(result)
}

pub(super) async fn connection_revoke_with(
    context: &dyn Context,
    config: TrustedOrigins,
    params: &Value,
    installation: &str,
) -> Result<Value> {
    let connection_id = id(params, "resourceId")?;
    let operation_key = id(params, "operationKey")?;
    let revision = params["expectedRevision"]
        .as_u64()
        .filter(|r| *r > 0 && *r <= 9_007_199_254_740_991)
        .ok_or_else(|| anyhow::anyhow!("SHIKA_INVALID_REQUEST"))?;
    let mut journal = super::load_state(context.store())?
        .ok_or_else(|| anyhow::anyhow!("SHIKA_RECOVERY_REQUIRED"))?;
    ensure!(
        journal.installation_id == installation && context.marker()?,
        "SHIKA_RECOVERY_REQUIRED"
    );
    let credential = journal
        .selected
        .clone()
        .ok_or_else(|| anyhow::anyhow!("SHIKA_RECOVERY_REQUIRED"))?;
    ensure!(
        credential.binding.connection_id == Some(connection_id)
            && credential.binding.api_origin == config.api.0
            && credential.binding.ui_origin == config.ui.0,
        "SHIKA_IDENTITY_CHANGED"
    );
    replay_denial(
        &journal,
        &config,
        ReplayIntent {
            kind: Kind::Revoke,
            operation_key,
            resource: Some(connection_id),
            revision: Some(revision),
            scopes: None,
            params,
        },
    )
    .await?;
    let if_match = format!("\"connection:{connection_id}:{revision}\"");
    if journal.pending.is_none() {
        let body =
            serde_json::to_vec(&json!({"expectedRevision":revision,"operationKey":operation_key}))?;
        let operation = Operation {
            kind: Kind::Revoke,
            operation_key,
            binding: credential.binding.clone(),
            method: "POST".into(),
            target: format!("/api/v2/connections/{connection_id}/revoke/"),
            body,
            if_match: Some(if_match.clone()),
            replacement_key: None,
        };
        journal.begin(context.store(), operation)?;
    }
    let operation = journal
        .pending
        .clone()
        .ok_or_else(|| anyhow::anyhow!("SHIKA_STORE_INVALID"))?;
    ensure!(
        matches!(operation.kind, Kind::Revoke)
            && operation.operation_key == operation_key
            && operation.target == format!("/api/v2/connections/{connection_id}/revoke/")
            && operation.if_match.as_deref() == Some(if_match.as_str())
            && operation.binding == credential.binding,
        "SHIKA_RECOVERY_REQUIRED"
    );
    let key_id = format!("c:{connection_id}:{}", credential.revision);
    let transport = Transport::new(config.api)?;
    let (status, bytes) = transport
        .send(
            Route::Revoke(connection_id),
            &credential.private_key,
            &key_id,
            RequestBody {
                body: &operation.body,
                operation: Some(operation_key),
                if_match: operation.if_match.as_deref(),
            },
            now()?,
        )
        .await?;
    settle_denial_if_verified(context, &mut journal, &operation, status, &bytes, params)?;
    http_success(status, 200)?;
    let response: super::wire::Connection =
        serde_json::from_slice(&bytes).map_err(|_| anyhow::anyhow!("SHIKA_RESPONSE_INVALID"))?;
    let public = ed25519_dalek::SigningKey::from_bytes(&credential.private_key)
        .verifying_key()
        .to_bytes();
    response.validate(&credential.binding, &public, &credential.scopes)?;
    ensure!(
        response.status == "revoked" && response.credential_revision == credential.revision,
        "SHIKA_RESPONSE_INVALID"
    );
    journal.finish(context.store(), &operation, None)?;
    serde_json::to_value(response).map_err(|_| anyhow::anyhow!("SHIKA_RESPONSE_INVALID"))
}

pub(super) async fn connection_refresh_with(
    context: &dyn Context,
    config: TrustedOrigins,
    params: &Value,
    installation: &str,
) -> Result<Value> {
    use rand::RngCore;
    let resource_id = id(params, "resourceId")?;
    let operation_key = id(params, "operationKey")?;
    let expected_revision = params["expectedRevision"]
        .as_u64()
        .filter(|r| *r > 0 && *r <= 9_007_199_254_740_991)
        .ok_or_else(|| anyhow::anyhow!("SHIKA_INVALID_REQUEST"))?;
    let mut journal = super::load_state(context.store())?
        .ok_or_else(|| anyhow::anyhow!("SHIKA_RECOVERY_REQUIRED"))?;
    ensure!(
        journal.installation_id == installation && context.marker()? && !journal.disconnect_pending,
        "SHIKA_RECOVERY_REQUIRED"
    );
    let credential = journal
        .selected
        .clone()
        .ok_or_else(|| anyhow::anyhow!("SHIKA_RECOVERY_REQUIRED"))?;
    let connection_id = credential
        .binding
        .connection_id
        .ok_or_else(|| anyhow::anyhow!("SHIKA_STORE_INVALID"))?;
    ensure!(
        connection_id == resource_id
            && credential.binding.api_origin == config.api.0
            && credential.binding.ui_origin == config.ui.0,
        "SHIKA_IDENTITY_CHANGED"
    );
    replay_denial(
        &journal,
        &config,
        ReplayIntent {
            kind: Kind::Refresh,
            operation_key,
            resource: Some(connection_id),
            revision: Some(expected_revision),
            scopes: None,
            params,
        },
    )
    .await?;
    let transport = Transport::new(config.api)?;
    if let Some(done) = journal
        .completed_refreshes
        .iter()
        .find(|v| v.operation.operation_key == operation_key)
    {
        let if_match = format!("\"connection:{connection_id}:{expected_revision}\"");
        ensure!(
            done.operation.binding == credential.binding
                && done.operation.if_match.as_deref() == Some(if_match.as_str())
                && done.operation.replacement_key == Some(credential.private_key)
                && done.previous_revision.checked_add(1) == Some(credential.revision),
            "SHIKA_RECOVERY_REQUIRED"
        );
        let key_id = format!("c:{connection_id}:{}", credential.revision);
        let (status, bytes) = transport
            .send(
                Route::Refresh(connection_id),
                &credential.private_key,
                &key_id,
                RequestBody {
                    body: &done.operation.body,
                    operation: Some(operation_key),
                    if_match: done.operation.if_match.as_deref(),
                },
                now()?,
            )
            .await?;
        http_success(status, 200)?;
        let response: super::wire::Connection = serde_json::from_slice(&bytes)
            .map_err(|_| anyhow::anyhow!("SHIKA_RESPONSE_INVALID"))?;
        let public = ed25519_dalek::SigningKey::from_bytes(&credential.private_key)
            .verifying_key()
            .to_bytes();
        response.validate(&credential.binding, &public, &credential.scopes)?;
        ensure!(
            response.status == "active"
                && response.credential_revision == credential.revision
                && response.revision > expected_revision,
            "SHIKA_RESPONSE_INVALID"
        );
        return serde_json::to_value(response)
            .map_err(|_| anyhow::anyhow!("SHIKA_RESPONSE_INVALID"));
    }
    ensure!(
        credential.revision < 9_007_199_254_740_991,
        "SHIKA_RECOVERY_REQUIRED"
    );
    let is_fresh = journal.pending.is_none();
    if is_fresh {
        let mut new_key = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut new_key);
        let public = ed25519_dalek::SigningKey::from_bytes(&new_key)
            .verifying_key()
            .to_bytes();
        let revision = expected_revision;
        let body = serde_json::to_vec(
            &json!({"expectedRevision":revision,"expectedCredentialRevision":credential.revision,"newPublicKey":super::wire::public_key_text(&public),"newProofKeyThumbprint":hex::encode(sha2::Sha256::digest(public)),"operationKey":operation_key}),
        )?;
        let operation = Operation {
            kind: Kind::Refresh,
            operation_key,
            binding: credential.binding.clone(),
            method: "POST".into(),
            target: format!("/api/v2/connections/{connection_id}/refresh/"),
            body,
            if_match: Some(format!("\"connection:{connection_id}:{revision}\"")),
            replacement_key: Some(new_key),
        };
        journal.begin(context.store(), operation)?;
    }
    let operation = journal
        .pending
        .clone()
        .ok_or_else(|| anyhow::anyhow!("SHIKA_STORE_INVALID"))?;
    ensure!(
        matches!(operation.kind, Kind::Refresh)
            && operation.operation_key == operation_key
            && operation.binding == credential.binding
            && operation.target == format!("/api/v2/connections/{connection_id}/refresh/")
            && operation.if_match.as_deref()
                == Some(format!("\"connection:{connection_id}:{expected_revision}\"").as_str()),
        "SHIKA_RECOVERY_REQUIRED"
    );
    let new_key = operation
        .replacement_key
        .ok_or_else(|| anyhow::anyhow!("SHIKA_STORE_INVALID"))?;
    let old_id = format!("c:{connection_id}:{}", credential.revision);
    let new_id = format!("c:{connection_id}:{}", credential.revision + 1);
    let (status, bytes) = if is_fresh {
        transport
            .send(
                Route::Refresh(connection_id),
                &credential.private_key,
                &old_id,
                RequestBody {
                    body: &operation.body,
                    operation: Some(operation_key),
                    if_match: operation.if_match.as_deref(),
                },
                now()?,
            )
            .await?
    } else {
        let attempt = transport
            .send(
                Route::Refresh(connection_id),
                &new_key,
                &new_id,
                RequestBody {
                    body: &operation.body,
                    operation: Some(operation_key),
                    if_match: operation.if_match.as_deref(),
                },
                now()?,
            )
            .await?;
        if attempt.0 == 401 {
            transport
                .send(
                    Route::Refresh(connection_id),
                    &credential.private_key,
                    &old_id,
                    RequestBody {
                        body: &operation.body,
                        operation: Some(operation_key),
                        if_match: operation.if_match.as_deref(),
                    },
                    now()?,
                )
                .await?
        } else {
            attempt
        }
    };
    settle_denial_if_verified(context, &mut journal, &operation, status, &bytes, params)?;
    http_success(status, 200)?;
    let response: super::wire::Connection =
        serde_json::from_slice(&bytes).map_err(|_| anyhow::anyhow!("SHIKA_RESPONSE_INVALID"))?;
    let public = ed25519_dalek::SigningKey::from_bytes(&new_key)
        .verifying_key()
        .to_bytes();
    response.validate(&credential.binding, &public, &credential.scopes)?;
    ensure!(
        response.status == "active"
            && response.credential_revision == credential.revision + 1
            && response.revision > expected_revision,
        "SHIKA_RESPONSE_INVALID"
    );
    let updated = super::journal::Credential {
        binding: credential.binding,
        private_key: new_key,
        revision: response.credential_revision,
        scopes: credential.scopes,
        metadata: response.clone(),
    };
    journal.finish(context.store(), &operation, Some(updated))?;
    serde_json::to_value(response).map_err(|_| anyhow::anyhow!("SHIKA_RESPONSE_INVALID"))
}
