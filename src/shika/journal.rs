//! Protected exact-operation journal. Callers must serialize every operation
//! across threads and processes before reading or changing the store.
use super::store::Store;
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Binding {
    pub(super) api_origin: String,
    pub(super) ui_origin: String,
    pub(super) installation_id: String,
    pub(super) device_id: Uuid,
    pub(super) actor_id: Option<Uuid>,
    pub(super) workspace_id: Option<Uuid>,
    pub(super) connection_id: Option<Uuid>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Kind {
    Start,
    Cancel,
    Exchange,
    Refresh,
    Revoke,
}

// The body can contain a verifier, so never derive Debug or return this as an
// RPC result. The private rotation key is retained before network dispatch.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Operation {
    pub(super) kind: Kind,
    pub(super) operation_key: Uuid,
    pub(super) binding: Binding,
    pub(super) method: String,
    pub(super) target: String,
    pub(super) body: Vec<u8>,
    pub(super) if_match: Option<String>,
    pub(super) replacement_key: Option<[u8; 32]>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Credential {
    pub(super) binding: Binding,
    pub(super) private_key: [u8; 32],
    pub(super) revision: u64,
    pub(super) scopes: Vec<String>,
    pub(super) metadata: super::wire::Connection,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CompletedExchange {
    pub(super) pairing: super::PendingPairing,
    pub(super) operation: Operation,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CompletedRefresh {
    pub(super) operation: Operation,
    pub(super) previous_revision: u64,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct TerminalDenial {
    pub(super) operation: Operation,
    pub(super) error_code: String,
    pub(super) request_hash: String,
    pub(super) pairing: Option<super::PendingPairing>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Tombstone {
    pub(super) operation_key: Uuid,
    pub(super) kind: Kind,
    pub(super) request_hash: String,
    pub(super) resource_id: Option<Uuid>,
    pub(super) outcome: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Journal {
    pub(super) version: u32,
    pub(super) installation_id: String,
    pub(super) device_id: Uuid,
    pub(super) selected: Option<Credential>,
    pub(super) other_credentials: Vec<Credential>,
    pub(super) pending_pairing: Option<super::PendingPairing>,
    pub(super) completed_exchanges: Vec<CompletedExchange>,
    pub(super) completed_cancels: Vec<CompletedExchange>,
    pub(super) rejected_exchanges: Vec<Operation>,
    pub(super) completed_refreshes: Vec<CompletedRefresh>,
    pub(super) denied_operations: Vec<TerminalDenial>,
    pub(super) tombstones: Vec<Tombstone>,
    pub(super) known_connections: Vec<Binding>,
    pub(super) pending: Option<Operation>,
    pub(super) disconnect_pending: bool,
}

impl Journal {
    fn record_operation(
        &mut self,
        operation: &Operation,
        resource_id: Option<Uuid>,
        outcome: &str,
    ) -> Result<()> {
        let hash = super::w3::operation_fingerprint(operation)?;
        if let Some(existing) = self
            .tombstones
            .iter()
            .find(|v| v.operation_key == operation.operation_key)
        {
            ensure!(
                existing.kind == operation.kind
                    && existing.request_hash == hash
                    && existing.resource_id == resource_id,
                "SHIKA_STORE_INVALID"
            );
            return Ok(());
        }
        self.tombstones.push(Tombstone {
            operation_key: operation.operation_key,
            kind: operation.kind,
            request_hash: hash,
            resource_id,
            outcome: outcome.to_owned(),
        });
        Ok(())
    }
    fn record_start(&mut self, pairing: &super::PendingPairing, outcome: &str) -> Result<()> {
        let binding = Binding {
            api_origin: pairing.api_origin.clone(),
            ui_origin: pairing.ui_origin.clone(),
            installation_id: self.installation_id.clone(),
            device_id: self.device_id,
            actor_id: pairing.actor_id,
            workspace_id: pairing.workspace_id,
            connection_id: None,
        };
        let operation = Operation {
            kind: Kind::Start,
            operation_key: pairing.operation_key,
            binding,
            method: "POST".into(),
            target: "/api/v2/pairings/".into(),
            body: pairing
                .request
                .clone()
                .ok_or_else(|| anyhow::anyhow!("SHIKA_STORE_INVALID"))?,
            if_match: None,
            replacement_key: None,
        };
        self.record_operation(&operation, pairing.pairing_id, outcome)
    }
    fn compact_pairing_denials(&mut self, pairing: &super::PendingPairing) -> Result<()> {
        let denials = std::mem::take(&mut self.denied_operations);
        for denial in denials {
            if denial
                .pairing
                .as_ref()
                .is_some_and(|p| p.private_key == pairing.private_key)
            {
                self.record_operation(&denial.operation, pairing.pairing_id, "denied")?;
            } else {
                self.denied_operations.push(denial);
            }
        }
        let rejected = std::mem::take(&mut self.rejected_exchanges);
        for operation in rejected {
            if pairing
                .pairing_id
                .is_some_and(|id| operation.target == format!("/api/v2/pairings/{id}/exchange/"))
            {
                self.record_operation(&operation, pairing.pairing_id, "denied")?;
            } else {
                self.rejected_exchanges.push(operation);
            }
        }
        Ok(())
    }
    pub(super) fn validate(&self) -> Result<()> {
        ensure!(
            self.version == 1 && !self.installation_id.is_empty(),
            "SHIKA_STORE_INVALID"
        );
        if let Some(pairing) = &self.pending_pairing {
            ensure!(
                pairing.device_id == self.device_id && pairing.request.is_some(),
                "SHIKA_STORE_INVALID"
            );
        }
        for b in self
            .selected
            .iter()
            .chain(self.other_credentials.iter())
            .map(|c| &c.binding)
            .chain(self.pending.iter().map(|p| &p.binding))
        {
            ensure!(
                b.installation_id == self.installation_id && b.device_id == self.device_id,
                "SHIKA_STORE_INVALID"
            );
        }
        if self.disconnect_pending {
            ensure!(
                matches!(self.pending.as_ref().map(|p| &p.kind), Some(Kind::Revoke)),
                "SHIKA_STORE_INVALID"
            );
        }
        Ok(())
    }
    // Commit the complete new state first; failed writes leave the previous
    // in-memory value untouched and never authorize a network send.
    fn save_change(&mut self, store: &dyn Store, candidate: Self) -> Result<()> {
        candidate.validate()?;
        let data =
            serde_json::to_vec(&candidate).map_err(|_| anyhow::anyhow!("SHIKA_STORE_INVALID"))?;
        store.save(&data)?;
        *self = candidate;
        Ok(())
    }
    pub(super) fn begin(&mut self, store: &dyn Store, operation: Operation) -> Result<()> {
        self.validate()?;
        if let Some(existing) = &self.pending {
            ensure!(existing == &operation, "SHIKA_RECOVERY_REQUIRED");
            return Ok(());
        }
        ensure!(!self.disconnect_pending, "SHIKA_RECOVERY_REQUIRED");
        ensure!(
            !self.used_key(operation.operation_key),
            "SHIKA_RECOVERY_REQUIRED"
        );
        if matches!(operation.kind, Kind::Refresh | Kind::Revoke) {
            ensure!(
                self.selected
                    .as_ref()
                    .is_some_and(|c| c.binding == operation.binding),
                "SHIKA_IDENTITY_CHANGED"
            );
        }
        let mut candidate = self.clone();
        candidate.disconnect_pending = matches!(operation.kind, Kind::Revoke);
        candidate.pending = Some(operation);
        self.save_change(store, candidate)
    }
    pub(super) fn begin_pairing(
        &mut self,
        store: &dyn Store,
        pairing: super::PendingPairing,
        operation: Operation,
    ) -> Result<()> {
        self.validate()?;
        ensure!(
            matches!(operation.kind, Kind::Start)
                && pairing.operation_key == operation.operation_key
                && pairing.device_id == self.device_id
                && pairing.request.as_ref() == Some(&operation.body),
            "SHIKA_STORE_INVALID"
        );
        if let Some(existing) = &self.pending {
            ensure!(existing == &operation, "SHIKA_RECOVERY_REQUIRED");
            let saved = self
                .pending_pairing
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("SHIKA_STORE_INVALID"))?;
            ensure!(
                saved.operation_key == pairing.operation_key
                    && saved.request == pairing.request
                    && saved.private_key == pairing.private_key
                    && saved.state == pairing.state
                    && saved.verifier == pairing.verifier,
                "SHIKA_RECOVERY_REQUIRED"
            );
            return Ok(());
        }
        ensure!(
            !self.disconnect_pending && self.pending_pairing.is_none(),
            "SHIKA_RECOVERY_REQUIRED"
        );
        ensure!(
            !self.used_key(operation.operation_key),
            "SHIKA_RECOVERY_REQUIRED"
        );
        let mut candidate = self.clone();
        candidate.pending_pairing = Some(pairing);
        candidate.pending = Some(operation);
        self.save_change(store, candidate)
    }
    pub(super) fn settle_pairing_start(
        &mut self,
        store: &dyn Store,
        expected: &Operation,
        id: Uuid,
        created_at: &str,
        expires_at: &str,
    ) -> Result<()> {
        ensure!(
            matches!(expected.kind, Kind::Start) && self.pending.as_ref() == Some(expected),
            "SHIKA_RECOVERY_REQUIRED"
        );
        let mut candidate = self.clone();
        let pairing = candidate
            .pending_pairing
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("SHIKA_STORE_INVALID"))?;
        ensure!(
            pairing.pairing_id.is_none_or(|v| v == id),
            "SHIKA_IDENTITY_CHANGED"
        );
        pairing.pairing_id = Some(id);
        pairing.created_at = Some(created_at.to_owned());
        pairing.expires_at = Some(expires_at.to_owned());
        candidate.pending = None;
        self.save_change(store, candidate)
    }
    pub(super) fn observe_assignment(
        &mut self,
        store: &dyn Store,
        actor: Uuid,
        workspace: Uuid,
    ) -> Result<()> {
        let mut candidate = self.clone();
        let pairing = candidate
            .pending_pairing
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("SHIKA_STORE_INVALID"))?;
        ensure!(
            pairing.actor_id.is_none_or(|id| id == actor)
                && pairing.workspace_id.is_none_or(|id| id == workspace),
            "SHIKA_IDENTITY_CHANGED"
        );
        if pairing.actor_id == Some(actor) && pairing.workspace_id == Some(workspace) {
            return Ok(());
        }
        pairing.actor_id = Some(actor);
        pairing.workspace_id = Some(workspace);
        self.save_change(store, candidate)
    }
    pub(super) fn settle_cancel(&mut self, store: &dyn Store, expected: &Operation) -> Result<()> {
        ensure!(
            matches!(expected.kind, Kind::Cancel) && self.pending.as_ref() == Some(expected),
            "SHIKA_RECOVERY_REQUIRED"
        );
        let mut candidate = self.clone();
        let pairing = candidate
            .pending_pairing
            .take()
            .ok_or_else(|| anyhow::anyhow!("SHIKA_STORE_INVALID"))?;
        candidate.record_start(&pairing, "cancelled")?;
        candidate.record_operation(expected, pairing.pairing_id, "cancelled")?;
        candidate.compact_pairing_denials(&pairing)?;
        candidate.pending = None;
        self.save_change(store, candidate)
    }
    pub(super) fn retire_pairing(
        &mut self,
        store: &dyn Store,
        pairing_id: Uuid,
        status: &str,
    ) -> Result<()> {
        ensure!(self.pending.is_none(), "SHIKA_RECOVERY_REQUIRED");
        ensure!(
            matches!(status, "expired" | "cancelled"),
            "SHIKA_RECOVERY_REQUIRED"
        );
        let mut candidate = self.clone();
        let pairing = candidate
            .pending_pairing
            .take()
            .ok_or_else(|| anyhow::anyhow!("SHIKA_STORE_INVALID"))?;
        ensure!(
            pairing.pairing_id == Some(pairing_id),
            "SHIKA_IDENTITY_CHANGED"
        );
        candidate.record_start(&pairing, status)?;
        candidate.compact_pairing_denials(&pairing)?;
        self.save_change(store, candidate)
    }
    pub(super) fn used_key(&self, key: Uuid) -> bool {
        self.tombstones.iter().any(|t| t.operation_key == key)
            || self.denied_operations.iter().any(|x| {
                x.operation.operation_key == key
                    || x.pairing.as_ref().is_some_and(|p| p.operation_key == key)
            })
            || self
                .completed_cancels
                .iter()
                .chain(self.completed_exchanges.iter())
                .any(|x| x.operation.operation_key == key || x.pairing.operation_key == key)
            || self
                .completed_refreshes
                .iter()
                .any(|x| x.operation.operation_key == key)
            || self
                .rejected_exchanges
                .iter()
                .any(|x| x.operation_key == key)
            || self
                .pending
                .as_ref()
                .is_some_and(|x| x.operation_key == key)
            || self
                .pending_pairing
                .as_ref()
                .is_some_and(|x| x.operation_key == key)
    }
    pub(super) fn settle_denial(
        &mut self,
        store: &dyn Store,
        expected: &Operation,
        error_code: &str,
        hash: &str,
    ) -> Result<()> {
        ensure!(
            self.pending.as_ref() == Some(expected),
            "SHIKA_RECOVERY_REQUIRED"
        );
        let mut candidate = self.clone();
        if matches!(expected.kind, Kind::Exchange) && error_code == "approval_snapshot_changed" {
            candidate.rejected_exchanges.push(expected.clone());
        }
        let pairing = if matches!(expected.kind, Kind::Start | Kind::Cancel | Kind::Exchange) {
            candidate.pending_pairing.clone()
        } else {
            None
        };
        if matches!(expected.kind, Kind::Start) {
            candidate.pending_pairing = None;
        }
        let mut denied_operation = expected.clone();
        // A definitively uncommitted rotation can never install this key. The
        // original public request still suffices for a current-proof replay.
        if matches!(denied_operation.kind, Kind::Refresh) {
            denied_operation.replacement_key = None;
        }
        candidate.denied_operations.push(TerminalDenial {
            operation: denied_operation,
            error_code: error_code.to_owned(),
            request_hash: hash.to_owned(),
            pairing,
        });
        candidate.pending = None;
        candidate.disconnect_pending = false;
        self.save_change(store, candidate)
    }
    // Caller must authenticate and validate the exact server response before
    // invoking this. A revoke can never be confirmed by unauthenticated retry.
    pub(super) fn finish(
        &mut self,
        store: &dyn Store,
        expected: &Operation,
        selected: Option<Credential>,
    ) -> Result<()> {
        ensure!(
            self.pending.as_ref() == Some(expected),
            "SHIKA_RECOVERY_REQUIRED"
        );
        ensure!(
            matches!(expected.kind, Kind::Exchange | Kind::Refresh | Kind::Revoke),
            "SHIKA_STORE_INVALID"
        );
        ensure!(
            selected.is_none() == matches!(expected.kind, Kind::Revoke),
            "SHIKA_STORE_INVALID"
        );
        if let Some(credential) = &selected {
            ensure!(
                credential.binding.installation_id == self.installation_id
                    && credential.binding.device_id == self.device_id,
                "SHIKA_IDENTITY_CHANGED"
            );
            ensure!(
                credential.binding.api_origin == expected.binding.api_origin
                    && credential.binding.ui_origin == expected.binding.ui_origin,
                "SHIKA_IDENTITY_CHANGED"
            );
            ensure!(
                expected.binding.actor_id.is_some()
                    && expected.binding.workspace_id.is_some()
                    && credential.binding.actor_id == expected.binding.actor_id
                    && credential.binding.workspace_id == expected.binding.workspace_id
                    && credential.binding.connection_id.is_some(),
                "SHIKA_IDENTITY_CHANGED"
            );
            if !matches!(expected.kind, Kind::Exchange) {
                ensure!(
                    credential.binding == expected.binding,
                    "SHIKA_IDENTITY_CHANGED"
                );
            }
            let public = ed25519_dalek::SigningKey::from_bytes(&credential.private_key)
                .verifying_key()
                .to_bytes();
            credential
                .metadata
                .validate(&credential.binding, &public, &credential.scopes)?;
            ensure!(
                credential.metadata.status == "active"
                    && credential.metadata.credential_revision == credential.revision,
                "SHIKA_RESPONSE_INVALID"
            );
            if matches!(expected.kind, Kind::Exchange) {
                for previous in &self.known_connections {
                    if previous.api_origin == credential.binding.api_origin
                        && previous.actor_id == credential.binding.actor_id
                        && previous.workspace_id == credential.binding.workspace_id
                    {
                        ensure!(
                            previous.device_id == credential.binding.device_id
                                && previous.installation_id == credential.binding.installation_id,
                            "SHIKA_IDENTITY_CHANGED"
                        );
                    }
                }
            }
            if matches!(expected.kind, Kind::Refresh) {
                let prior = self
                    .selected
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("SHIKA_IDENTITY_CHANGED"))?;
                ensure!(
                    prior.revision.checked_add(1) == Some(credential.revision)
                        && expected.replacement_key == Some(credential.private_key)
                        && prior.scopes == credential.scopes,
                    "SHIKA_RESPONSE_INVALID"
                );
            }
        }
        let mut candidate = self.clone();
        if matches!(expected.kind, Kind::Revoke | Kind::Refresh) {
            if let Some(old) = &self.selected {
                let entries = std::mem::take(&mut candidate.completed_exchanges);
                for entry in entries {
                    if entry.pairing.private_key == old.private_key {
                        candidate.record_start(&entry.pairing, "start_committed")?;
                        candidate.record_operation(
                            &entry.operation,
                            entry.pairing.pairing_id,
                            "exchange_committed",
                        )?;
                        candidate.compact_pairing_denials(&entry.pairing)?;
                    } else {
                        candidate.completed_exchanges.push(entry);
                    }
                }
                let refreshes = std::mem::take(&mut candidate.completed_refreshes);
                for entry in refreshes {
                    if entry.operation.binding.connection_id == old.binding.connection_id {
                        candidate.record_operation(
                            &entry.operation,
                            old.binding.connection_id,
                            "refresh_committed",
                        )?;
                    } else {
                        candidate.completed_refreshes.push(entry);
                    }
                }
            }
        }
        if matches!(expected.kind, Kind::Refresh) {
            let old = self
                .selected
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("SHIKA_STORE_INVALID"))?;
            candidate.completed_refreshes.push(CompletedRefresh {
                operation: expected.clone(),
                previous_revision: old.revision,
            });
        }
        if matches!(expected.kind, Kind::Revoke) {
            candidate.record_operation(expected, expected.binding.connection_id, "revoked")?;
        }
        if matches!(expected.kind, Kind::Exchange) {
            let pairing = candidate
                .pending_pairing
                .take()
                .ok_or_else(|| anyhow::anyhow!("SHIKA_STORE_INVALID"))?;
            candidate.completed_exchanges.push(CompletedExchange {
                pairing,
                operation: expected.clone(),
            });
            let binding = &selected
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("SHIKA_STORE_INVALID"))?
                .binding;
            if let Some(previous) = candidate.known_connections.iter_mut().find(|prior| {
                prior.api_origin == binding.api_origin
                    && prior.actor_id == binding.actor_id
                    && prior.workspace_id == binding.workspace_id
                    && prior.device_id == binding.device_id
                    && prior.installation_id == binding.installation_id
            }) {
                *previous = binding.clone();
            } else {
                candidate.known_connections.push(binding.clone());
            }
            if let Some(old) = candidate.selected.take() {
                if old.binding.connection_id != binding.connection_id {
                    candidate.other_credentials.push(old);
                }
            }
        }
        candidate.selected = selected;
        candidate.pending = None;
        candidate.disconnect_pending = false;
        self.save_change(store, candidate)
    }
}
