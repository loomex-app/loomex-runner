//! Exact owner receipt reads for retained presentation mutations. This module
//! never dispatches the original mutation or infers an idempotency key.
use crate::{
    api::Api,
    auth::{Auth, CredentialIdentity},
    control, presentation,
};
use anyhow::{Context, Result, ensure};
use serde_json::Value;
use std::future::Future;

pub(super) struct Owner<'a> {
    pub organization: &'a str,
    pub account: &'a str,
    pub installation: &'a str,
}
pub(super) struct Read {
    pub method: String,
    pub params: Value,
}
pub(super) fn plan(candidate: &Value, owner: &Owner<'_>) -> Result<Read> {
    ensure!(
        candidate["kind"] == "presentation_operation"
            && candidate["organizationId"] == owner.organization
            && candidate["accountSubject"] == owner.account,
        "AUTH_IDENTITY_CHANGED"
    );
    ensure!(
        candidate["installationId"]
            .as_str()
            .is_some_and(|id| id.is_empty() || id == owner.installation),
        "AUTH_IDENTITY_CHANGED"
    );
    let plan = presentation::maintenance_operation_plan(candidate)?;
    Ok(Read {
        method: plan["method"]
            .as_str()
            .context("MANAGED_WORK_RECONCILIATION_UNSUPPORTED")?
            .to_owned(),
        params: plan["params"].clone(),
    })
}
fn validate_receipt(candidate: &Value, read: &Read, receipt: &Value) -> Result<()> {
    let key = if read.method == "workflow.operations.get" {
        &receipt["idempotencyKey"]
    } else {
        &receipt["key"]
    };
    ensure!(
        receipt["operation"] == read.params["operation"] && *key == candidate["operationKey"],
        "MANAGED_WORK_RECEIPT_MISMATCH"
    );
    ensure!(
        matches!(
            receipt["status"].as_str(),
            Some("completed" | "pending" | "not_found")
        ),
        "MANAGED_WORK_RECEIPT_MISMATCH"
    );
    ensure!(
        receipt["status"] == "completed",
        "MANAGED_DOMAIN_OUTCOME_PENDING"
    );
    presentation::verify_maintenance_operation_receipt(candidate, receipt)
}
/// The injected reader receives only the existing receipt route and its original
/// read arguments. It cannot receive or execute the original mutation payload.
pub(super) async fn read_with<F, Fut>(
    candidate: &Value,
    owner: &Owner<'_>,
    reader: F,
) -> Result<Value>
where
    F: FnOnce(String, String, Option<Value>) -> Fut,
    Fut: Future<Output = Result<Value>>,
{
    let read = plan(candidate, owner)?;
    let (verb, route, body) = control::backend_route(&read.method, &read.params)?;
    let receipt = reader(verb, route, body).await?;
    validate_receipt(candidate, &read, &receipt)?;
    Ok(receipt)
}
pub(super) async fn read(
    api: &Api,
    auth: &Auth,
    candidate: &Value,
    expected: &CredentialIdentity,
) -> Result<Value> {
    let org = candidate["organizationId"]
        .as_str()
        .context("INVALID_REQUEST")?;
    let account = candidate["accountSubject"]
        .as_str()
        .context("INVALID_REQUEST")?;
    let (credential, owner_snapshot) = auth
        .owner_bound_credential(org, Some(expected), Some(account))
        .await?;
    let owner = Owner {
        organization: org,
        account,
        installation: &owner_snapshot.identity.installation_id,
    };
    auth.verify_bound_owner(&owner_snapshot).await?;
    let receipt = read_with(candidate, &owner, |verb, route, body| async move {
        Ok(api
            .request(&verb, &route, body, Some(&credential), None)
            .await?)
    })
    .await;
    auth.verify_bound_owner(&owner_snapshot).await?;
    receipt
}

/// A legacy observation with no original request identity cannot be correlated
/// by guessing from a filename. Its canonical outcome remains explicitly unknown.
pub(super) async fn read_operation(
    api: &Api,
    auth: &Auth,
    candidate: &Value,
    expected: &CredentialIdentity,
    recover_auth: bool,
) -> Result<Value> {
    let binding = &candidate["binding"];
    let method = candidate["method"]
        .as_str()
        .context("MANAGED_WORK_CHANGED")?;
    let native =
        matches!(method, "builder.start" | "editor.start") && candidate["runId"].as_str().is_some();
    let interaction = matches!(
        method,
        "interactions.respond"
            | "interactions.decide"
            | "interactions.draft.delete"
            | "interactions.draft.update"
    );
    if !native && !interaction && binding.is_null() {
        return Ok(serde_json::json!({"remoteOutcome":"unknown","safeReason":"missing_binding"}));
    }
    let organizations = if let Some(org) = binding["organizationId"].as_str() {
        vec![org.to_owned()]
    } else {
        auth.enrolled_organizations().await?
    };
    ensure!(organizations.len() <= 64, "MANAGED_WORK_PREVIEW_LIMIT");
    let mut matches = Vec::new();
    let mut lookup_state = "missing_binding";
    let mut unavailable = false;
    for org in organizations {
        let account = if binding.is_null() {
            None
        } else {
            ensure!(
                binding["installationId"] == expected.installation_id,
                "AUTH_IDENTITY_CHANGED"
            );
            Some(
                binding["accountSubject"]
                    .as_str()
                    .context("AUTH_IDENTITY_CHANGED")?,
            )
        };
        let admission = if recover_auth {
            auth.owner_bound_credential(&org, Some(expected), account)
                .await
        } else {
            auth.owner_bound_existing_credential(&org, Some(expected), account)
                .await
        };
        let (credential, before) = match admission {
            Ok(admitted) => admitted,
            Err(error) => {
                // An unknown or pending protected auth operation is never
                // skipped. Only a completed rotation with the original owner
                // still present may be isolated for an unbound legacy lookup.
                if binding.is_null() {
                    if let Some(owner) = crate::auth::unavailable_bound_owner(&error) {
                        auth.verify_bound_owner(owner).await?;
                        unavailable = true;
                        continue;
                    }
                }
                return Err(error);
            }
        };
        auth.verify_bound_owner(&before).await?;
        let (route, body) = if native {
            (
                "v2/native-authoring-receipts/get/",
                serde_json::json!({"operation":method,"executionId":candidate["runId"],"cacheReference":candidate["legacySlot"],"accountSubject":before.account,"cacheRequestDigest":candidate["record"]["digest"]}),
            )
        } else if interaction {
            if binding["receipt"]["method"] == "interactions.operations.get" {
                (
                    "v2/interaction-operations/get/",
                    binding["receipt"]["params"].clone(),
                )
            } else {
                (
                    "v2/interaction-operations/get/",
                    serde_json::json!({"operation":if method=="interactions.respond"||method=="interactions.decide" {"interaction.resolve"}else{method},"cacheReference":candidate["legacySlot"],"accountSubject":before.account}),
                )
            }
        } else {
            return Ok(
                serde_json::json!({"remoteOutcome":"unknown","safeReason":"unsupported_family"}),
            );
        };
        let receipt = match api
            .request("POST", route, Some(body), Some(&credential), None)
            .await
        {
            Ok(receipt) => receipt,
            Err(_) => {
                auth.verify_bound_owner(&before).await?;
                unavailable = true;
                lookup_state = "unavailable";
                continue;
            }
        };
        lookup_state = match receipt["status"].as_str() {
            Some("pending") => "pending",
            Some("not_found") => "not_found",
            Some("expired") => "expired",
            Some("completed") => "same_key_only",
            _ => "unavailable",
        };
        unavailable |= lookup_state == "unavailable";
        auth.verify_bound_owner(&before).await?;
        ensure!(
            receipt["operation"]
                == (if method == "interactions.respond" || method == "interactions.decide" {
                    "interaction.resolve"
                } else {
                    method
                }),
            "MANAGED_WORK_RECEIPT_MISMATCH"
        );
        if receipt["status"] != "completed" || receipt["match"] != "exact_request_match" {
            continue;
        }
        if native {
            ensure!(
                receipt["provenance"] == "native_authoring_queued_receipt"
                    && receipt["cacheRequestDigest"] == candidate["record"]["digest"],
                "MANAGED_WORK_RECEIPT_MISMATCH"
            );
            control::verify_native_authoring_start(method, &receipt["result"])?;
            ensure!(
                receipt["result"]["executionId"] == candidate["runId"],
                "MANAGED_WORK_RECEIPT_MISMATCH"
            );
            matches.push((before, receipt));
        } else {
            ensure!(
                receipt["submissionFingerprintVersion"] == "loomex.operation-submission/v1"
                    && !binding["backendSubmissionDigest"].is_null()
                    && receipt["submissionFingerprint"] == binding["backendSubmissionDigest"],
                "MANAGED_WORK_RECEIPT_MISMATCH"
            );
            ensure!(
                receipt["requestId"] == binding["references"]["requestId"],
                "MANAGED_WORK_RECEIPT_MISMATCH"
            );
            matches.push((before, receipt));
        }
    }
    ensure!(matches.len() <= 1, "MANAGED_WORK_RECEIPT_MISMATCH");
    if let Some((matched_owner, receipt)) = matches.pop() {
        auth.verify_bound_owner(&matched_owner).await?;
        let mut owner = candidate.clone();
        owner["organizationId"] = serde_json::json!(matched_owner.organization);
        owner["accountSubject"] = serde_json::json!(matched_owner.account);
        let run = if native {
            Some(candidate["runId"].clone())
        } else {
            receipt["result"]["executionId"]
                .as_str()
                .map(|run| serde_json::json!(run))
        };
        if let Some(run) = run {
            owner["runId"] = run;
            let observation =
                super::read_run(api, auth, &owner, &matched_owner.identity, recover_auth).await?;
            if !observation["terminalResult"].is_null() {
                return Ok(
                    serde_json::json!({"remoteOutcome":"terminal","organizationId":owner["organizationId"],"accountSubject":owner["accountSubject"],"installationId":expected.installation_id,"canonicalReceipt":receipt,"observation":observation}),
                );
            }
        } else if method == "interactions.draft.delete" && receipt["result"]["deleted"].is_boolean()
        {
            return Ok(
                serde_json::json!({"remoteOutcome":"completed","organizationId":owner["organizationId"],"accountSubject":owner["accountSubject"],"installationId":expected.installation_id,"canonicalReceipt":receipt}),
            );
        }
        return Ok(serde_json::json!({"remoteOutcome":"unknown","safeReason":"terminal_missing"}));
    }
    if unavailable {
        lookup_state = "unavailable";
    }
    Ok(
        serde_json::json!({"remoteOutcome":"unknown","safeReason":if lookup_state=="missing_binding" && binding.is_null(){"missing_binding"}else{"canonical_pending"},"lookupState":lookup_state}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use uuid::Uuid;
    fn candidate() -> Value {
        let key = Uuid::new_v4();
        json!({"kind":"presentation_operation","organizationId":"org","accountSubject":"account","installationId":"install","method":"workflows.create","params":{"name":"SECRET_PROMPT","idempotencyKey":key},"operationKey":key,"reconciliation":{"method":"workflow.operations.get","params":{"operation":"workflows.create","idempotencyKey":key}}})
    }
    fn receipt(candidate: &Value) -> Value {
        json!({"operation":"workflows.create","idempotencyKey":candidate["operationKey"],"status":"completed","response":{"workflowId":Uuid::new_v4(),"name":"SECRET_RESPONSE","slug":"fixture"}})
    }
    fn owner() -> Owner<'static> {
        Owner {
            organization: "org",
            account: "account",
            installation: "install",
        }
    }
    #[tokio::test]
    async fn exact_receipt_read_never_receives_original_mutation_payload() {
        let candidate = candidate();
        let expected = receipt(&candidate);
        let copy = expected.clone();
        let received = read_with(&candidate, &owner(), |verb, route, body| async move {
            assert_eq!(verb, "POST");
            assert_eq!(route, "v2/workflow-operations/get/");
            let body = body.unwrap();
            assert_eq!(body.as_object().unwrap().len(), 2);
            assert!(!body.to_string().contains("SECRET_PROMPT"));
            Ok(copy)
        })
        .await
        .unwrap();
        assert_eq!(received, expected);
    }
    #[tokio::test]
    async fn unknown_wrong_key_and_scope_never_prove_completion() {
        let candidate = candidate();
        for status in ["pending", "not_found"] {
            let response = json!({"operation":"workflows.create","idempotencyKey":candidate["operationKey"],"status":status});
            assert_eq!(
                read_with(&candidate, &owner(), |_, _, _| async move { Ok(response) })
                    .await
                    .unwrap_err()
                    .to_string(),
                "MANAGED_DOMAIN_OUTCOME_PENDING"
            );
        }
        let mut wrong = receipt(&candidate);
        wrong["idempotencyKey"] = json!(Uuid::new_v4());
        assert!(
            read_with(&candidate, &owner(), |_, _, _| async move { Ok(wrong) })
                .await
                .is_err()
        );
        let mut wrong = candidate.clone();
        wrong["organizationId"] = json!("other-org");
        let read_called = std::cell::Cell::new(false);
        assert!(
            read_with(&wrong, &owner(), |_, _, _| {
                read_called.set(true);
                async { Ok(Value::Null) }
            })
            .await
            .is_err()
        );
        assert!(!read_called.get());
    }
    #[tokio::test]
    async fn lost_read_response_repeats_only_original_canonical_read() {
        let candidate = candidate();
        assert!(
            read_with(&candidate, &owner(), |_, _, _| async {
                Err(anyhow::anyhow!("NETWORK_AMBIGUOUS"))
            })
            .await
            .is_err()
        );
        let expected = receipt(&candidate);
        let copy = expected.clone();
        assert_eq!(
            read_with(&candidate, &owner(), |verb, route, _| async move {
                assert_eq!(verb, "POST");
                assert_eq!(route, "v2/workflow-operations/get/");
                Ok(copy)
            })
            .await
            .unwrap(),
            expected
        );
    }
    #[test]
    fn changed_original_key_or_descriptor_and_unsupported_methods_are_refused() {
        let original = candidate();
        let mut changed = original.clone();
        changed["params"]["idempotencyKey"] = json!(Uuid::new_v4());
        assert!(plan(&changed, &owner()).is_err());
        let mut changed = original.clone();
        changed["reconciliation"]["method"] = json!("runs.commit");
        assert!(plan(&changed, &owner()).is_err());
        let mut changed = original;
        changed["method"] = json!("interactions.respond");
        assert!(plan(&changed, &owner()).is_err());
    }
}
