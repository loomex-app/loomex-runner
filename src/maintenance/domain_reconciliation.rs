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
    ensure!(
        auth.enrolled_organizations()
            .await?
            .iter()
            .any(|id| id == org),
        "ORGANIZATION_NOT_ENROLLED"
    );
    let credential = auth.credential(org).await?;
    let before = auth.current_child_identity(org).await?;
    ensure!(
        before.0 == account
            && credential.subject == account
            && before.1 == expected.installation_id,
        "AUTH_IDENTITY_CHANGED"
    );
    let owner = Owner {
        organization: org,
        account,
        installation: &before.1,
    };
    let receipt = read_with(candidate, &owner, |verb, route, body| async move {
        Ok(api
            .request(&verb, &route, body, Some(&credential), None)
            .await?)
    })
    .await?;
    ensure!(
        auth.current_child_identity(org).await? == before,
        "AUTH_IDENTITY_CHANGED"
    );
    ensure!(
        auth.maintenance_identity()
            .await?
            .as_ref()
            .is_some_and(
                |identity| identity.installation_id == expected.installation_id
                    && (expected.device_id.is_none() || identity.device_id == expected.device_id)
            ),
        "AUTH_IDENTITY_CHANGED"
    );
    Ok(receipt)
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
