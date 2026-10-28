use super::store::Store;
use super::*;
use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey};
use std::sync::Mutex;

#[derive(Default)]
struct FakeStore {
    bytes: Mutex<Option<Vec<u8>>>,
    fail: Mutex<bool>,
}
impl Store for FakeStore {
    fn load(&self) -> Result<Option<Vec<u8>>> {
        Ok(self.bytes.lock().unwrap().clone())
    }
    fn save(&self, bytes: &[u8]) -> Result<()> {
        ensure!(!*self.fail.lock().unwrap(), "SHIKA_STORE_UNAVAILABLE");
        *self.bytes.lock().unwrap() = Some(bytes.to_vec());
        Ok(())
    }
}
#[derive(Default)]
struct FakeContext {
    store: FakeStore,
    marker: Mutex<bool>,
}
impl super::service::Context for FakeContext {
    fn store(&self) -> &dyn Store {
        &self.store
    }
    fn marker(&self) -> Result<bool> {
        Ok(*self.marker.lock().unwrap())
    }
    fn ensure_marker(&self) -> Result<()> {
        *self.marker.lock().unwrap() = true;
        Ok(())
    }
}

#[tokio::test]
async fn missing_key_with_marker_fences_without_network_or_native_store() {
    let context = FakeContext::default();
    *context.marker.lock().unwrap() = true;
    let config =
        TrustedOrigins::from_config("https://api.example.com", "https://ui.example.com", false)
            .unwrap();
    assert!(
        super::service::connection_get_with(&context, config, "installation")
            .await
            .is_err()
    );
    assert!(context.store.load().unwrap().is_none());
}

#[tokio::test]
async fn loopback_start_journals_before_request_and_redacts_secrets() {
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let context = Arc::new(FakeContext::default());
    let context_for_server = context.clone();
    let server_origin = origin.clone();
    let task = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut buffer = Vec::new();
        let mut block = [0u8; 4096];
        let header_end;
        loop {
            let n = socket.read(&mut block).await.unwrap();
            assert!(n > 0);
            buffer.extend_from_slice(&block[..n]);
            if let Some(i) = buffer.windows(4).position(|w| w == b"\r\n\r\n") {
                header_end = i + 4;
                break;
            }
        }
        let headers = String::from_utf8(buffer[..header_end].to_vec()).unwrap();
        let length: usize = headers
            .lines()
            .find_map(|line| {
                line.split_once(':')
                    .filter(|(k, _)| k.eq_ignore_ascii_case("content-length"))
                    .map(|(_, v)| v.trim().parse().unwrap())
            })
            .unwrap();
        while buffer.len() < header_end + length {
            let n = socket.read(&mut block).await.unwrap();
            assert!(n > 0);
            buffer.extend_from_slice(&block[..n]);
        }
        let request: serde_json::Value =
            serde_json::from_slice(&buffer[header_end..header_end + length]).unwrap();
        let saved = load_state(&context_for_server.store).unwrap().unwrap();
        let pending = saved.pending_pairing.unwrap();
        assert!(saved.pending.is_some());
        assert!(!String::from_utf8_lossy(&buffer).contains(&pending.verifier));
        assert!(!String::from_utf8_lossy(&buffer).contains(&pending.state));
        let response = serde_json::json!({"pairing":{"schemaVersion":"shika.pairing/v1","pairingId":Uuid::new_v4(),"operationKey":request["operationKey"],"origin":server_origin,"deviceId":request["deviceId"],"installationId":request["installationId"],"proofKeyThumbprint":request["proofKeyThumbprint"],"codeChallenge":request["codeChallenge"],"createdAt":"2026-01-01T00:00:00Z","expiresAt":"2026-01-01T00:10:00Z","status":"pending","actorId":null,"workspaceId":null,"exchangeOperationKey":null},"revision":1,"uiOrigin":request["uiOrigin"],"requestedScopes":request["requestedScopes"],"approvalRevision":null,"reapprovalRequired":false});
        let body = serde_json::to_vec(&response).unwrap();
        socket.write_all(format!("HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).as_bytes()).await.unwrap();
        socket.write_all(&body).await.unwrap();
    });
    let config = TrustedOrigins::from_config(&origin, &origin, true).unwrap();
    let input = serde_json::json!({"origin":origin,"uiOrigin":origin,"requestedScopes":["shika.read"],"operationKey":Uuid::new_v4()});
    let result =
        super::service::pairing_start_with(context.as_ref(), config, &input, "installation")
            .await
            .unwrap();
    task.await.unwrap();
    let state = load_state(&context.store).unwrap().unwrap();
    let pairing = state.pending_pairing.unwrap();
    assert!(state.pending.is_none());
    assert!(
        result["browserUrl"]
            .as_str()
            .unwrap()
            .contains(&pairing.state)
    );
    assert!(!result.to_string().contains(&pairing.verifier));
}

#[test]
fn restart_preserves_pending_and_failed_overwrite() {
    let store = FakeStore::default();
    let mut pending = PendingPairing::generate(Uuid::new_v4(), Uuid::new_v4());
    pending.bind_request(b"immutable".to_vec()).unwrap();
    let state = journal::Journal {
        version: 1,
        installation_id: "installation".into(),
        device_id: pending.device_id,
        pending_pairing: Some(pending.clone()),
        completed_exchanges: vec![],
        completed_cancels: vec![],
        rejected_exchanges: vec![],
        completed_refreshes: vec![],
        denied_operations: vec![],
        tombstones: vec![],
        known_connections: vec![],
        selected: None,
        other_credentials: vec![],
        pending: None,
        disconnect_pending: false,
    };
    persist_new(&store, &state).unwrap();
    let recovered = load_state(&store)
        .unwrap()
        .unwrap()
        .pending_pairing
        .unwrap();
    assert_eq!(recovered.private_key, pending.private_key);
    assert_eq!(recovered.verifier, pending.verifier);
    assert_eq!(recovered.state, pending.state);
    assert_eq!(recovered.request, pending.request);
    assert!(persist_new(&store, &state).is_err());
    *store.fail.lock().unwrap() = true;
    assert!(store.save(b"replacement").is_err());
    assert_eq!(
        load_state(&store)
            .unwrap()
            .unwrap()
            .pending_pairing
            .unwrap()
            .operation_key,
        pending.operation_key
    );
}

#[test]
fn origins_and_safe_browser_url() {
    assert!(Origin::parse("https://example.com", false).is_ok());
    for bad in [
        "https://example.com/",
        "https://user@example.com",
        "https://example.com/path",
        "https://example.com?x=1",
        "https://EXAMPLE.com",
        "http://example.com",
        "http://127.0.0.1",
    ] {
        assert!(Origin::parse(bad, false).is_err(), "{bad}");
    }
    assert!(Origin::parse("http://127.0.0.1:3000", true).is_ok());
    let mut p = PendingPairing::generate(Uuid::new_v4(), Uuid::new_v4());
    p.pairing_id = Some(Uuid::new_v4());
    let url = p
        .browser_url(&Origin::parse("https://example.com", false).unwrap())
        .unwrap();
    assert!(url.contains(&p.state));
    assert!(!url.contains(&p.verifier));
    assert_eq!(p.state.len(), 43);
    assert_eq!(p.verifier.len(), 43);
}

#[test]
fn pkce_rfc7636_vector() {
    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    assert_eq!(
        URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes())),
        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    );
}

#[test]
fn ed25519_rfc8032_empty_message_vector() {
    let seed: [u8; 32] =
        hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
            .unwrap()
            .try_into()
            .unwrap();
    let key = SigningKey::from_bytes(&seed);
    assert_eq!(
        hex::encode(key.verifying_key().to_bytes()),
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    );
    assert_eq!(
        hex::encode(key.sign(b"").to_bytes()),
        concat!(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155",
            "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        )
    );
}

#[test]
fn proof_binds_exact_transcript_and_uses_fresh_nonce() {
    let key = [7; 32];
    let origin = Origin::parse("https://example.com", false).unwrap();
    let key_id = format!("p:{}", "a".repeat(64));
    let a = proof::sign(
        &key,
        &key_id,
        "POST",
        &origin,
        "/api/v2/pairings/",
        b"{}",
        123,
    )
    .unwrap();
    let b = proof::sign(
        &key,
        &key_id,
        "POST",
        &origin,
        "/api/v2/pairings/",
        b"{}",
        123,
    )
    .unwrap();
    assert_ne!(a.value, b.value);
    let parts: Vec<_> = a.value.split('.').collect();
    assert_eq!(parts.len(), 3);
    let transcript = format!(
        "shika-pop/v1\nPOST\nhttps://example.com\n/api/v2/pairings/\n{}\n123\n{}\n{key_id}",
        hex::encode(Sha256::digest(b"{}")),
        parts[1]
    );
    let signature = Signature::from_slice(&URL_SAFE_NO_PAD.decode(parts[2]).unwrap()).unwrap();
    let public = VerifyingKey::from(&SigningKey::from_bytes(&key));
    assert!(public.verify(transcript.as_bytes(), &signature).is_ok());
    assert!(
        public
            .verify(transcript.replace("POST", "GET").as_bytes(), &signature)
            .is_err()
    );
}

#[test]
fn shika_pop_independent_fixed_vector_and_field_mutations() {
    // Public vector: UW-06-02/shika-pop-v1-vectors-r2.json, SHA-256
    // c1b08dda602c4bf210181df4d27de70a44fc2900461b30d57f73ebef60235a56.
    let seed: [u8; 32] =
        hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
            .unwrap()
            .try_into()
            .unwrap();
    let public: [u8; 32] =
        hex::decode("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
            .unwrap()
            .try_into()
            .unwrap();
    let signature=Signature::from_slice(&hex::decode("4716d728fc3eb968f8b501bcfeee572a35c3bc7d2368b767a936e0fac816cb5b44c432742c58d1102c13ba244c54667632ebbe1b713a683f583ba7d31176d800").unwrap()).unwrap();
    let body =
        b"{\"expectedRevision\":1,\"operationKey\":\"00000000-0000-4000-8000-000000000001\"}";
    assert_eq!(
        hex::encode(Sha256::digest(body)),
        "67570d38e1f78c983f4fb5c8b6644b202c320236f2ac65f24e8d95d36035fd26"
    );
    let transcript = "shika-pop/v1\nPOST\nhttps://api.example.test\n/api/v2/pairings/00000000-0000-4000-8000-000000000002/cancel/\n67570d38e1f78c983f4fb5c8b6644b202c320236f2ac65f24e8d95d36035fd26\n1793181600\nAAECAwQFBgcICQoLDA0ODw\np:21fe31dfa154a261626bf854046fd2271b7bed4b6abe45aa58877ef47f9721b9";
    assert_eq!(
        hex::encode(Sha256::digest(transcript.as_bytes())),
        "4313c965f103c487c08d5cf0c5a941edb05be2a19b9d4bab210b1962368153a3"
    );
    let verifier = VerifyingKey::from_bytes(&public).unwrap();
    assert!(
        verifier
            .verify_strict(transcript.as_bytes(), &signature)
            .is_ok()
    );
    let changed_body =
        b"{\"expectedRevision\":2,\"operationKey\":\"00000000-0000-4000-8000-000000000001\"}";
    for (old, new) in [
        ("POST".to_string(), "GET".to_string()),
        (
            "https://api.example.test".into(),
            "https://other.example.test".into(),
        ),
        ("/cancel/".into(), "/exchange/".into()),
        (
            "67570d38e1f78c983f4fb5c8b6644b202c320236f2ac65f24e8d95d36035fd26".into(),
            hex::encode(Sha256::digest(changed_body)),
        ),
        ("1793181600".into(), "1793181601".into()),
        (
            "AAECAwQFBgcICQoLDA0ODw".into(),
            "AQECAwQFBgcICQoLDA0ODw".into(),
        ),
        (
            "p:21fe31dfa154a261626bf854046fd2271b7bed4b6abe45aa58877ef47f9721b9".into(),
            format!("p:{}", "0".repeat(64)),
        ),
    ] {
        assert!(
            verifier
                .verify_strict(transcript.replace(&old, &new).as_bytes(), &signature)
                .is_err()
        );
    }
    let bad=Signature::from_slice(&hex::decode("0016d728fc3eb968f8b501bcfeee572a35c3bc7d2368b767a936e0fac816cb5b44c432742c58d1102c13ba244c54667632ebbe1b713a683f583ba7d31176d800").unwrap()).unwrap();
    assert!(verifier.verify_strict(transcript.as_bytes(), &bad).is_err());
    let bad_public: [u8; 32] =
        hex::decode("005a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
            .unwrap()
            .try_into()
            .unwrap();
    assert!(
        VerifyingKey::from_bytes(&bad_public).is_err()
            || VerifyingKey::from_bytes(&bad_public)
                .unwrap()
                .verify_strict(transcript.as_bytes(), &signature)
                .is_err()
    );
    assert!(URL_SAFE_NO_PAD.decode("AAECAwQFBgcICQoLDA0ODw==").is_err());
    assert!(URL_SAFE_NO_PAD.decode("RxbXKPw-uWj4tQG8_u5XKjXDvH0jaLdnqTbg-sgWy1tExDJ0LFjRECwTuiRMVGZ2Muu-G3E6aD9YO6fTEXbYAA==").is_err());
    let key_id = "p:21fe31dfa154a261626bf854046fd2271b7bed4b6abe45aa58877ef47f9721b9";
    let origin = Origin::parse("https://api.example.test", false).unwrap();
    let output = proof::sign(
        &seed,
        key_id,
        "POST",
        &origin,
        "/api/v2/pairings/00000000-0000-4000-8000-000000000002/cancel/",
        body,
        1793181600,
    )
    .unwrap();
    let parts: Vec<_> = output.value.split('.').collect();
    let independent = transcript.replace("AAECAwQFBgcICQoLDA0ODw", parts[1]);
    let actual = Signature::from_slice(&URL_SAFE_NO_PAD.decode(parts[2]).unwrap()).unwrap();
    assert!(
        verifier
            .verify_strict(independent.as_bytes(), &actual)
            .is_ok()
    );
    let connection_transcript = "shika-pop/v1\nPOST\nhttps://api.example.test\n/api/v2/connections/00000000-0000-4000-8000-000000000003/revoke/\n67570d38e1f78c983f4fb5c8b6644b202c320236f2ac65f24e8d95d36035fd26\n1793181600\nAAECAwQFBgcICQoLDA0ODw\nc:00000000-0000-4000-8000-000000000003:1";
    let connection_signature=Signature::from_slice(&hex::decode("01c94a8b5ac017a0352b823b4970853820deb147f6ee403aec93e6eff2fdb09c63f7666efb9013b3e31a77aa4e00470a013780bb32f726402c1cceee300f830d").unwrap()).unwrap();
    assert_eq!(
        hex::encode(Sha256::digest(connection_transcript.as_bytes())),
        "46c6c4d7393bdbeebfac072320e4810348888984004e11fecbf790c5ea8bb040"
    );
    assert!(
        verifier
            .verify_strict(connection_transcript.as_bytes(), &connection_signature)
            .is_ok()
    );
    for changed in [
        "c:00000000-0000-4000-8000-000000000003:2",
        "c:00000000-0000-4000-8000-000000000003:01",
        "c:00000000-0000-4000-8000-000000000004:1",
    ] {
        assert!(
            verifier
                .verify_strict(
                    connection_transcript
                        .replace("c:00000000-0000-4000-8000-000000000003:1", changed)
                        .as_bytes(),
                    &connection_signature
                )
                .is_err()
        );
    }
    assert!(
        proof::sign(
            &seed,
            "c:00000000-0000-4000-8000-000000000003:01",
            "POST",
            &origin,
            "/api/v2/connections/00000000-0000-4000-8000-000000000003/revoke/",
            body,
            1793181600
        )
        .is_err()
    );
    let generated = proof::sign(
        &seed,
        "c:00000000-0000-4000-8000-000000000003:1",
        "POST",
        &origin,
        "/api/v2/connections/00000000-0000-4000-8000-000000000003/revoke/",
        body,
        1793181600,
    )
    .unwrap();
    let parts: Vec<_> = generated.value.split('.').collect();
    let independent = connection_transcript.replace("AAECAwQFBgcICQoLDA0ODw", parts[1]);
    let actual = Signature::from_slice(&URL_SAFE_NO_PAD.decode(parts[2]).unwrap()).unwrap();
    assert!(
        verifier
            .verify_strict(independent.as_bytes(), &actual)
            .is_ok()
    );
}

#[test]
fn exact_journal_fences_revoke_and_failed_store() {
    use super::journal::{Binding, Credential, Journal, Kind, Operation};
    let store = FakeStore::default();
    let device_id = Uuid::new_v4();
    let binding = Binding {
        api_origin: "https://api.example.com".into(),
        ui_origin: "https://ui.example.com".into(),
        installation_id: "installation".into(),
        device_id,
        actor_id: Some(Uuid::new_v4()),
        workspace_id: Some(Uuid::new_v4()),
        connection_id: Some(Uuid::new_v4()),
    };
    let metadata = wire::Connection {
        schema_version: "shika.connection/v1".into(),
        connection_id: binding.connection_id.unwrap().to_string(),
        revision: 1,
        origin: binding.api_origin.clone(),
        actor_id: binding.actor_id.unwrap().to_string(),
        workspace_id: binding.workspace_id.unwrap().to_string(),
        device_id: device_id.to_string(),
        installation_id: binding.installation_id.clone(),
        proof_key_thumbprint: String::new(),
        credential_revision: 1,
        status: "active".into(),
        scopes: vec!["shika.read".into()],
    };
    let credential = Credential {
        binding: binding.clone(),
        private_key: [4; 32],
        revision: 1,
        scopes: vec!["shika.read".into()],
        metadata,
    };
    let mut journal = Journal {
        version: 1,
        installation_id: "installation".into(),
        device_id,
        selected: Some(credential),
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
    let op = Operation {
        kind: Kind::Revoke,
        operation_key: Uuid::new_v4(),
        binding,
        method: "POST".into(),
        target: "/api/v2/connections/id/revoke/".into(),
        body: b"{}".to_vec(),
        if_match: Some("revision".into()),
        replacement_key: None,
    };
    *store.fail.lock().unwrap() = true;
    assert!(journal.begin(&store, op.clone()).is_err());
    assert!(journal.pending.is_none());
    *store.fail.lock().unwrap() = false;
    journal.begin(&store, op.clone()).unwrap();
    assert!(journal.disconnect_pending);
    let mut changed = op.clone();
    changed.body = b"changed".to_vec();
    assert!(journal.begin(&store, changed).is_err());
    *store.fail.lock().unwrap() = true;
    assert!(journal.finish(&store, &op, None).is_err());
    assert!(journal.disconnect_pending);
    assert!(journal.pending.is_some());
}

#[test]
fn approval_revision_rejects_null_future_and_accepts_reapproval() {
    let p = PendingPairing::generate(Uuid::new_v4(), Uuid::new_v4());
    let api = Origin::parse("https://api.example.com", false).unwrap();
    let ui = Origin::parse("https://ui.example.com", false).unwrap();
    let scope = vec!["shika.read".to_string()];
    let pairing = wire::Pairing {
        schema_version: "shika.pairing/v1".into(),
        pairing_id: Uuid::new_v4().to_string(),
        operation_key: p.operation_key.to_string(),
        origin: api.0.clone(),
        device_id: p.device_id.to_string(),
        installation_id: "installation".into(),
        proof_key_thumbprint: hex::encode(Sha256::digest(p.public_key())),
        code_challenge: p.challenge(),
        created_at: "2026-01-01T00:00:00Z".into(),
        expires_at: "2026-01-01T00:10:00Z".into(),
        status: "approved".into(),
        actor_id: Some(Uuid::new_v4().to_string()),
        workspace_id: Some(Uuid::new_v4().to_string()),
        exchange_operation_key: None,
    };
    let mut envelope = wire::PairingEnvelope {
        pairing,
        revision: 5,
        ui_origin: ui.0.clone(),
        requested_scopes: scope.clone(),
        approval_revision: None,
        reapproval_required: false,
    };
    assert!(
        envelope
            .validate(&p, &api, &ui, "installation", &scope)
            .is_err()
    );
    envelope.approval_revision = Some(6);
    assert!(
        envelope
            .validate(&p, &api, &ui, "installation", &scope)
            .is_err()
    );
    envelope.approval_revision = Some(3);
    assert!(
        envelope
            .validate(&p, &api, &ui, "installation", &scope)
            .is_ok()
    );
    assert!(envelope.approval_revision.is_none_or(|r| r <= 3));
    envelope.approval_revision = Some(4);
    assert!(
        envelope
            .validate(&p, &api, &ui, "installation", &scope)
            .is_ok()
    );
    assert!(envelope.approval_revision.is_some_and(|r| r > 3));
}

#[test]
fn method_catalog_advertises_only_the_versioned_implemented_surface() {
    let catalog: serde_json::Value =
        serde_json::from_str(include_str!("../../contracts/method-catalog.json")).unwrap();
    let methods = catalog["methods"].as_array().unwrap();
    let caps = catalog["capabilities"].as_array().unwrap();
    for name in [
        "shika.v2.pairing.start",
        "shika.v2.pairing.get",
        "shika.v2.pairing.cancel",
        "shika.v2.pairing.exchange",
        "shika.v2.connection.get",
        "shika.v2.connection.revoke",
        "shika.v2.connection.refresh",
    ] {
        assert_eq!(methods.iter().filter(|m| m["name"] == name).count(), 1);
        assert!(caps.contains(&serde_json::json!(format!("method:{name}"))));
    }
    assert!(
        !caps
            .iter()
            .filter_map(|v| v.as_str())
            .any(|v| v.starts_with("method:shika.") && !v.starts_with("method:shika.v2."))
    );
    assert!(!caps.iter().filter_map(|v| v.as_str()).any(
        |v| v.contains("shika.standing-authority")
            || v.contains("shika.job-bridge")
            || v.contains("shika.codex-background")
    ));
}

#[test]
fn scopes_compare_as_unique_sets_without_rewriting_request() {
    let original = vec!["shika.read".to_owned(), "shika.write".to_owned()];
    assert!(wire::same_scopes(
        &original,
        &["shika.write".into(), "shika.read".into()]
    ));
    assert!(!wire::same_scopes(
        &original,
        &["shika.read".into(), "shika.read".into()]
    ));
    assert!(!wire::same_scopes(&original, &["shika.read".into()]));
    assert_eq!(original, vec!["shika.read", "shika.write"]);
}

#[test]
fn w3_matches_pinned_cross_language_vectors_and_rejects_unsafe_values() {
    let cases = [
        (
            serde_json::json!(null),
            "6e3b",
            "0492cf50f43a86cd8a34e48fb3969f207abed99f8d7a5662fc41cce70fe1e46b",
        ),
        (
            serde_json::json!(-0.0),
            "64303030303030303030303030303030303b",
            "6455e75a524d3fbbc2df7f4cfb82c6de51970d4a956a5b74d1519dac92c1b059",
        ),
        (
            serde_json::json!({"b":[null,-0.0,"ی"],"a":1}),
            "6f323a7b73313a6164336666303030303030303030303030303b73313a6261333a5b6e3b64303030303030303030303030303030303b73323adb8c5d7d",
            "6168d796379b67b346d0f81714aa15ee52428b0fb6756c65a86d1d8b2f9828b5",
        ),
        (
            serde_json::json!({"z":"😀","é":"é","é":"é"}),
            "6f333a7b73333a65cc8173333a65cc8173313a7a73343af09f988073323ac3a973323ac3a97d",
            "f653f02004a3992ebfb0410ba18db4168027fd1d0800bfc79fe0171f24e7bb7b",
        ),
        (
            serde_json::json!([1e-7, 1e-6, 9007199254740991u64, -12.25]),
            "61343a5b64336537616437663239616263616634383b64336562306336663761306235656438643b64343333666666666666666666666666663b64633032383830303030303030303030303b5d",
            "a6208afb62dadb8ec9771102abaa42f58a10e3d8677eb99acf38ee739526fd88",
        ),
        (
            serde_json::json!({"method":"PATCH","path":"/api/v2/tasks/00000000-0000-4000-8000-000000000001/","query":{},"preconditions":{"task:00000000-0000-4000-8000-000000000001":1},"body":{"dueDay":null,"title":"طرح 😀"}}),
            "6f353a7b73343a626f64796f323a7b73363a6475654461796e3b73353a7469746c657331313ad8b7d8b1d8ad20f09f98807d73363a6d6574686f6473353a504154434873343a706174687335313a2f6170692f76322f7461736b732f30303030303030302d303030302d343030302d383030302d3030303030303030303030312f7331333a707265636f6e646974696f6e736f313a7b7334313a7461736b3a30303030303030302d303030302d343030302d383030302d30303030303030303030303164336666303030303030303030303030303b7d73353a71756572796f303a7b7d7d",
            "f74edc49918a7ab45fcc80ea0fce23597b484cac9afca51890f5d5db8b1fc65a",
        ),
    ];
    for (value, encoded, digest) in cases {
        assert_eq!(hex::encode(super::w3::encode(&value).unwrap()), encoded);
        assert_eq!(super::w3::fingerprint(&value).unwrap(), digest);
    }
    assert!(super::w3::encode(&serde_json::json!(9007199254740992u64)).is_err());
    let mut nested = serde_json::json!(null);
    for _ in 0..65 {
        nested = serde_json::json!([nested]);
    }
    assert!(super::w3::encode(&nested).is_err());
}

#[test]
fn local_request_hash_pinned_unicode_vector() {
    let value = serde_json::json!({"params":{"z":"😀","é":"é","é":"é"},"method":"shika.v2.connection.refresh"});
    assert_eq!(
        hex::encode(super::w3::encode(&value).unwrap()),
        "6f323a7b73363a6d6574686f647332373a7368696b612e76322e636f6e6e656374696f6e2e7265667265736873363a706172616d736f333a7b73333a65cc8173333a65cc8173313a7a73343af09f988073323ac3a973323ac3a97d7d"
    );
    assert_eq!(
        super::w3::fingerprint(&value).unwrap(),
        "aa11670fb91ab9103f133052e35c124454d2a0ea5221ae404bc891178b0b1890"
    );
}

#[test]
fn typed_denial_projection_requires_exact_method_and_recovery_negotiation() {
    use super::{
        journal::Kind,
        service::{VerifiedDenial, local_denial},
    };
    let key = Uuid::new_v4();
    let method = "shika.v2.pairing.exchange";
    let params =
        serde_json::json!({"pairingId":Uuid::new_v4(),"expectedRevision":3,"operationKey":key});
    let verified = VerifiedDenial {
        kind: Kind::Exchange,
        operation_key: key,
        request_hash: "a".repeat(64),
        error_code: "approval_snapshot_changed".into(),
        public_params: params.clone(),
    };
    let typed = local_denial(method, &params, &verified).unwrap();
    assert_eq!(
        typed.data()["localRequestHash"],
        super::w3::fingerprint(&serde_json::json!({"method":method,"params":params})).unwrap()
    );
    assert_eq!(
        typed.data()["backendReceipt"]["operationKind"],
        "pairing_exchange"
    );
    let error: anyhow::Error = typed.into();
    let capable = vec![format!("method:{method}")];
    let qualified = crate::control::rpc_error_for_client(&error, method, true, &capable, false);
    assert_eq!(qualified["outcome"], "rejected");
    assert_eq!(qualified["recovery"], "refresh_authority");
    assert_eq!(qualified["data"]["operationKey"], serde_json::json!(key));
    for unqualified in [
        crate::control::rpc_error_for_client(&error, method, false, &capable, true),
        crate::control::rpc_error_for_client(&error, method, true, &[], true),
        crate::control::rpc_error_for_client(
            &error,
            "shika.v2.connection.revoke",
            true,
            &capable,
            true,
        ),
    ] {
        assert!(unqualified.get("data").is_none());
        assert!(unqualified.get("outcome").is_none());
        assert!(unqualified.get("recovery").is_none());
    }
    assert!(local_denial("shika.v2.connection.revoke", &params, &verified).is_err());
    let mut changed = params.clone();
    changed["operationKey"] = serde_json::json!(Uuid::new_v4());
    assert!(local_denial(method, &changed, &verified).is_err());
    changed = params.clone();
    changed["expectedRevision"] = serde_json::json!(4);
    assert!(local_denial(method, &changed, &verified).is_err());
    let spoof = anyhow::anyhow!("SHIKA_APPROVAL_CHANGED");
    let untyped = crate::control::rpc_error_for_client(&spoof, method, true, &capable, false);
    assert!(untyped.get("data").is_none());
    assert_ne!(untyped["outcome"], "rejected");
}

#[test]
fn terminal_denial_requires_exact_authoritative_receipt_and_w3_hash() {
    use super::journal::{Binding, Kind, Operation};
    let pairing = Uuid::new_v4();
    let key = Uuid::new_v4();
    let binding = Binding {
        api_origin: "https://api.example.com".into(),
        ui_origin: "https://ui.example.com".into(),
        installation_id: "installation".into(),
        device_id: Uuid::new_v4(),
        actor_id: Some(Uuid::new_v4()),
        workspace_id: Some(Uuid::new_v4()),
        connection_id: None,
    };
    let body = serde_json::to_vec(
        &serde_json::json!({"codeVerifier":"a","expectedRevision":3,"operationKey":key}),
    )
    .unwrap();
    let op = Operation {
        kind: Kind::Exchange,
        operation_key: key,
        binding,
        method: "POST".into(),
        target: format!("/api/v2/pairings/{pairing}/exchange/"),
        body,
        if_match: Some(format!("\"pairing:{pairing}:3\"")),
        replacement_key: None,
    };
    let hash = super::w3::operation_fingerprint(&op).unwrap();
    let mut error = serde_json::json!({"schemaVersion":"2.0","status":409,"code":"approval_snapshot_changed","message":"Denied","requestId":Uuid::new_v4(),"violations":[],"details":{"operationReceipt":{"schemaVersion":"shika.pairing-denial/v1","operationKind":"pairing_exchange","operationKey":key,"requestHash":hash.clone(),"terminal":true,"committed":false,"errorCode":"approval_snapshot_changed"}}});
    let valid = |v: &serde_json::Value, status| {
        super::w3::verified_denial(status, &serde_json::to_vec(v).unwrap(), &op)
            .unwrap()
            .is_some()
    };
    assert!(valid(&error, 409));
    error["details"]["operationReceipt"]["requestHash"] = serde_json::json!("0".repeat(64));
    assert!(!valid(&error, 409));
    error["details"]["operationReceipt"]["requestHash"] = serde_json::json!(hash);
    error["details"]["operationReceipt"]["committed"] = serde_json::json!(true);
    assert!(!valid(&error, 409));
    error["details"]["operationReceipt"]["committed"] = serde_json::json!(false);
    error["details"]["operationReceipt"]["operationKind"] = serde_json::json!("connection_revoke");
    assert!(!valid(&error, 409));
    error["details"]["operationReceipt"]["operationKind"] = serde_json::json!("pairing_exchange");
    error["details"]["operationReceipt"]["operationKey"] = serde_json::json!(Uuid::new_v4());
    assert!(!valid(&error, 409));
    error["details"]["operationReceipt"]["operationKey"] = serde_json::json!(key);
    error["details"]["operationReceipt"]["errorCode"] = serde_json::json!("needs_attention");
    assert!(!valid(&error, 409));
    assert!(!valid(&error, 401));
    assert!(!valid(&error, 429));
    assert!(!valid(&error, 503));
}

#[test]
fn denial_receipt_is_durable_before_pending_operation_is_retired() {
    use super::journal::{Binding, Journal, Kind, Operation};
    let store = FakeStore::default();
    let device = Uuid::new_v4();
    let pairing_id = Uuid::new_v4();
    let key = Uuid::new_v4();
    let mut pairing = PendingPairing::generate(device, Uuid::new_v4());
    pairing.bind_request(b"start".to_vec()).unwrap();
    pairing.pairing_id = Some(pairing_id);
    let binding = Binding {
        api_origin: "https://api.example.com".into(),
        ui_origin: "https://ui.example.com".into(),
        installation_id: "installation".into(),
        device_id: device,
        actor_id: Some(Uuid::new_v4()),
        workspace_id: Some(Uuid::new_v4()),
        connection_id: None,
    };
    let op = Operation {
        kind: Kind::Exchange,
        operation_key: key,
        binding,
        method: "POST".into(),
        target: format!("/api/v2/pairings/{pairing_id}/exchange/"),
        body: serde_json::to_vec(
            &serde_json::json!({"codeVerifier":"a","expectedRevision":3,"operationKey":key}),
        )
        .unwrap(),
        if_match: Some(format!("\"pairing:{pairing_id}:3\"")),
        replacement_key: None,
    };
    let hash = super::w3::operation_fingerprint(&op).unwrap();
    let mut state = Journal {
        version: 1,
        installation_id: "installation".into(),
        device_id: device,
        selected: None,
        other_credentials: vec![],
        pending_pairing: Some(pairing),
        completed_exchanges: vec![],
        completed_cancels: vec![],
        rejected_exchanges: vec![],
        completed_refreshes: vec![],
        denied_operations: vec![],
        tombstones: vec![],
        known_connections: vec![],
        pending: Some(op.clone()),
        disconnect_pending: false,
    };
    store.save(&serde_json::to_vec(&state).unwrap()).unwrap();
    *store.fail.lock().unwrap() = true;
    assert!(
        state
            .settle_denial(&store, &op, "approval_snapshot_changed", &hash)
            .is_err()
    );
    assert!(load_state(&store).unwrap().unwrap().pending.as_ref() == Some(&op));
    *store.fail.lock().unwrap() = false;
    state
        .settle_denial(&store, &op, "approval_snapshot_changed", &hash)
        .unwrap();
    assert!(state.pending.is_none());
    assert_eq!(state.denied_operations[0].request_hash, hash);
    assert!(state.begin(&store, op).is_err());
}

#[test]
fn valid_denial_failed_store_never_produces_typed_outcome() {
    use super::journal::{Binding, Journal, Kind, Operation};
    let context = FakeContext::default();
    let device = Uuid::new_v4();
    let id = Uuid::new_v4();
    let key = Uuid::new_v4();
    let mut pairing = PendingPairing::generate(device, Uuid::new_v4());
    pairing.pairing_id = Some(id);
    pairing.bind_request(b"start".to_vec()).unwrap();
    let binding = Binding {
        api_origin: "https://api.example.com".into(),
        ui_origin: "https://ui.example.com".into(),
        installation_id: "installation".into(),
        device_id: device,
        actor_id: Some(Uuid::new_v4()),
        workspace_id: Some(Uuid::new_v4()),
        connection_id: None,
    };
    let op = Operation {
        kind: Kind::Exchange,
        operation_key: key,
        binding,
        method: "POST".into(),
        target: format!("/api/v2/pairings/{id}/exchange/"),
        body: serde_json::to_vec(
            &serde_json::json!({"operationKey":key,"expectedRevision":3,"codeVerifier":"value"}),
        )
        .unwrap(),
        if_match: Some(format!("\"pairing:{id}:3\"")),
        replacement_key: None,
    };
    let hash = super::w3::operation_fingerprint(&op).unwrap();
    let receipt = serde_json::json!({"schemaVersion":"2.0","status":409,"code":"approval_snapshot_changed","message":"Denied","requestId":Uuid::new_v4(),"violations":[],"details":{"operationReceipt":{"schemaVersion":"shika.pairing-denial/v1","operationKind":"pairing_exchange","operationKey":key,"requestHash":hash,"terminal":true,"committed":false,"errorCode":"approval_snapshot_changed"}}});
    let mut journal = Journal {
        version: 1,
        installation_id: "installation".into(),
        device_id: device,
        selected: None,
        other_credentials: vec![],
        pending_pairing: Some(pairing),
        completed_exchanges: vec![],
        completed_cancels: vec![],
        rejected_exchanges: vec![],
        completed_refreshes: vec![],
        denied_operations: vec![],
        tombstones: vec![],
        known_connections: vec![],
        pending: Some(op.clone()),
        disconnect_pending: false,
    };
    *context.store.fail.lock().unwrap() = true;
    let params = serde_json::json!({"pairingId":id,"expectedRevision":3,"operationKey":key});
    let error = super::service::settle_denial_if_verified(
        &context,
        &mut journal,
        &op,
        409,
        &serde_json::to_vec(&receipt).unwrap(),
        &params,
    )
    .unwrap_err();
    assert!(
        error
            .downcast_ref::<super::service::VerifiedDenial>()
            .is_none()
    );
    assert!(journal.pending.as_ref() == Some(&op));
}

#[test]
fn denied_refresh_discards_unused_private_key_but_retains_exact_request_hash() {
    use super::journal::{Binding, Journal, Kind, Operation};
    let store = FakeStore::default();
    let device = Uuid::new_v4();
    let id = Uuid::new_v4();
    let key = Uuid::new_v4();
    let binding = Binding {
        api_origin: "https://api.example.com".into(),
        ui_origin: "https://ui.example.com".into(),
        installation_id: "installation".into(),
        device_id: device,
        actor_id: Some(Uuid::new_v4()),
        workspace_id: Some(Uuid::new_v4()),
        connection_id: Some(id),
    };
    let op = Operation {
        kind: Kind::Refresh,
        operation_key: key,
        binding,
        method: "POST".into(),
        target: format!("/api/v2/connections/{id}/refresh/"),
        body: serde_json::to_vec(
            &serde_json::json!({"operationKey":key,"expectedRevision":1,"newPublicKey":"public"}),
        )
        .unwrap(),
        if_match: Some(format!("\"connection:{id}:1\"")),
        replacement_key: Some([7; 32]),
    };
    let hash = super::w3::operation_fingerprint(&op).unwrap();
    let mut journal = Journal {
        version: 1,
        installation_id: "installation".into(),
        device_id: device,
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
        pending: Some(op.clone()),
        disconnect_pending: false,
    };
    journal
        .settle_denial(&store, &op, "revision_conflict", &hash)
        .unwrap();
    let denied = &journal.denied_operations[0];
    assert!(denied.operation.replacement_key.is_none());
    assert_eq!(
        super::w3::operation_fingerprint(&denied.operation).unwrap(),
        hash
    );
}

#[test]
fn refresh_failed_final_store_keeps_exact_operation_and_replacement_key() {
    use super::journal::{Binding, Credential, Journal, Kind, Operation};
    let store = FakeStore::default();
    let device = Uuid::new_v4();
    let actor = Uuid::new_v4();
    let workspace = Uuid::new_v4();
    let connection = Uuid::new_v4();
    let binding = Binding {
        api_origin: "https://api.example.com".into(),
        ui_origin: "https://ui.example.com".into(),
        installation_id: "installation".into(),
        device_id: device,
        actor_id: Some(actor),
        workspace_id: Some(workspace),
        connection_id: Some(connection),
    };
    let scopes = vec!["shika.read".to_owned()];
    let metadata = |key: [u8; 32], revision| wire::Connection {
        schema_version: "shika.connection/v1".into(),
        connection_id: connection.to_string(),
        revision,
        origin: binding.api_origin.clone(),
        actor_id: actor.to_string(),
        workspace_id: workspace.to_string(),
        device_id: device.to_string(),
        installation_id: binding.installation_id.clone(),
        proof_key_thumbprint: hex::encode(Sha256::digest(
            SigningKey::from_bytes(&key).verifying_key().to_bytes(),
        )),
        credential_revision: revision,
        status: "active".into(),
        scopes: scopes.clone(),
    };
    let old = Credential {
        binding: binding.clone(),
        private_key: [1; 32],
        revision: 1,
        scopes: scopes.clone(),
        metadata: metadata([1; 32], 1),
    };
    let updated = Credential {
        binding: binding.clone(),
        private_key: [2; 32],
        revision: 2,
        scopes: scopes.clone(),
        metadata: metadata([2; 32], 2),
    };
    let operation = Operation {
        kind: Kind::Refresh,
        operation_key: Uuid::new_v4(),
        binding,
        method: "POST".into(),
        target: format!("/api/v2/connections/{connection}/refresh/"),
        body: b"exact bytes".to_vec(),
        if_match: Some(format!("\"connection:{connection}:1\"")),
        replacement_key: Some([2; 32]),
    };
    let mut state = Journal {
        version: 1,
        installation_id: "installation".into(),
        device_id: device,
        selected: Some(old),
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
    state.begin(&store, operation.clone()).unwrap();
    *store.fail.lock().unwrap() = true;
    assert!(
        state
            .finish(&store, &operation, Some(updated.clone()))
            .is_err()
    );
    let recovered = load_state(&store).unwrap().unwrap();
    assert!(recovered.pending.as_ref() == Some(&operation));
    assert_eq!(recovered.selected.unwrap().private_key, [1; 32]);
    *store.fail.lock().unwrap() = false;
    state.finish(&store, &operation, Some(updated)).unwrap();
    assert_eq!(
        state.completed_refreshes[0].operation.body.as_slice(),
        b"exact bytes"
    );
}

#[tokio::test]
async fn refresh_lost_response_reuses_body_and_proves_with_new_key() {
    use super::journal::{Binding, Credential, Journal};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let context = FakeContext::default();
    *context.marker.lock().unwrap() = true;
    let device = Uuid::new_v4();
    let actor = Uuid::new_v4();
    let workspace = Uuid::new_v4();
    let connection = Uuid::new_v4();
    let binding = Binding {
        api_origin: origin.clone(),
        ui_origin: origin.clone(),
        installation_id: "installation".into(),
        device_id: device,
        actor_id: Some(actor),
        workspace_id: Some(workspace),
        connection_id: Some(connection),
    };
    let scopes = vec!["shika.read".to_owned()];
    let old_key = [1u8; 32];
    let old = wire::Connection {
        schema_version: "shika.connection/v1".into(),
        connection_id: connection.to_string(),
        revision: 1,
        origin: origin.clone(),
        actor_id: actor.to_string(),
        workspace_id: workspace.to_string(),
        device_id: device.to_string(),
        installation_id: "installation".into(),
        proof_key_thumbprint: hex::encode(Sha256::digest(
            SigningKey::from_bytes(&old_key).verifying_key().to_bytes(),
        )),
        credential_revision: 1,
        status: "active".into(),
        scopes: scopes.clone(),
    };
    let state = Journal {
        version: 1,
        installation_id: "installation".into(),
        device_id: device,
        selected: Some(Credential {
            binding,
            private_key: old_key,
            revision: 1,
            scopes,
            metadata: old.clone(),
        }),
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
    persist_new(&context.store, &state).unwrap();
    let server = tokio::spawn(async move {
        let mut first_body = Vec::new();
        for attempt in 0..2 {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buffer = Vec::new();
            let mut chunk = [0; 4096];
            let end;
            loop {
                let n = socket.read(&mut chunk).await.unwrap();
                assert!(n > 0);
                buffer.extend_from_slice(&chunk[..n]);
                if let Some(i) = buffer.windows(4).position(|x| x == b"\r\n\r\n") {
                    end = i + 4;
                    break;
                }
            }
            let headers = String::from_utf8(buffer[..end].to_vec()).unwrap();
            let length: usize = headers
                .lines()
                .find_map(|line| {
                    line.split_once(':')
                        .filter(|(k, _)| k.eq_ignore_ascii_case("content-length"))
                        .map(|(_, v)| v.trim().parse().unwrap())
                })
                .unwrap();
            while buffer.len() < end + length {
                let n = socket.read(&mut chunk).await.unwrap();
                assert!(n > 0);
                buffer.extend_from_slice(&chunk[..n]);
            }
            let body = buffer[end..end + length].to_vec();
            let key_id = headers
                .lines()
                .find_map(|l| {
                    l.split_once(':')
                        .filter(|(k, _)| k.eq_ignore_ascii_case("x-shika-key-id"))
                        .map(|(_, v)| v.trim())
                })
                .unwrap();
            assert_eq!(key_id, format!("c:{connection}:{}", attempt + 1));
            if attempt == 0 {
                first_body = body;
                continue;
            }
            assert_eq!(body, first_body);
            let request: serde_json::Value = serde_json::from_slice(&body).unwrap();
            let mut response = serde_json::to_value(&old).unwrap();
            response["revision"] = serde_json::json!(2);
            response["credentialRevision"] = serde_json::json!(2);
            response["proofKeyThumbprint"] = request["newProofKeyThumbprint"].clone();
            let bytes = serde_json::to_vec(&response).unwrap();
            socket.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", bytes.len()).as_bytes()).await.unwrap();
            socket.write_all(&bytes).await.unwrap();
        }
    });
    let params = serde_json::json!({"resourceId":connection,"expectedRevision":1,"operationKey":Uuid::new_v4()});
    let config = || TrustedOrigins::from_config(&origin, &origin, true).unwrap();
    assert!(
        super::service::connection_refresh_with(&context, config(), &params, "installation")
            .await
            .is_err()
    );
    assert!(
        load_state(&context.store)
            .unwrap()
            .unwrap()
            .pending
            .is_some()
    );
    let result =
        super::service::connection_refresh_with(&context, config(), &params, "installation")
            .await
            .unwrap();
    assert_eq!(result["credentialRevision"], 2);
    server.await.unwrap();
}

#[tokio::test]
async fn denial_replay_resends_original_and_requires_current_server_authority() {
    use super::journal::{Binding, Journal, Kind, Operation, TerminalDenial};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let context = FakeContext::default();
    *context.marker.lock().unwrap() = true;
    let device = Uuid::new_v4();
    let key = Uuid::new_v4();
    let mut pairing = PendingPairing::generate(device, key);
    pairing.api_origin = origin.clone();
    pairing.ui_origin = origin.clone();
    let body = serde_json::to_vec(&serde_json::json!({"deviceId":device,"installationId":"installation","publicKey":wire::public_key_text(&pairing.public_key()),"proofKeyThumbprint":hex::encode(Sha256::digest(pairing.public_key())),"codeChallenge":pairing.challenge(),"uiOrigin":origin,"requestedScopes":["shika.read","shika.write"],"stateHash":pairing.state_hash(),"operationKey":key})).unwrap();
    pairing.bind_request(body.clone()).unwrap();
    let binding = Binding {
        api_origin: origin.clone(),
        ui_origin: origin.clone(),
        installation_id: "installation".into(),
        device_id: device,
        actor_id: None,
        workspace_id: None,
        connection_id: None,
    };
    let op = Operation {
        kind: Kind::Start,
        operation_key: key,
        binding,
        method: "POST".into(),
        target: "/api/v2/pairings/".into(),
        body: body.clone(),
        if_match: None,
        replacement_key: None,
    };
    let hash = super::w3::operation_fingerprint(&op).unwrap();
    let state = Journal {
        version: 1,
        installation_id: "installation".into(),
        device_id: device,
        selected: None,
        other_credentials: vec![],
        pending_pairing: None,
        completed_exchanges: vec![],
        completed_cancels: vec![],
        rejected_exchanges: vec![],
        completed_refreshes: vec![],
        denied_operations: vec![TerminalDenial {
            operation: op,
            error_code: "needs_attention".into(),
            request_hash: hash.clone(),
            pairing: Some(pairing),
        }],
        tombstones: vec![],
        known_connections: vec![],
        pending: None,
        disconnect_pending: false,
    };
    persist_new(&context.store, &state).unwrap();
    let server = tokio::spawn(async move {
        for attempt in 0..2 {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut bytes = Vec::new();
            let mut block = [0; 4096];
            let end;
            loop {
                let n = socket.read(&mut block).await.unwrap();
                assert!(n > 0);
                bytes.extend_from_slice(&block[..n]);
                if let Some(i) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                    end = i + 4;
                    break;
                }
            }
            let header = String::from_utf8(bytes[..end].to_vec()).unwrap();
            let len: usize = header
                .lines()
                .find_map(|l| {
                    l.split_once(':')
                        .filter(|(k, _)| k.eq_ignore_ascii_case("content-length"))
                        .map(|(_, v)| v.trim().parse().unwrap())
                })
                .unwrap();
            while bytes.len() < end + len {
                let n = socket.read(&mut block).await.unwrap();
                assert!(n > 0);
                bytes.extend_from_slice(&block[..n]);
            }
            assert_eq!(&bytes[end..end + len], body.as_slice());
            let (status, response) = if attempt == 0 {
                (
                    409,
                    serde_json::json!({"schemaVersion":"2.0","status":409,"code":"needs_attention","message":"Denied","requestId":Uuid::new_v4(),"violations":[],"details":{"operationReceipt":{"schemaVersion":"shika.pairing-denial/v1","operationKind":"pairing_start","operationKey":key,"requestHash":hash,"terminal":true,"committed":false,"errorCode":"needs_attention"}}}),
                )
            } else {
                (401, serde_json::json!({}))
            };
            let response = serde_json::to_vec(&response).unwrap();
            socket.write_all(format!("HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", response.len()).as_bytes()).await.unwrap();
            socket.write_all(&response).await.unwrap();
        }
    });
    let config = || TrustedOrigins::from_config(&origin, &origin, true).unwrap();
    let mut params = serde_json::json!({"origin":origin,"uiOrigin":origin,"requestedScopes":["shika.write","shika.read"],"operationKey":key});
    let before = context.store.load().unwrap().unwrap();
    let changed = super::service::pairing_start_with(&context, config(), &params, "installation")
        .await
        .unwrap_err();
    assert_eq!(changed.to_string(), "SHIKA_RECOVERY_REQUIRED");
    assert!(
        changed
            .downcast_ref::<super::service::VerifiedDenial>()
            .is_none()
    );
    assert_eq!(context.store.load().unwrap().unwrap(), before);
    params["requestedScopes"] = serde_json::json!(["shika.read", "shika.write"]);
    let exact = super::service::pairing_start_with(&context, config(), &params, "installation")
        .await
        .unwrap_err();
    assert_eq!(exact.to_string(), "SHIKA_OPERATION_DENIED");
    let local = super::service::local_denial(
        "shika.v2.pairing.start",
        &params,
        exact
            .downcast_ref::<super::service::VerifiedDenial>()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        local.data()["localRequestHash"],
        super::w3::fingerprint(
            &serde_json::json!({"method":"shika.v2.pairing.start","params":params})
        )
        .unwrap()
    );
    assert_eq!(
        super::service::pairing_start_with(&context, config(), &params, "installation")
            .await
            .unwrap_err()
            .to_string(),
        "SHIKA_RECOVERY_REQUIRED"
    );
    server.await.unwrap();
}

#[tokio::test]
async fn ambiguous_start_rejects_reordered_scopes_before_network_or_state_change() {
    use super::journal::{Binding, Journal, Kind, Operation};
    let context = FakeContext::default();
    *context.marker.lock().unwrap() = true;
    let origin = "http://127.0.0.1:9";
    let device = Uuid::new_v4();
    let key = Uuid::new_v4();
    let mut pairing = PendingPairing::generate(device, key);
    pairing.api_origin = origin.into();
    pairing.ui_origin = origin.into();
    let body=serde_json::to_vec(&serde_json::json!({"operationKey":key,"uiOrigin":origin,"requestedScopes":["shika.read","shika.write"]})).unwrap();
    pairing.bind_request(body.clone()).unwrap();
    let binding = Binding {
        api_origin: origin.into(),
        ui_origin: origin.into(),
        installation_id: "installation".into(),
        device_id: device,
        actor_id: None,
        workspace_id: None,
        connection_id: None,
    };
    let op = Operation {
        kind: Kind::Start,
        operation_key: key,
        binding,
        method: "POST".into(),
        target: "/api/v2/pairings/".into(),
        body,
        if_match: None,
        replacement_key: None,
    };
    let state = Journal {
        version: 1,
        installation_id: "installation".into(),
        device_id: device,
        selected: None,
        other_credentials: vec![],
        pending_pairing: Some(pairing),
        completed_exchanges: vec![],
        completed_cancels: vec![],
        rejected_exchanges: vec![],
        completed_refreshes: vec![],
        denied_operations: vec![],
        tombstones: vec![],
        known_connections: vec![],
        pending: Some(op),
        disconnect_pending: false,
    };
    persist_new(&context.store, &state).unwrap();
    let before = context.store.load().unwrap().unwrap();
    let config = || TrustedOrigins::from_config(origin, origin, true).unwrap();
    let mut params = serde_json::json!({"origin":origin,"uiOrigin":origin,"requestedScopes":["shika.write","shika.read"],"operationKey":key});
    let error = super::service::pairing_start_with(&context, config(), &params, "installation")
        .await
        .unwrap_err();
    assert_eq!(error.to_string(), "SHIKA_RECOVERY_REQUIRED");
    assert!(
        error
            .downcast_ref::<super::service::VerifiedDenial>()
            .is_none()
    );
    assert_eq!(context.store.load().unwrap().unwrap(), before);
    params["operationKey"] = serde_json::json!(Uuid::new_v4());
    assert!(
        super::service::pairing_start_with(&context, config(), &params, "installation")
            .await
            .is_err()
    );
    assert_eq!(context.store.load().unwrap().unwrap(), before);
    params["operationKey"] = serde_json::json!(key);
    params["uiOrigin"] = serde_json::json!("http://localhost:9");
    assert!(
        super::service::pairing_start_with(&context, config(), &params, "installation")
            .await
            .is_err()
    );
    assert_eq!(context.store.load().unwrap().unwrap(), before);
}

#[tokio::test]
async fn expired_pairing_is_retired_only_after_server_observation_and_old_key_stays_used() {
    use super::journal::{Binding, Journal, Kind, Operation, TerminalDenial};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let context = FakeContext::default();
    *context.marker.lock().unwrap() = true;
    let device = Uuid::new_v4();
    let old_key = Uuid::new_v4();
    let old_id = Uuid::new_v4();
    let mut pairing = PendingPairing::generate(device, old_key);
    pairing.api_origin = origin.clone();
    pairing.ui_origin = origin.clone();
    pairing.pairing_id = Some(old_id);
    pairing.created_at = Some("2026-01-01T00:00:00Z".into());
    pairing.expires_at = Some("2026-01-01T00:10:00Z".into());
    let request = serde_json::json!({"deviceId":device,"installationId":"installation","publicKey":wire::public_key_text(&pairing.public_key()),"proofKeyThumbprint":hex::encode(Sha256::digest(pairing.public_key())),"codeChallenge":pairing.challenge(),"uiOrigin":origin,"requestedScopes":["shika.read"],"stateHash":pairing.state_hash(),"operationKey":old_key});
    pairing
        .bind_request(serde_json::to_vec(&request).unwrap())
        .unwrap();
    let denied_key = Uuid::new_v4();
    let denied_op = Operation {
        kind: Kind::Cancel,
        operation_key: denied_key,
        binding: Binding {
            api_origin: origin.clone(),
            ui_origin: origin.clone(),
            installation_id: "installation".into(),
            device_id: device,
            actor_id: None,
            workspace_id: None,
            connection_id: None,
        },
        method: "POST".into(),
        target: format!("/api/v2/pairings/{old_id}/cancel/"),
        body: serde_json::to_vec(
            &serde_json::json!({"operationKey":denied_key,"expectedRevision":1}),
        )
        .unwrap(),
        if_match: Some(format!("\"pairing:{old_id}:1\"")),
        replacement_key: None,
    };
    let denied_hash = super::w3::operation_fingerprint(&denied_op).unwrap();
    let state = Journal {
        version: 1,
        installation_id: "installation".into(),
        device_id: device,
        selected: None,
        other_credentials: vec![],
        pending_pairing: Some(pairing.clone()),
        completed_exchanges: vec![],
        completed_cancels: vec![],
        rejected_exchanges: vec![],
        completed_refreshes: vec![],
        denied_operations: vec![TerminalDenial {
            operation: denied_op,
            error_code: "needs_attention".into(),
            request_hash: denied_hash,
            pairing: Some(pairing),
        }],
        tombstones: vec![],
        known_connections: vec![],
        pending: None,
        disconnect_pending: false,
    };
    persist_new(&context.store, &state).unwrap();
    let server_origin = origin.clone();
    let server = tokio::spawn(async move {
        for attempt in 0..2 {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut raw = Vec::new();
            let mut part = [0u8; 4096];
            let end;
            loop {
                let n = socket.read(&mut part).await.unwrap();
                assert!(n > 0);
                raw.extend_from_slice(&part[..n]);
                if let Some(i) = raw.windows(4).position(|v| v == b"\r\n\r\n") {
                    end = i + 4;
                    break;
                }
            }
            let headers = String::from_utf8(raw[..end].to_vec()).unwrap();
            let len: usize = headers
                .lines()
                .find_map(|l| {
                    l.split_once(':')
                        .filter(|(k, _)| k.eq_ignore_ascii_case("content-length"))
                        .map(|(_, v)| v.trim().parse().unwrap())
                })
                .unwrap_or(0);
            while raw.len() < end + len {
                let n = socket.read(&mut part).await.unwrap();
                assert!(n > 0);
                raw.extend_from_slice(&part[..n]);
            }
            let sent = if attempt == 0 {
                request.clone()
            } else {
                serde_json::from_slice::<serde_json::Value>(&raw[end..end + len]).unwrap()
            };
            assert_eq!(sent["deviceId"], serde_json::json!(device));
            let id = if attempt == 0 { old_id } else { Uuid::new_v4() };
            let response = serde_json::json!({"pairing":{"schemaVersion":"shika.pairing/v1","pairingId":id,"operationKey":sent["operationKey"],"origin":server_origin,"deviceId":sent["deviceId"],"installationId":sent["installationId"],"proofKeyThumbprint":sent["proofKeyThumbprint"],"codeChallenge":sent["codeChallenge"],"createdAt":"2026-01-01T00:00:00Z","expiresAt":"2026-01-01T00:10:00Z","status":if attempt==0 {"expired"} else {"pending"},"actorId":null,"workspaceId":null,"exchangeOperationKey":null},"revision":1,"uiOrigin":sent["uiOrigin"],"requestedScopes":sent["requestedScopes"],"approvalRevision":null,"reapprovalRequired":false});
            let bytes = serde_json::to_vec(&response).unwrap();
            let code = if attempt == 0 { 200 } else { 201 };
            socket.write_all(format!("HTTP/1.1 {code} OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",bytes.len()).as_bytes()).await.unwrap();
            socket.write_all(&bytes).await.unwrap();
        }
    });
    let config = || TrustedOrigins::from_config(&origin, &origin, true).unwrap();
    let new_key = Uuid::new_v4();
    let mut params = serde_json::json!({"origin":origin,"uiOrigin":origin,"requestedScopes":["shika.read"],"operationKey":new_key});
    assert!(
        super::service::pairing_start_with(&context, config(), &params, "installation")
            .await
            .is_ok()
    );
    server.await.unwrap();
    let restarted = load_state(&context.store).unwrap().unwrap();
    assert!(
        restarted
            .tombstones
            .iter()
            .any(|v| v.operation_key == old_key)
    );
    assert!(
        restarted
            .tombstones
            .iter()
            .any(|v| v.operation_key == denied_key)
    );
    assert_eq!(restarted.device_id, device);
    params["operationKey"] = serde_json::json!(old_key);
    assert!(
        super::service::pairing_start_with(&context, config(), &params, "installation")
            .await
            .is_err()
    );
    assert_eq!(
        load_state(&context.store)
            .unwrap()
            .unwrap()
            .pending_pairing
            .unwrap()
            .operation_key,
        new_key
    );
}

#[tokio::test]
async fn unresolved_exchange_and_cancelled_start_key_never_generate_replacement() {
    use super::journal::{Binding, CompletedExchange, Journal, Kind, Operation};
    let context = FakeContext::default();
    *context.marker.lock().unwrap() = true;
    let device = Uuid::new_v4();
    let start_key = Uuid::new_v4();
    let id = Uuid::new_v4();
    let origin = "http://127.0.0.1:9";
    let mut p = PendingPairing::generate(device, start_key);
    p.api_origin = origin.into();
    p.ui_origin = origin.into();
    p.pairing_id = Some(id);
    p.bind_request(b"{}".to_vec()).unwrap();
    let binding = Binding {
        api_origin: origin.into(),
        ui_origin: origin.into(),
        installation_id: "installation".into(),
        device_id: device,
        actor_id: None,
        workspace_id: None,
        connection_id: None,
    };
    let op = Operation {
        kind: Kind::Exchange,
        operation_key: Uuid::new_v4(),
        binding: binding.clone(),
        method: "POST".into(),
        target: format!("/api/v2/pairings/{id}/exchange/"),
        body: b"{}".to_vec(),
        if_match: None,
        replacement_key: None,
    };
    let mut state = Journal {
        version: 1,
        installation_id: "installation".into(),
        device_id: device,
        selected: None,
        other_credentials: vec![],
        pending_pairing: Some(p.clone()),
        completed_exchanges: vec![],
        completed_cancels: vec![],
        rejected_exchanges: vec![],
        completed_refreshes: vec![],
        denied_operations: vec![],
        tombstones: vec![],
        known_connections: vec![],
        pending: Some(op.clone()),
        disconnect_pending: false,
    };
    persist_new(&context.store, &state).unwrap();
    let config = || TrustedOrigins::from_config(origin, origin, true).unwrap();
    let mut params = serde_json::json!({"origin":origin,"uiOrigin":origin,"requestedScopes":["shika.read"],"operationKey":Uuid::new_v4()});
    assert!(
        super::service::pairing_start_with(&context, config(), &params, "installation")
            .await
            .is_err()
    );
    assert!(
        load_state(&context.store)
            .unwrap()
            .unwrap()
            .pending
            .as_ref()
            == Some(&op)
    );
    state.pending = None;
    state.pending_pairing = None;
    let cancel = Operation {
        kind: Kind::Cancel,
        operation_key: Uuid::new_v4(),
        binding,
        method: "POST".into(),
        target: format!("/api/v2/pairings/{id}/cancel/"),
        body: b"{}".to_vec(),
        if_match: None,
        replacement_key: None,
    };
    state.completed_cancels.push(CompletedExchange {
        pairing: p,
        operation: cancel,
    });
    context
        .store
        .save(&serde_json::to_vec(&state).unwrap())
        .unwrap();
    params["operationKey"] = serde_json::json!(start_key);
    assert_eq!(
        super::service::pairing_start_with(&context, config(), &params, "installation")
            .await
            .unwrap_err()
            .to_string(),
        "SHIKA_RECOVERY_REQUIRED"
    );
    assert!(
        load_state(&context.store)
            .unwrap()
            .unwrap()
            .pending
            .is_none()
    );
}

#[tokio::test]
async fn consumed_server_observation_never_retires_pairing_for_new_start() {
    use super::journal::Journal;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let context = FakeContext::default();
    *context.marker.lock().unwrap() = true;
    let device = Uuid::new_v4();
    let id = Uuid::new_v4();
    let old_key = Uuid::new_v4();
    let mut p = PendingPairing::generate(device, old_key);
    p.pairing_id = Some(id);
    p.api_origin = origin.clone();
    p.ui_origin = origin.clone();
    p.created_at = Some("2026-01-01T00:00:00Z".into());
    p.expires_at = Some("2026-01-01T00:10:00Z".into());
    p.bind_request(
        serde_json::to_vec(
            &serde_json::json!({"operationKey":old_key,"requestedScopes":["shika.read"]}),
        )
        .unwrap(),
    )
    .unwrap();
    let response = serde_json::json!({"pairing":{"schemaVersion":"shika.pairing/v1","pairingId":id,"operationKey":old_key,"origin":origin,"deviceId":device,"installationId":"installation","proofKeyThumbprint":hex::encode(Sha256::digest(p.public_key())),"codeChallenge":p.challenge(),"createdAt":"2026-01-01T00:00:00Z","expiresAt":"2026-01-01T00:10:00Z","status":"consumed","actorId":Uuid::new_v4(),"workspaceId":Uuid::new_v4(),"exchangeOperationKey":Uuid::new_v4()},"revision":3,"uiOrigin":origin,"requestedScopes":["shika.read"],"approvalRevision":2,"reapprovalRequired":false});
    let state = Journal {
        version: 1,
        installation_id: "installation".into(),
        device_id: device,
        selected: None,
        other_credentials: vec![],
        pending_pairing: Some(p),
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
    persist_new(&context.store, &state).unwrap();
    let before = context.store.load().unwrap().unwrap();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut data = [0u8; 2048];
        assert!(socket.read(&mut data).await.unwrap() > 0);
        let bytes = serde_json::to_vec(&response).unwrap();
        socket.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",bytes.len()).as_bytes()).await.unwrap();
        socket.write_all(&bytes).await.unwrap();
    });
    let params = serde_json::json!({"origin":origin,"uiOrigin":origin,"requestedScopes":["shika.read"],"operationKey":Uuid::new_v4()});
    let config = TrustedOrigins::from_config(&origin, &origin, true).unwrap();
    assert!(
        super::service::pairing_start_with(&context, config, &params, "installation")
            .await
            .is_err()
    );
    server.await.unwrap();
    assert_eq!(context.store.load().unwrap().unwrap(), before);
}

#[tokio::test]
async fn consumed_lookup_always_requires_original_current_credential_and_server_proof() {
    use super::journal::{Binding, CompletedExchange, Credential, Journal, Kind, Operation};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let context = FakeContext::default();
    *context.marker.lock().unwrap() = true;
    let device = Uuid::new_v4();
    let id = Uuid::new_v4();
    let actor = Uuid::new_v4();
    let workspace = Uuid::new_v4();
    let connection = Uuid::new_v4();
    let mut pairing = PendingPairing::generate(device, Uuid::new_v4());
    pairing.api_origin = origin.clone();
    pairing.ui_origin = origin.clone();
    pairing.pairing_id = Some(id);
    pairing.actor_id = Some(actor);
    pairing.workspace_id = Some(workspace);
    pairing.created_at = Some("2026-01-01T00:00:00Z".into());
    pairing.expires_at = Some("2026-01-01T00:10:00Z".into());
    let start = serde_json::json!({"requestedScopes":["shika.read"]});
    pairing
        .bind_request(serde_json::to_vec(&start).unwrap())
        .unwrap();
    let binding = Binding {
        api_origin: origin.clone(),
        ui_origin: origin.clone(),
        installation_id: "installation".into(),
        device_id: device,
        actor_id: Some(actor),
        workspace_id: Some(workspace),
        connection_id: Some(connection),
    };
    let thumb = hex::encode(Sha256::digest(pairing.public_key()));
    let metadata = wire::Connection {
        schema_version: "shika.connection/v1".into(),
        connection_id: connection.to_string(),
        revision: 1,
        origin: origin.clone(),
        actor_id: actor.to_string(),
        workspace_id: workspace.to_string(),
        device_id: device.to_string(),
        installation_id: "installation".into(),
        proof_key_thumbprint: thumb.clone(),
        credential_revision: 1,
        status: "active".into(),
        scopes: vec!["shika.read".into()],
    };
    let credential = Credential {
        binding: binding.clone(),
        private_key: pairing.private_key,
        revision: 1,
        scopes: vec!["shika.read".into()],
        metadata,
    };
    let operation = Operation {
        kind: Kind::Exchange,
        operation_key: Uuid::new_v4(),
        binding,
        method: "POST".into(),
        target: format!("/api/v2/pairings/{id}/exchange/"),
        body: b"{}".to_vec(),
        if_match: None,
        replacement_key: None,
    };
    let response = serde_json::json!({"pairing":{"schemaVersion":"shika.pairing/v1","pairingId":id,"operationKey":pairing.operation_key,"origin":origin,"deviceId":device,"installationId":"installation","proofKeyThumbprint":thumb,"codeChallenge":pairing.challenge(),"createdAt":"2026-01-01T00:00:00Z","expiresAt":"2026-01-01T00:10:00Z","status":"consumed","actorId":actor,"workspaceId":workspace,"exchangeOperationKey":operation.operation_key},"revision":3,"uiOrigin":origin,"requestedScopes":["shika.read"],"approvalRevision":2,"reapprovalRequired":false});
    let mut state = Journal {
        version: 1,
        installation_id: "installation".into(),
        device_id: device,
        selected: Some(credential),
        other_credentials: vec![],
        pending_pairing: None,
        completed_exchanges: vec![CompletedExchange { pairing, operation }],
        completed_cancels: vec![],
        rejected_exchanges: vec![],
        completed_refreshes: vec![],
        denied_operations: vec![],
        tombstones: vec![],
        known_connections: vec![],
        pending: None,
        disconnect_pending: false,
    };
    persist_new(&context.store, &state).unwrap();
    let server = tokio::spawn(async move {
        for attempt in 0..2 {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buffer = [0u8; 2048];
            let n = socket.read(&mut buffer).await.unwrap();
            assert!(n > 0);
            let status = if attempt == 0 { 200 } else { 401 };
            let bytes = if attempt == 0 {
                serde_json::to_vec(&response).unwrap()
            } else {
                b"{}".to_vec()
            };
            socket.write_all(format!("HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",bytes.len()).as_bytes()).await.unwrap();
            socket.write_all(&bytes).await.unwrap();
        }
    });
    let params = serde_json::json!({"pairingId":id});
    let config = || TrustedOrigins::from_config(&origin, &origin, true).unwrap();
    let result = super::service::pairing_get_with(&context, config(), &params, "installation")
        .await
        .unwrap();
    assert_eq!(result["pairing"]["status"], "consumed");
    assert!(
        super::service::pairing_get_with(&context, config(), &params, "installation")
            .await
            .is_err()
    );
    server.await.unwrap();
    state.selected.as_mut().unwrap().private_key = [9; 32];
    context
        .store
        .save(&serde_json::to_vec(&state).unwrap())
        .unwrap();
    assert!(
        super::service::pairing_get_with(&context, config(), &params, "installation")
            .await
            .is_err()
    );
}

#[test]
fn completed_history_compacts_without_capacity_blocking_revoke() {
    use super::journal::{Binding, Credential, Journal, Kind, Operation, TerminalDenial};
    let store = FakeStore::default();
    let device = Uuid::new_v4();
    let actor = Uuid::new_v4();
    let workspace = Uuid::new_v4();
    let connection = Uuid::new_v4();
    let binding = Binding {
        api_origin: "https://api.example.com".into(),
        ui_origin: "https://ui.example.com".into(),
        installation_id: "installation".into(),
        device_id: device,
        actor_id: Some(actor),
        workspace_id: Some(workspace),
        connection_id: Some(connection),
    };
    let metadata = wire::Connection {
        schema_version: "shika.connection/v1".into(),
        connection_id: connection.to_string(),
        revision: 1,
        origin: binding.api_origin.clone(),
        actor_id: actor.to_string(),
        workspace_id: workspace.to_string(),
        device_id: device.to_string(),
        installation_id: "installation".into(),
        proof_key_thumbprint: String::new(),
        credential_revision: 1,
        status: "active".into(),
        scopes: vec!["shika.read".into()],
    };
    let credential = Credential {
        binding: binding.clone(),
        private_key: [1; 32],
        revision: 1,
        scopes: vec!["shika.read".into()],
        metadata,
    };
    let mut state = Journal {
        version: 1,
        installation_id: "installation".into(),
        device_id: device,
        selected: Some(credential),
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
    let mut keys = Vec::new();
    for _ in 0..40 {
        let start = Uuid::new_v4();
        let cancel = Uuid::new_v4();
        let id = Uuid::new_v4();
        let mut p = PendingPairing::generate(device, start);
        p.pairing_id = Some(id);
        p.api_origin = binding.api_origin.clone();
        p.ui_origin = binding.ui_origin.clone();
        p.bind_request(serde_json::to_vec(&serde_json::json!({"operationKey":start})).unwrap())
            .unwrap();
        let mut pair_binding = binding.clone();
        pair_binding.connection_id = None;
        let op = Operation {
            kind: Kind::Cancel,
            operation_key: cancel,
            binding: pair_binding,
            method: "POST".into(),
            target: format!("/api/v2/pairings/{id}/cancel/"),
            body: serde_json::to_vec(
                &serde_json::json!({"operationKey":cancel,"expectedRevision":1}),
            )
            .unwrap(),
            if_match: Some(format!("\"pairing:{id}:1\"")),
            replacement_key: None,
        };
        state.pending_pairing = Some(p);
        state.pending = Some(op.clone());
        state.settle_cancel(&store, &op).unwrap();
        keys.push(start);
    }
    assert_eq!(state.tombstones.len(), 80);
    assert!(state.completed_cancels.is_empty());
    let restored = load_state(&store).unwrap().unwrap();
    assert!(keys.iter().all(|key| restored.used_key(*key)));
    for _ in 0..40 {
        let denied_key = Uuid::new_v4();
        let mut pair_binding = binding.clone();
        pair_binding.connection_id = None;
        let denied = Operation {
            kind: Kind::Start,
            operation_key: denied_key,
            binding: pair_binding,
            method: "POST".into(),
            target: "/api/v2/pairings/".into(),
            body: serde_json::to_vec(&serde_json::json!({"operationKey":denied_key})).unwrap(),
            if_match: None,
            replacement_key: None,
        };
        let hash = super::w3::operation_fingerprint(&denied).unwrap();
        state.denied_operations.push(TerminalDenial {
            operation: denied,
            error_code: "needs_attention".into(),
            request_hash: hash,
            pairing: None,
        });
    }
    let prior_start = Uuid::new_v4();
    let prior_exchange = Uuid::new_v4();
    let pairing_id = Uuid::new_v4();
    let mut prior = PendingPairing::generate(device, prior_start);
    prior.private_key = [1; 32];
    prior.pairing_id = Some(pairing_id);
    prior.api_origin = binding.api_origin.clone();
    prior.ui_origin = binding.ui_origin.clone();
    prior
        .bind_request(serde_json::to_vec(&serde_json::json!({"operationKey":prior_start})).unwrap())
        .unwrap();
    let prior_verifier = prior.verifier.clone();
    let mut pair_binding = binding.clone();
    pair_binding.connection_id = None;
    let prior_op=Operation{kind:Kind::Exchange,operation_key:prior_exchange,binding:pair_binding,method:"POST".into(),target:format!("/api/v2/pairings/{pairing_id}/exchange/"),body:serde_json::to_vec(&serde_json::json!({"operationKey":prior_exchange,"expectedRevision":1,"codeVerifier":prior_verifier})).unwrap(),if_match:Some(format!("\"pairing:{pairing_id}:1\"")),replacement_key:None};
    state
        .completed_exchanges
        .push(super::journal::CompletedExchange {
            pairing: prior,
            operation: prior_op,
        });
    let revoke_key = Uuid::new_v4();
    let revoke = Operation {
        kind: Kind::Revoke,
        operation_key: revoke_key,
        binding,
        method: "POST".into(),
        target: format!("/api/v2/connections/{connection}/revoke/"),
        body: serde_json::to_vec(
            &serde_json::json!({"operationKey":revoke_key,"expectedRevision":1}),
        )
        .unwrap(),
        if_match: Some(format!("\"connection:{connection}:1\"")),
        replacement_key: None,
    };
    state.begin(&store, revoke.clone()).unwrap();
    assert!(state.disconnect_pending);
    state.finish(&store, &revoke, None).unwrap();
    let restored = load_state(&store).unwrap().unwrap();
    assert_eq!(restored.denied_operations.len(), 40);
    assert!(restored.used_key(revoke_key));
    assert!(restored.used_key(prior_start));
    assert!(restored.used_key(prior_exchange));
    assert!(restored.completed_exchanges.is_empty());
    assert!(
        !String::from_utf8(store.load().unwrap().unwrap())
            .unwrap()
            .contains(&prior_verifier)
    );
    assert!(keys.iter().all(|key| restored.used_key(*key)));
}

#[test]
fn re_pair_keeps_connector_tuple_with_new_connection_uuid() {
    use super::journal::{Binding, Credential, Journal, Kind, Operation};
    let store = FakeStore::default();
    let device = Uuid::new_v4();
    let actor = Uuid::new_v4();
    let workspace = Uuid::new_v4();
    let mut pairing = PendingPairing::generate(device, Uuid::new_v4());
    pairing.bind_request(b"start".to_vec()).unwrap();
    let mut binding = Binding {
        api_origin: "https://api.example.com".into(),
        ui_origin: "https://ui.example.com".into(),
        installation_id: "installation".into(),
        device_id: device,
        actor_id: Some(actor),
        workspace_id: Some(workspace),
        connection_id: Some(Uuid::new_v4()),
    };
    let previous = binding.clone();
    binding.connection_id = Some(Uuid::new_v4());
    let mut request_binding = binding.clone();
    request_binding.connection_id = None;
    let op = Operation {
        kind: Kind::Exchange,
        operation_key: Uuid::new_v4(),
        binding: request_binding,
        method: "POST".into(),
        target: "/api/v2/pairings/test/exchange/".into(),
        body: b"{}".to_vec(),
        if_match: None,
        replacement_key: None,
    };
    let scopes = vec!["shika.read".to_string()];
    let metadata = wire::Connection {
        schema_version: "shika.connection/v1".into(),
        connection_id: binding.connection_id.unwrap().to_string(),
        revision: 1,
        origin: binding.api_origin.clone(),
        actor_id: actor.to_string(),
        workspace_id: workspace.to_string(),
        device_id: device.to_string(),
        installation_id: binding.installation_id.clone(),
        proof_key_thumbprint: hex::encode(Sha256::digest(pairing.public_key())),
        credential_revision: 1,
        status: "active".into(),
        scopes: scopes.clone(),
    };
    let credential = Credential {
        binding: binding.clone(),
        private_key: pairing.private_key,
        revision: 1,
        scopes,
        metadata,
    };
    let mut state = Journal {
        version: 1,
        installation_id: "installation".into(),
        device_id: device,
        selected: None,
        other_credentials: vec![],
        pending_pairing: Some(pairing),
        completed_exchanges: vec![],
        completed_cancels: vec![],
        rejected_exchanges: vec![],
        completed_refreshes: vec![],
        denied_operations: vec![],
        tombstones: vec![],
        known_connections: vec![previous],
        pending: Some(op.clone()),
        disconnect_pending: false,
    };
    state.finish(&store, &op, Some(credential)).unwrap();
    assert_eq!(state.known_connections.len(), 1);
    assert_eq!(
        state.known_connections[0].connection_id,
        binding.connection_id
    );
}
