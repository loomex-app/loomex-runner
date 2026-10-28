use super::Origin;
use anyhow::{Result, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer, SigningKey};
use rand::{RngCore, rngs::OsRng};
use sha2::{Digest, Sha256};

// Kept out of Debug and serialization: this is an authorization header.
pub(super) struct Proof {
    pub(super) key_id: String,
    pub(super) value: String,
}

pub(super) fn sign(
    key: &[u8; 32],
    key_id: &str,
    method: &str,
    origin: &Origin,
    target: &str,
    body: &[u8],
    timestamp: u64,
) -> Result<Proof> {
    ensure!(
        !method.is_empty() && method.bytes().all(|b| b.is_ascii_uppercase()),
        "INVALID_PROOF_INPUT"
    );
    ensure!(
        target.starts_with('/')
            && target.is_ascii()
            && !target.bytes().any(|b| b <= 0x20 || b == 0x7f || b == b'#'),
        "INVALID_PROOF_INPUT"
    );
    let valid_key_id = if let Some(hash) = key_id.strip_prefix("p:") {
        hash.len() == 64
            && hash
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    } else if let Some(value) = key_id.strip_prefix("c:") {
        value.split_once(':').is_some_and(|(id, revision)| {
            uuid::Uuid::parse_str(id).is_ok_and(|parsed| parsed.to_string() == id)
                && revision
                    .parse::<u64>()
                    .is_ok_and(|n| n > 0 && n.to_string() == revision)
        })
    } else {
        false
    };
    ensure!(valid_key_id, "INVALID_PROOF_INPUT");
    let mut nonce = [0u8; 16];
    OsRng.fill_bytes(&mut nonce);
    let nonce = URL_SAFE_NO_PAD.encode(nonce);
    let transcript = format!(
        "shika-pop/v1\n{method}\n{}\n{target}\n{}\n{timestamp}\n{nonce}\n{key_id}",
        origin.0,
        hex::encode(Sha256::digest(body))
    );
    let signature = SigningKey::from_bytes(key).sign(transcript.as_bytes());
    Ok(Proof {
        key_id: key_id.to_owned(),
        value: format!(
            "{timestamp}.{nonce}.{}",
            URL_SAFE_NO_PAD.encode(signature.to_bytes())
        ),
    })
}
