use std::sync::Arc;

use axum::{Json, extract::State};
use sha2::{Digest, Sha256};
use stellar::{Client, PoolTransactInput, submit_tx};
use tracing::info;

use crate::{
    error::RelayerError,
    state::AppState,
    types::{RelayRequest, RelayResponse},
};

fn relay_request_fingerprint(req: &RelayRequest) -> Result<String, RelayerError> {
    let bytes = serde_json::to_vec(req)
        .map_err(|e| RelayerError::Internal(format!("relay fingerprint serialization: {e}")))?;
    let digest = Sha256::digest(bytes);
    Ok(hex::encode(digest))
}

pub async fn handler(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RelayRequest>,
) -> Result<Json<RelayResponse>, RelayerError> {
    // --- Validate proof bytes ---
    if req.proof_uncompressed_hex.len() != 512 {
        return Err(RelayerError::Validation(format!(
            "proof_uncompressed_hex must be 512 hex chars (256 bytes), got {}",
            req.proof_uncompressed_hex.len()
        )));
    }
    let proof_bytes = hex::decode(&req.proof_uncompressed_hex)
        .map_err(|e| RelayerError::Validation(format!("invalid proof hex: {e}")))?;

    let request_fingerprint = relay_request_fingerprint(&req)?;

    let input = PoolTransactInput {
        proof_uncompressed: proof_bytes,
        ext_data: req.ext_data,
        public: req.public,
    };

    let relayer_pubkey = state.signer.public_key().to_owned();

    // Hold sequence lock for the entire simulate → sign → submit flow to prevent
    // concurrent requests racing on the same account sequence number.
    let _lock = state.sequence_lock.lock().await;

    if let Some(cached) = state
        .relay_cache
        .lock()
        .await
        .get(&request_fingerprint)
        .cloned()
    {
        info!(
            pool_id = %req.pool_id,
            tx_hash = %cached.tx_hash,
            "relay idempotency cache hit"
        );
        return Ok(Json(cached));
    }

    // Simulate (griefing guard: catches invalid proofs, stale roots, spent
    // nullifiers before spending real fees).
    let prepared = state
        .fetcher
        .prepare_pool_transact(&req.pool_id, &input, &relayer_pubkey)
        .await
        .map_err(|e| {
            let msg = format!("{e:#}");
            if msg.contains("simulation") || msg.contains("contract") || msg.contains("HostError") {
                RelayerError::SimulationRejected(msg)
            } else {
                RelayerError::from(e)
            }
        })?;

    // Sign with relayer keypair.
    let signed = state
        .signer
        .sign_prepared_transaction(&prepared, &state.network_passphrase, &relayer_pubkey)
        .map_err(|e| RelayerError::Internal(e.to_string()))?;

    // Submit. Build a fresh RPC client using the same URL as the StateFetcher's
    // underlying client (passed in via state at construction time).
    let rpc = Client::new(&state.rpc_url)
        .map_err(|e| RelayerError::Internal(format!("rpc client: {e}")))?;

    let tx_hash = submit_tx(&signed, &rpc).await.map_err(RelayerError::from)?;

    info!(pool_id = %req.pool_id, tx_hash = %tx_hash, "relay submitted");

    let response = RelayResponse {
        tx_hash,
        status: "submitted",
    };
    state
        .relay_cache
        .lock()
        .await
        .insert(request_fingerprint, response.clone());

    Ok(Json(response))
}

#[cfg(test)]
mod tests {
    use super::*;
    use types::{ExtAmount, Field, U256};

    fn sample_request() -> RelayRequest {
        RelayRequest {
            pool_id: "CCB5JF3L7K3Y5X5HYY57LJCDGN4FKIE2MBYQOTZWDIXNX6STFFXOU4II".to_owned(),
            proof_uncompressed_hex: "00".repeat(256),
            ext_data: types::ExtData {
                recipient: "GACNTLJEYVHVQOHFJC7T7VTGJIZZHYN52MH6FHYGRGK2RFSY33GL2GXG".to_owned(),
                ext_amount: ExtAmount::from(0),
                encrypted_output0: vec![1, 2, 3],
                encrypted_output1: vec![4, 5, 6],
            },
            public: stellar::OnchainProofPublicInputs {
                root: Field(U256::from(1)),
                input_nullifiers: [Field(U256::from(2)), Field(U256::from(3))],
                output_commitment0: Field(U256::from(4)),
                output_commitment1: Field(U256::from(5)),
                public_amount: Field(U256::from(6)),
                ext_data_hash_be: [7u8; 32],
                asp_membership_root: Field(U256::from(8)),
                asp_non_membership_root: Field(U256::from(9)),
            },
        }
    }

    #[test]
    fn relay_request_fingerprint_is_stable_and_sensitive() {
        let first = sample_request();
        let mut second = sample_request();

        let first_hash = relay_request_fingerprint(&first).expect("first hash");
        let repeat_hash = relay_request_fingerprint(&first).expect("repeat hash");
        assert_eq!(first_hash, repeat_hash);
        assert_eq!(first_hash.len(), 64);

        second.public.input_nullifiers[0] = Field(U256::from(10));
        let changed_hash = relay_request_fingerprint(&second).expect("changed hash");
        assert_ne!(first_hash, changed_hash);
    }
}
