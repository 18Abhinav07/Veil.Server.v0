use std::sync::Arc;

use axum::{Json, extract::State};
use stellar::{Client, PoolTransactInput, submit_tx};
use tracing::info;

use crate::{
    error::RelayerError,
    state::AppState,
    types::{RelayRequest, RelayResponse},
};

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
    let proof_bytes = hex::decode(&req.proof_uncompressed_hex).map_err(|e| {
        RelayerError::Validation(format!("invalid proof hex: {e}"))
    })?;

    let input = PoolTransactInput {
        proof_uncompressed: proof_bytes,
        ext_data: req.ext_data,
        public: req.public,
    };

    let relayer_pubkey = state.signer.public_key().to_owned();

    // Hold sequence lock for the entire simulate → sign → submit flow to prevent
    // concurrent requests racing on the same account sequence number.
    let _lock = state.sequence_lock.lock().await;

    // Simulate (griefing guard: catches invalid proofs, stale roots, spent
    // nullifiers before spending real fees).
    let prepared = state
        .fetcher
        .prepare_pool_transact(&req.pool_id, &input, &relayer_pubkey)
        .await
        .map_err(|e| {
            let msg = e.to_string();
            if msg.contains("simulation") || msg.contains("contract") {
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

    let tx_hash = submit_tx(&signed, &rpc)
        .await
        .map_err(RelayerError::from)?;

    info!(pool_id = %req.pool_id, tx_hash = %tx_hash, "relay submitted");

    Ok(Json(RelayResponse {
        tx_hash,
        status: "submitted",
    }))
}
