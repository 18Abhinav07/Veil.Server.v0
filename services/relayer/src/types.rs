use serde::{Deserialize, Serialize};
use stellar::OnchainProofPublicInputs;
use types::ExtData;

/// POST /relay request body.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayRequest {
    /// Pool contract ID (C... strkey).
    pub pool_id: String,
    /// Uncompressed Groth16 proof — 256 bytes as a lowercase hex string (512 chars).
    pub proof_uncompressed_hex: String,
    /// External data (recipient, amount, encrypted outputs).
    pub ext_data: ExtData,
    /// On-chain public inputs (roots, nullifiers, commitments).
    pub public: OnchainProofPublicInputs,
}

/// POST /relay response body.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayResponse {
    pub tx_hash: String,
    pub status: &'static str,
}
