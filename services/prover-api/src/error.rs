use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde_json::json;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProverError {
    #[error("bad request: {0}")]
    BadRequest(String),
    #[error("proof generation failed: {0}")]
    ProofFailed(String),
    #[error("chain error: {0}")]
    ChainError(String),
    #[error("internal error: {0}")]
    Internal(String),
}

fn normalized_message(message: &str) -> String {
    message.chars().filter(|c| !c.is_whitespace()).collect()
}

pub fn classify_prover_error_message(message: &str) -> &'static str {
    let normalized = normalized_message(message);
    if normalized.contains("Error(Contract,#9)") || message.contains("AlreadySpentNullifier") {
        return "already_spent_nullifier";
    }
    if normalized.contains("Error(Contract,#8)") || message.contains("UnknownRoot") {
        return "unknown_root";
    }
    if normalized.contains("Error(Contract,#0)")
        || normalized.contains("Error(Contract,#7)")
        || message.contains("Groth16Error::InvalidProof")
        || message.contains("InvalidProof")
    {
        return "invalid_proof";
    }
    if message.contains("contracts_data_for_pool")
        || message.contains("asp_state")
        || message.contains("out of range")
        || message.contains("not been indexed")
        || message.contains("only has")
        || message.contains("indexed yet")
        || message.contains("RPC sync gap")
        || message.contains("local sync is ahead")
    {
        return "pool_state_lag";
    }
    if message.contains("network")
        || message.contains("RPC")
        || message.contains("timeout")
        || message.contains("fetch")
    {
        return "network";
    }
    "unknown"
}

pub fn format_error_chain(error: &anyhow::Error) -> String {
    format!("{error:#}")
}

impl From<anyhow::Error> for ProverError {
    fn from(e: anyhow::Error) -> Self {
        Self::Internal(e.to_string())
    }
}

impl IntoResponse for ProverError {
    fn into_response(self) -> Response {
        let (status, msg) = match &self {
            Self::BadRequest(m) => (StatusCode::BAD_REQUEST, m.clone()),
            Self::ProofFailed(m) => (StatusCode::UNPROCESSABLE_ENTITY, m.clone()),
            Self::ChainError(m) => (StatusCode::BAD_GATEWAY, m.clone()),
            Self::Internal(m) => (StatusCode::INTERNAL_SERVER_ERROR, m.clone()),
        };
        let body = json!({
            "error": msg,
            "class": classify_prover_error_message(&msg),
        });
        (status, Json(body)).into_response()
    }
}

pub type ProverResult<T> = Result<T, ProverError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_prepare_pool_transact_invalid_proof_chain() {
        let message =
            "prepare_pool_transact: transaction simulation failed: HostError: Error(Contract, #0)";

        assert_eq!(classify_prover_error_message(message), "invalid_proof");
    }

    #[test]
    fn classifies_indexing_lag_as_pool_state_lag() {
        let message = "pool Merkle proof for leaf 8: note leaf index out of range: requested leaf=8 but pool only has 4 commitments";

        assert_eq!(classify_prover_error_message(message), "pool_state_lag");
    }
}
