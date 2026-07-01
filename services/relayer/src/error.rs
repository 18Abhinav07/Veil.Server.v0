use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde_json::json;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum RelayerError {
    #[error("validation: {0}")]
    Validation(String),

    /// Proof simulation failed (invalid proof, stale root, spent nullifier, etc.)
    #[error("simulation rejected: {0}")]
    SimulationRejected(String),

    /// RPC returned txBAD_SEQ — client should retry once after a ledger.
    #[error("sequence conflict, retry after 1 ledger")]
    BadSequence,

    #[error("relayer account not found on network")]
    RelayerAccountNotFound,

    #[error("rpc error: {0}")]
    #[allow(dead_code)]
    Rpc(String),

    #[error("internal: {0}")]
    Internal(String),
}

fn normalized_message(message: &str) -> String {
    message.chars().filter(|c| !c.is_whitespace()).collect()
}

pub fn classify_simulation_failure(message: &str) -> &'static str {
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
    if normalized.contains("Error(Contract,#10)") || message.contains("WrongExtHash") {
        return "wrong_ext_hash";
    }
    if normalized.contains("Error(Contract,#6)") || message.contains("WrongExtAmount") {
        return "wrong_ext_amount";
    }
    "unknown"
}

impl IntoResponse for RelayerError {
    fn into_response(self) -> Response {
        let (status, code, msg, class) = match &self {
            Self::Validation(_) => (
                StatusCode::BAD_REQUEST,
                "VALIDATION_ERROR",
                self.to_string(),
                None,
            ),
            Self::SimulationRejected(message) => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "SIMULATION_REJECTED",
                self.to_string(),
                Some(classify_simulation_failure(message)),
            ),
            Self::BadSequence => (
                StatusCode::SERVICE_UNAVAILABLE,
                "BAD_SEQUENCE",
                self.to_string(),
                None,
            ),
            Self::RelayerAccountNotFound => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "ACCOUNT_NOT_FOUND",
                self.to_string(),
                None,
            ),
            Self::Rpc(_) => (StatusCode::BAD_GATEWAY, "RPC_ERROR", self.to_string(), None),
            Self::Internal(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL",
                self.to_string(),
                None,
            ),
        };

        let body = if let Some(class) = class {
            json!({ "error": code, "message": msg, "class": class })
        } else {
            json!({ "error": code, "message": msg })
        };
        let mut resp = axum::Json(body).into_response();
        *resp.status_mut() = status;
        resp
    }
}

impl From<anyhow::Error> for RelayerError {
    fn from(e: anyhow::Error) -> Self {
        let msg = e.to_string();
        if msg.contains("txBAD_SEQ") || msg.contains("TxBadSeq") {
            Self::BadSequence
        } else if msg.contains("account not found") || msg.contains("AccountNotFound") {
            Self::RelayerAccountNotFound
        } else {
            Self::Internal(msg)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_verifier_invalid_proof_as_non_retryable() {
        let message =
            r#"simulation rejected: transaction simulation failed: HostError: Error(Contract, #0)"#;

        assert_eq!(classify_simulation_failure(message), "invalid_proof");
    }

    #[test]
    fn classifies_pool_root_lag_as_unknown_root() {
        let message =
            r#"simulation rejected: transaction simulation failed: HostError: Error(Contract, #8)"#;

        assert_eq!(classify_simulation_failure(message), "unknown_root");
    }
}
