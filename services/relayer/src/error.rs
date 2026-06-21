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

impl IntoResponse for RelayerError {
    fn into_response(self) -> Response {
        let (status, code, msg) = match &self {
            Self::Validation(_) => (StatusCode::BAD_REQUEST, "VALIDATION_ERROR", self.to_string()),
            Self::SimulationRejected(_) => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "SIMULATION_REJECTED",
                self.to_string(),
            ),
            Self::BadSequence => (
                StatusCode::SERVICE_UNAVAILABLE,
                "BAD_SEQUENCE",
                self.to_string(),
            ),
            Self::RelayerAccountNotFound => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "ACCOUNT_NOT_FOUND",
                self.to_string(),
            ),
            Self::Rpc(_) => (StatusCode::BAD_GATEWAY, "RPC_ERROR", self.to_string()),
            Self::Internal(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL",
                self.to_string(),
            ),
        };

        let body = json!({ "error": code, "message": msg });
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
