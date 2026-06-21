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
        (status, Json(json!({ "error": msg }))).into_response()
    }
}

pub type ProverResult<T> = Result<T, ProverError>;
