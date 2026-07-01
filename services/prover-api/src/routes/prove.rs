use axum::{Json, extract::State};

use crate::{
    error::{ProverResult, format_error_chain},
    proof::{
        prove_deposit, prove_register, prove_register_asp_membership, prove_transfer,
        prove_withdraw,
    },
    state::AppState,
    types::{
        DepositRequest, DepositResponse, RegisterAspMembershipRequest,
        RegisterAspMembershipResponse, RegisterRequest, RegisterResponse, TransferRequest,
        TransferResponse, WithdrawRequest, WithdrawResponse,
    },
};

pub async fn deposit_handler(
    State(state): State<AppState>,
    Json(req): Json<DepositRequest>,
) -> ProverResult<Json<DepositResponse>> {
    prove_deposit(&state, req).await.map(Json).map_err(|e| {
        tracing::error!("deposit proof failed: {e:#}");
        crate::error::ProverError::ProofFailed(format_error_chain(&e))
    })
}

pub async fn withdraw_handler(
    State(state): State<AppState>,
    Json(req): Json<WithdrawRequest>,
) -> ProverResult<Json<WithdrawResponse>> {
    prove_withdraw(&state, req).await.map(Json).map_err(|e| {
        tracing::error!("withdraw proof failed: {e:#}");
        crate::error::ProverError::ProofFailed(format_error_chain(&e))
    })
}

pub async fn transfer_handler(
    State(state): State<AppState>,
    Json(req): Json<TransferRequest>,
) -> ProverResult<Json<TransferResponse>> {
    prove_transfer(&state, req).await.map(Json).map_err(|e| {
        tracing::error!("transfer proof failed: {e:#}");
        crate::error::ProverError::ProofFailed(format_error_chain(&e))
    })
}

pub async fn register_handler(
    State(state): State<AppState>,
    Json(req): Json<RegisterRequest>,
) -> ProverResult<Json<RegisterResponse>> {
    prove_register(&state, req).await.map(Json).map_err(|e| {
        tracing::error!("register failed: {e:#}");
        crate::error::ProverError::ChainError(format_error_chain(&e))
    })
}

pub async fn register_asp_membership_handler(
    State(state): State<AppState>,
    Json(req): Json<RegisterAspMembershipRequest>,
) -> ProverResult<Json<RegisterAspMembershipResponse>> {
    prove_register_asp_membership(&state, req)
        .await
        .map(Json)
        .map_err(|e| {
            tracing::error!("asp membership registration failed: {e:#}");
            crate::error::ProverError::ChainError(format_error_chain(&e))
        })
}
