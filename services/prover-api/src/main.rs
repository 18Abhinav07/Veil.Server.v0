mod chain;
mod circuits;
mod config;
mod error;
mod proof;
mod routes;
mod state;
mod types;

use anyhow::Result;
use axum::{
    Router,
    routing::{get, post},
};
use tower_http::{
    cors::{Any, CorsLayer},
    trace::TraceLayer,
};
use tracing_subscriber::{EnvFilter, fmt};

use config::Config;
use state::AppState;

#[tokio::main]
async fn main() -> Result<()> {
    fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("prover_api=debug,info")),
        )
        .init();

    let config = Config::from_env()?;
    tracing::info!(addr = %config.listen_addr, "starting prover-api");

    let state = AppState::new(&config)?;

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let router = Router::new()
        .route("/health", get(routes::health::handler))
        .route(
            "/keys/derive-note-public",
            post(routes::keys::derive_note_public_key_handler),
        )
        .route(
            "/keys/decrypt-output-note",
            post(routes::keys::decrypt_output_note_handler),
        )
        .route("/prove/deposit", post(routes::prove::deposit_handler))
        .route("/prove/withdraw", post(routes::prove::withdraw_handler))
        .route("/prove/transfer", post(routes::prove::transfer_handler))
        .route("/prove/register", post(routes::prove::register_handler))
        .route(
            "/prove/register-asp-membership",
            post(routes::prove::register_asp_membership_handler),
        )
        .layer(TraceLayer::new_for_http())
        .layer(cors)
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(config.listen_addr).await?;
    tracing::info!(addr = %config.listen_addr, "listening");

    axum::serve(listener, router)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}

async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("failed to install CTRL+C handler");
    tracing::info!("shutting down prover-api");
}
