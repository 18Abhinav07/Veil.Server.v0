use std::sync::Arc;

use anyhow::Result;
use axum::{Router, routing::{get, post}};
use tower_http::{
    cors::{Any, CorsLayer},
    trace::TraceLayer,
};
use tracing::info;
use tracing_subscriber::EnvFilter;

mod config;
mod error;
mod routes;
mod state;
mod types;

use config::Config;
use state::AppState;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("relayer=info".parse()?))
        .init();

    let config = Config::from_env()?;
    let listen_addr = config.listen_addr;

    let app_state = Arc::new(AppState::new(&config)?);

    // Browser clients (the Next.js UI) call /relay cross-origin, so allow CORS.
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let router = Router::new()
        .route("/health", get(routes::health::handler))
        .route("/relay", post(routes::relay::handler))
        .layer(TraceLayer::new_for_http())
        .layer(cors)
        .with_state(app_state);

    info!("relayer listening on {listen_addr}");
    let listener = tokio::net::TcpListener::bind(listen_addr).await?;
    axum::serve(listener, router)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}
