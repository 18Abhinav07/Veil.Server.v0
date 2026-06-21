use anyhow::{Context, Result};
use std::{env, net::SocketAddr, path::PathBuf};

#[derive(Debug, Clone)]
pub struct Config {
    /// S... Stellar secret key for the relayer account (never logged).
    pub relayer_secret: String,
    /// Soroban RPC URL (e.g. https://soroban-testnet.stellar.org).
    pub stellar_rpc_url: String,
    /// Network passphrase (e.g. "Test SDF Network ; September 2015").
    pub network_passphrase: String,
    /// Path to deployments.json.
    pub contract_config_path: PathBuf,
    /// Bind address for the HTTP server.
    pub listen_addr: SocketAddr,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        Ok(Self {
            relayer_secret: env_var("RELAYER_SECRET")?,
            stellar_rpc_url: env_var("RELAYER_STELLAR_RPC_URL")?,
            network_passphrase: env_var("RELAYER_NETWORK_PASSPHRASE")?,
            contract_config_path: env_var("RELAYER_CONTRACT_CONFIG_PATH")?.into(),
            listen_addr: env::var("RELAYER_LISTEN_ADDR")
                .unwrap_or_else(|_| "0.0.0.0:3000".to_string())
                .parse()
                .context("RELAYER_LISTEN_ADDR is not a valid socket address")?,
        })
    }
}

fn env_var(key: &str) -> Result<String> {
    env::var(key).with_context(|| format!("missing required env var: {key}"))
}
