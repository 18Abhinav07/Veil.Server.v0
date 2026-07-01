use crate::config::Config;
use anyhow::{Context, Result};
use stellar::{LocalSigner, StateFetcher};
use std::collections::HashMap;
use tokio::sync::Mutex;
use types::ContractConfig;

/// Shared application state (wrapped in Arc by Axum).
pub struct AppState {
    pub fetcher: StateFetcher,
    pub signer: LocalSigner,
    pub network_passphrase: String,
    pub rpc_url: String,
    /// Prevents concurrent relay requests from racing on account sequence numbers.
    pub sequence_lock: Mutex<()>,
    /// Returns the original tx hash when clients retry the exact same relay
    /// body after a lost HTTP response.
    pub relay_cache: Mutex<HashMap<String, crate::types::RelayResponse>>,
}

impl AppState {
    pub fn new(config: &Config) -> Result<Self> {
        // Load and leak the ContractConfig so StateFetcher can hold a &'static ref.
        let cfg_bytes = std::fs::read(&config.contract_config_path)
            .with_context(|| format!("read {}", config.contract_config_path.display()))?;
        let contract_config: ContractConfig =
            serde_json::from_slice(&cfg_bytes).context("parse deployments.json")?;
        let contract_config: &'static ContractConfig = Box::leak(Box::new(contract_config));

        let fetcher =
            StateFetcher::new(&config.stellar_rpc_url, contract_config).context("StateFetcher")?;
        let signer =
            LocalSigner::from_secret(&config.relayer_secret).context("LocalSigner")?;

        Ok(Self {
            fetcher,
            signer,
            network_passphrase: config.network_passphrase.clone(),
            rpc_url: config.stellar_rpc_url.clone(),
            sequence_lock: Mutex::new(()),
            relay_cache: Mutex::new(HashMap::new()),
        })
    }
}
