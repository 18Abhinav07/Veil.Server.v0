use anyhow::Result;
use std::sync::Arc;
use stellar::StateFetcher;
use types::ContractConfig;

use crate::{circuits::CircomProver, config::Config};

#[derive(Clone)]
pub struct AppState(pub Arc<Inner>);

pub struct Inner {
    pub fetcher: StateFetcher,
    pub prover: CircomProver,
    /// Ledger from which pool contracts were first deployed (for event scanning).
    pub min_deployment_ledger: u32,
    /// Ledger from which ASP membership events should be scanned.
    pub asp_membership_scan_start_ledger: u32,
}

impl AppState {
    pub fn new(config: &Config) -> Result<Self> {
        let cfg_bytes = std::fs::read(&config.deployments_path)?;
        let contract_config: &'static ContractConfig =
            Box::leak(Box::new(serde_json::from_slice(&cfg_bytes)?));

        let fetcher = StateFetcher::new(&config.stellar_rpc_url, contract_config)?;

        let min_deployment_ledger = contract_config.min_deployment_ledger().unwrap_or(0);
        let asp_membership_scan_start_ledger = contract_config
            .asp_membership_scan_start_ledger()
            .unwrap_or(min_deployment_ledger);

        let prover = CircomProver::load(
            config.wasm_path.clone(),
            config.r1cs_path.clone(),
            config.proving_key_path.clone(),
        )?;

        Ok(Self(Arc::new(Inner {
            fetcher,
            prover,
            min_deployment_ledger,
            asp_membership_scan_start_ledger,
        })))
    }

    pub fn fetcher(&self) -> &StateFetcher {
        &self.0.fetcher
    }

    #[allow(dead_code)]
    pub fn prover(&self) -> &CircomProver {
        &self.0.prover
    }

    #[allow(dead_code)]
    pub fn min_deployment_ledger(&self) -> u32 {
        self.0.min_deployment_ledger
    }

    #[allow(dead_code)]
    pub fn asp_membership_scan_start_ledger(&self) -> u32 {
        self.0.asp_membership_scan_start_ledger
    }
}
