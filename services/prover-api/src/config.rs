use anyhow::{Context, Result, bail};
use std::{net::SocketAddr, path::PathBuf};

fn default_proving_key_path() -> PathBuf {
    PathBuf::from("deployments/testnet/circuit_keys/policy_tx_2_2_proving_key.bin")
}

fn is_deployed_runtime() -> bool {
    std::env::var_os("RAILWAY_ENVIRONMENT").is_some()
        || std::env::var_os("RAILWAY_SERVICE_ID").is_some()
        || std::env::var_os("RAILWAY_PROJECT_ID").is_some()
}

fn validate_proving_key_path_for_environment(path: &std::path::Path, deployed: bool) -> Result<()> {
    if deployed && path.to_string_lossy().contains("testdata") {
        bail!(
            "testdata proving key path is not allowed in deployed runtime: {}. Use deployments/testnet/circuit_keys/policy_tx_2_2_proving_key.bin",
            path.display()
        );
    }
    Ok(())
}

pub struct Config {
    /// Path to deployments.json (ContractConfig)
    pub deployments_path: PathBuf,
    /// Stellar RPC URL
    pub stellar_rpc_url: String,
    /// Path to the Circom WASM witness calculator
    pub wasm_path: PathBuf,
    /// Path to the Circom R1CS file
    pub r1cs_path: PathBuf,
    /// Path to the Groth16 proving key binary
    pub proving_key_path: PathBuf,
    /// Listen address for the HTTP server
    pub listen_addr: SocketAddr,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        let deployments_path = PathBuf::from(
            std::env::var("PROVER_API_DEPLOYMENTS_PATH")
                .unwrap_or_else(|_| "deployments/testnet/deployments.json".into()),
        );
        if !deployments_path.exists() {
            bail!("deployments file not found: {}", deployments_path.display());
        }

        let stellar_rpc_url = std::env::var("PROVER_API_STELLAR_RPC_URL")
            .unwrap_or_else(|_| "https://soroban-testnet.stellar.org".into());

        let wasm_path = PathBuf::from(
            std::env::var("PROVER_API_WASM_PATH")
                .unwrap_or_else(|_| "target/circuits-artifacts/debug/policy_tx_2_2.wasm".into()),
        );

        let r1cs_path = PathBuf::from(
            std::env::var("PROVER_API_R1CS_PATH")
                .unwrap_or_else(|_| "target/circuits-artifacts/debug/policy_tx_2_2.r1cs".into()),
        );

        let proving_key_path = PathBuf::from(
            std::env::var("PROVER_API_PK_PATH")
                .unwrap_or_else(|_| default_proving_key_path().to_string_lossy().into_owned()),
        );
        validate_proving_key_path_for_environment(&proving_key_path, is_deployed_runtime())?;

        for (label, path) in [
            ("WASM", &wasm_path),
            ("R1CS", &r1cs_path),
            ("proving key", &proving_key_path),
        ] {
            if !path.exists() {
                bail!("{label} file not found: {}", path.display());
            }
        }

        let listen_addr: SocketAddr = std::env::var("PROVER_API_LISTEN_ADDR")
            .unwrap_or_else(|_| "0.0.0.0:3001".into())
            .parse()
            .context("PROVER_API_LISTEN_ADDR must be a valid socket address")?;

        Ok(Self {
            deployments_path,
            stellar_rpc_url,
            wasm_path,
            r1cs_path,
            proving_key_path,
            listen_addr,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn default_proving_key_path_uses_canonical_deployment_key() {
        let default = default_proving_key_path();

        assert_eq!(
            default,
            Path::new("deployments/testnet/circuit_keys/policy_tx_2_2_proving_key.bin")
        );
        assert!(
            !default.to_string_lossy().contains("testdata"),
            "deployed prover defaults must not use local testdata keys"
        );
    }

    #[test]
    fn deployed_runtime_rejects_testdata_proving_key_path() {
        let err = validate_proving_key_path_for_environment(
            Path::new("testdata/policy_tx_2_2_proving_key.bin"),
            true,
        )
        .expect_err("testdata proving keys must be rejected in deployed runtime");

        assert!(
            err.to_string().contains("testdata proving key"),
            "unexpected error: {err}"
        );
    }
}
