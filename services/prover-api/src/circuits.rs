//! Groth16 proof generation via ark-circom (native, wasmer-backed).

use anyhow::{Result, anyhow};
use ark_bn254::{Bn254, Fr};
use ark_circom::{CircomBuilder, CircomConfig, CircomReduction};
use ark_groth16::{Groth16, ProvingKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK as _;
use ark_std::rand::rngs::OsRng;
use num_bigint::{BigInt, Sign};
use prover::prover::convert_proof_to_soroban;
use prover::types::{CircuitInputs, InputValue};
use std::{io::BufReader, path::PathBuf};

/// Wrapper around Groth16 proving key + circuit files.
pub struct CircomProver {
    pub wasm_path: PathBuf,
    pub r1cs_path: PathBuf,
    pub pk: ProvingKey<Bn254>,
}

impl CircomProver {
    pub fn load(wasm_path: PathBuf, r1cs_path: PathBuf, pk_path: PathBuf) -> Result<Self> {
        tracing::info!(
            wasm = %wasm_path.display(),
            r1cs = %r1cs_path.display(),
            pk   = %pk_path.display(),
            "loading circuit artifacts"
        );
        let file = std::fs::File::open(&pk_path)
            .map_err(|e| anyhow!("open pk {}: {e}", pk_path.display()))?;
        let mut reader = BufReader::new(file);
        let pk = ProvingKey::<Bn254>::deserialize_compressed(&mut reader)
            .map_err(|e| anyhow!("deserialize proving key: {e}"))?;
        tracing::info!("proving key loaded");
        Ok(Self {
            wasm_path,
            r1cs_path,
            pk,
        })
    }

    /// Generate an uncompressed 256-byte Soroban-compatible Groth16 proof
    /// from `CircuitInputs` (hex-string signals from `prover::flows`).
    pub fn prove(&self, inputs: &CircuitInputs) -> Result<Vec<u8>> {
        let cfg = CircomConfig::<Fr>::new(&self.wasm_path, &self.r1cs_path)
            .map_err(|e| anyhow!("CircomConfig: {e}"))?;
        let mut builder = CircomBuilder::new(cfg);

        for (name, val) in &inputs.signals {
            match val {
                InputValue::Single(s) => {
                    builder.push_input(name, hex_to_bigint(s)?);
                }
                InputValue::Array(arr) => {
                    for s in arr {
                        builder.push_input(name, hex_to_bigint(s)?);
                    }
                }
            }
        }

        let circuit = builder.build().map_err(|e| anyhow!("circuit build: {e}"))?;
        let mut rng = OsRng;
        let proof = Groth16::<Bn254, CircomReduction>::prove(&self.pk, circuit, &mut rng)
            .map_err(|e| anyhow!("Groth16::prove: {e}"))?;

        // Serialize to compressed then convert to Soroban uncompressed format.
        let mut compressed = Vec::new();
        proof
            .serialize_compressed(&mut compressed)
            .map_err(|e| anyhow!("serialize proof: {e}"))?;

        convert_proof_to_soroban(&compressed)
    }
}

/// Parse a `0x`-prefixed big-endian hex string to a `BigInt`.
fn hex_to_bigint(s: &str) -> Result<BigInt> {
    let hex = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(hex).map_err(|e| anyhow!("hex decode '{s}': {e}"))?;
    Ok(BigInt::from_bytes_be(Sign::Plus, &bytes))
}
