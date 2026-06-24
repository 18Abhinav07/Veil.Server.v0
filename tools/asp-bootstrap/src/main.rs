//! ASP Bootstrap — one-shot tool to populate ASP membership and non-membership
//! contracts with test-user keys for a permissive hackathon testnet setup.
//!
//! Run once after fresh contract deployment. Writes `asp-state.json` with
//! final Merkle roots and per-user blindings so the prover can reconstruct
//! membership proofs offline.
//!
//! Usage:
//!   asp-bootstrap --config deployments/testnet/deployments.json \
//!                 --admin <IDENTITY_OR_SECRET> \
//!                 --network testnet \
//!                 [--output testnet-asp-state.json]
//!
//! Seeds 1001..=1011 are the 11 deterministic test-user BN254 private keys.
//! Blindings are derived as seed * 7919 (prime) for reproducibility without
//! requiring a randomness source.

use anyhow::{Context, Result, bail};
use circuits::test::utils::{general::poseidon2_hash2, keypair::derive_public_key};
use clap::Parser;
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};
use std::{
    path::PathBuf,
    process::{Command, Output},
    thread::sleep,
    time::Duration,
};
use zkhash::{
    ark_ff::{BigInteger, PrimeField},
    fields::bn256::FpBN256 as Scalar,
};

// ---------------------------------------------------------------------------
// CLI args
// ---------------------------------------------------------------------------

#[derive(Debug, Parser)]
#[command(name = "asp-bootstrap", about = "Populate ASP contracts for testnet")]
struct Cli {
    /// Path to deployments.json produced by deploy.sh
    #[arg(long, default_value = "deployments/testnet/deployments.json")]
    config: PathBuf,

    /// Stellar identity alias or S... secret key for the admin account
    #[arg(long, env = "ASP_BOOTSTRAP_ADMIN")]
    admin: String,

    /// Stellar network name (e.g. testnet)
    #[arg(long, default_value = "testnet")]
    network: String,

    /// Path to write the resulting asp-state.json
    #[arg(long, default_value = "testnet-asp-state.json")]
    output: PathBuf,

    /// Seconds to sleep between contract invocations (for ledger settlement)
    #[arg(long, default_value_t = 9)]
    sleep_secs: u64,

    /// Max retries per invocation on TxBadSeq / timeout
    #[arg(long, default_value_t = 5)]
    max_retries: u32,
}

// ---------------------------------------------------------------------------
// Deployments.json schema (minimal)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct Deployments {
    asp_membership: String,
    asp_non_membership: String,
}

// ---------------------------------------------------------------------------
// State output
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
struct UserEntry {
    seed: u64,
    pub_key_hex: String,
    blinding_hex: String,
    membership_leaf_hex: String,
}

#[derive(Debug, Serialize)]
struct AspState {
    network: String,
    asp_membership_id: String,
    asp_non_membership_id: String,
    asp_membership_root: String,
    asp_non_membership_root: String,
    users: Vec<UserEntry>,
}

// ---------------------------------------------------------------------------
// Scalar → Stellar CLI U256 conversion
// ---------------------------------------------------------------------------

/// Convert a `Scalar` (BN254 field element) to 32 big-endian bytes.
fn scalar_to_be_bytes(s: Scalar) -> [u8; 32] {
    let le = s.into_bigint().to_bytes_le();
    let mut be = [0u8; 32];
    for (i, b) in le.iter().enumerate() {
        be[31 - i] = *b;
    }
    be
}

/// Format a Scalar as a decimal integer string for the Stellar CLI `u256` arg.
/// The CLI accepts: `--leaf 12345678...` (plain decimal, no JSON object).
fn scalar_to_u256_decimal(s: Scalar) -> String {
    BigUint::from_bytes_be(&scalar_to_be_bytes(s)).to_string()
}


// ---------------------------------------------------------------------------
// stellar CLI wrapper
// ---------------------------------------------------------------------------

/// Invoke `stellar contract invoke` with retry on TxBadSeq / timeout.
/// `fn_args` is a list of `(flag_name, value)` pairs appended after `--`.
fn stellar_invoke(
    contract_id: &str,
    admin: &str,
    network: &str,
    fn_name: &str,
    fn_args: &[(&str, &str)],
    sleep_secs: u64,
    max_retries: u32,
) -> Result<String> {
    let mut attempts = 0u32;
    loop {
        let mut cmd = Command::new("stellar");
        cmd.args(["contract", "invoke"])
            .args(["--id", contract_id])
            .args(["--source-account", admin])
            .args(["--network", network])
            .arg("--")
            .arg(fn_name);
        for (flag, value) in fn_args {
            cmd.arg(format!("--{flag}")).arg(value);
        }

        let out: Output = cmd.output().context("failed to run stellar CLI")?;
        let stdout = String::from_utf8_lossy(&out.stdout).to_string();
        let stderr = String::from_utf8_lossy(&out.stderr).to_string();
        let combined = format!("{stdout}{stderr}");

        if combined.contains("TxBadSeq")
            || combined.contains("timeout")
            || combined.contains("timed out")
        {
            attempts = attempts.saturating_add(1);
            if attempts >= max_retries {
                bail!(
                    "stellar invoke {fn_name} failed after {attempts} attempts:\n{combined}"
                );
            }
            eprintln!(
                "  [retry {attempts}/{max_retries}] transient error, waiting {sleep_secs}s…"
            );
            sleep(Duration::from_secs(sleep_secs));
            continue;
        }

        if !out.status.success() {
            // Idempotent for insert_leaf: the Stellar CLI reports any contract
            // error (including KeyAlreadyExists) as "Trapped". Treat all
            // Trapped failures on insert_leaf as duplicate-key skips since the
            // leaf arguments are deterministic and only re-run on re-bootstrap.
            if fn_name == "insert_leaf" && combined.contains("Trapped") {
                eprintln!("  [skip] {fn_name}: already inserted (Trapped = duplicate), continuing");
                sleep(Duration::from_secs(sleep_secs));
                return Ok(String::new());
            }
            bail!("stellar invoke {fn_name} failed (exit {:?}):\n{combined}", out.status.code());
        }

        sleep(Duration::from_secs(sleep_secs));
        // Strip surrounding JSON quotes that stellar CLI adds to string return values.
        let trimmed = stdout.trim().trim_matches('"').to_owned();
        return Ok(trimmed);
    }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn main() -> Result<()> {
    let cli = Cli::parse();

    let cfg_bytes = std::fs::read(&cli.config)
        .with_context(|| format!("cannot read {}", cli.config.display()))?;
    let deployments: Deployments =
        serde_json::from_slice(&cfg_bytes).context("invalid deployments.json")?;

    let membership_id = &deployments.asp_membership;
    let non_membership_id = &deployments.asp_non_membership;

    eprintln!("==> ASP membership:     {membership_id}");
    eprintln!("==> ASP non-membership: {non_membership_id}");
    eprintln!("==> Network:            {}", cli.network);

    // Build per-user data: deterministic BN254 keys + blindings + leaves.
    // Seeds 1001..=1011, blinding = seed * 7919 (large prime, no overflow for this range).
    struct UserData {
        seed: u64,
        pub_key: Scalar,
        blinding: Scalar,
        leaf: Scalar,
    }

    let user_data: Vec<UserData> = (1001u64..=1011)
        .map(|seed| {
            let priv_key = Scalar::from(seed);
            let pub_key = derive_public_key(priv_key);
            let blinding = Scalar::from(seed * 7919);
            let leaf = poseidon2_hash2(pub_key, blinding, Some(Scalar::from(1u64)));
            UserData { seed, pub_key, blinding, leaf }
        })
        .collect();

    // --- Skip membership inserts if tree already has leaves ---
    // Check current membership root; if non-zero, bootstrap was already run.
    let current_membership_root = stellar_invoke(
        membership_id,
        &cli.admin,
        &cli.network,
        "get_root",
        &[],
        cli.sleep_secs,
        cli.max_retries,
    )
    .context("pre-check membership root")?;
    let is_empty = current_membership_root.trim() == "0" || current_membership_root.is_empty();

    // --- Insert membership leaves ---
    if !is_empty {
        eprintln!(
            "\n==> Membership tree already populated (root={}), skipping inserts.",
            &current_membership_root
        );
    } else {
    eprintln!("\n==> Inserting {} membership leaves…", user_data.len());
    for (i, u) in user_data.iter().enumerate() {
        let leaf_arg = scalar_to_u256_decimal(u.leaf);
        eprintln!(
            "  [{}/{}] seed={} leaf=0x{}…",
            i.saturating_add(1),
            user_data.len(),
            u.seed,
            &hex::encode(scalar_to_be_bytes(u.leaf))[..8],
        );
        stellar_invoke(
            membership_id,
            &cli.admin,
            &cli.network,
            "insert_leaf",
            &[("leaf", &leaf_arg)],
            cli.sleep_secs,
            cli.max_retries,
        )
        .with_context(|| format!("insert_leaf membership seed={}", u.seed))?;
    }

    } // end if is_empty (membership inserts)

    // --- Non-membership tree: leave empty for permissive mode ---
    //
    // An empty non-membership tree (root = 0) means nobody is sanctioned.
    // StateFetcher::get_nonmembership_proof handles root = 0 as a special
    // case: it returns a trivial is_old0=true proof without any on-chain
    // query. No inserts needed.
    eprintln!("\n==> Non-membership tree: leaving empty (permissive mode — root = 0).");

    // --- Fetch final roots ---
    eprintln!("\n==> Fetching final ASP roots…");
    let membership_root = stellar_invoke(
        membership_id,
        &cli.admin,
        &cli.network,
        "get_root",
        &[],
        cli.sleep_secs,
        cli.max_retries,
    )
    .context("get_root membership")?;
    let non_membership_root = stellar_invoke(
        non_membership_id,
        &cli.admin,
        &cli.network,
        "get_root",
        &[],
        cli.sleep_secs,
        cli.max_retries,
    )
    .context("get_root non-membership")?;

    eprintln!("  membership root:     {membership_root}");
    eprintln!("  non-membership root: {non_membership_root}");

    // --- Build output state ---
    let users: Vec<UserEntry> = user_data
        .iter()
        .map(|u| UserEntry {
            seed: u.seed,
            pub_key_hex: hex::encode(scalar_to_be_bytes(u.pub_key)),
            blinding_hex: hex::encode(scalar_to_be_bytes(u.blinding)),
            membership_leaf_hex: hex::encode(scalar_to_be_bytes(u.leaf)),
        })
        .collect();

    let state = AspState {
        network: cli.network.clone(),
        asp_membership_id: membership_id.clone(),
        asp_non_membership_id: non_membership_id.clone(),
        asp_membership_root: membership_root,
        asp_non_membership_root: non_membership_root,
        users,
    };

    let json = serde_json::to_string_pretty(&state).context("serialize asp-state")?;
    std::fs::write(&cli.output, &json)
        .with_context(|| format!("write {}", cli.output.display()))?;

    eprintln!("\n==> Done. State written to {}", cli.output.display());
    Ok(())
}
