//! High-level prove_deposit / prove_withdraw flows.
//!
//! Each function:
//!   1. Reads production BN254/X25519 key material from the request.
//!   2. Fetches on-chain state (pool root, ASP proofs, Merkle paths).
//!   3. Calls the prover to produce TransactArtifacts + circuit inputs.
//!   4. Runs ark-circom to generate the Groth16 proof bytes.
//!   5. Returns the proof hex and whatever the caller needs next
//!      (XDR for deposits, relay body for withdrawals).

use anyhow::{Context, Result, anyhow};
use prover::{
    crypto::{asp_membership_leaf, derive_public_key},
    flows::{
        DepositParams, TransactInputNote, TransactOutput, TransferParams, WithdrawParams, deposit,
        transfer, withdraw,
    },
    merkle::MerklePrefixTree,
};
use stellar::{OnchainProofPublicInputs, PoolTransactInput, StateFetcher};
use types::{
    AspMembershipProof, ContractConfig, EncryptionPublicKey, ExtAmount, Field, NoteAmount,
    NotePrivateKey, NotePublicKey,
};
use zkhash::{
    ark_ff::{BigInteger, PrimeField},
    fields::bn256::FpBN256 as Scalar,
};

use crate::{
    chain::{fetch_asp_membership_leaves, fetch_pool_commitments},
    state::AppState,
    types::{
        DepositRequest, DepositResponse, RegisterAspMembershipRequest,
        RegisterAspMembershipResponse, RegisterRequest, RegisterResponse, TransferRequest,
        TransferResponse, WithdrawRequest, WithdrawResponse,
    },
};

fn scalar_to_field(s: Scalar) -> Result<Field> {
    let le = s.into_bigint().to_bytes_le();
    let mut bytes = [0u8; 32];
    let len = le.len().min(32);
    bytes[..len].copy_from_slice(&le[..len]);
    Field::try_from_le_bytes(bytes).map_err(|e| anyhow!("scalar_to_field: {e}"))
}

fn field_to_be_hex(f: Field) -> String {
    format!("0x{}", hex::encode(f.to_be_bytes()))
}

/// Parse a decimal string amount to `ExtAmount`.
fn parse_amount(s: &str) -> Result<ExtAmount> {
    let n: i128 = s.parse().map_err(|_| anyhow!("invalid amount: {s}"))?;
    Ok(ExtAmount::from(n))
}

/// Parse a decimal string to u64.
fn parse_u128(s: &str) -> Result<u128> {
    s.parse::<u128>()
        .map_err(|_| anyhow!("invalid amount: {s}"))
}

fn parse_hex32(s: &str, label: &str) -> Result<[u8; 32]> {
    let hex_str = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(hex_str).map_err(|e| anyhow!("{label} hex decode: {e}"))?;
    if bytes.len() != 32 {
        return Err(anyhow!("{label} must be 32 bytes, got {}", bytes.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn parse_note_private_key_hex(s: &str) -> Result<NotePrivateKey> {
    Ok(NotePrivateKey(parse_hex32(s, "notePrivateKeyHex")?))
}

fn parse_note_public_key_hex(s: &str) -> Result<NotePublicKey> {
    Ok(NotePublicKey(parse_hex32(s, "note public key")?))
}

fn parse_encryption_public_key_hex(s: &str) -> Result<EncryptionPublicKey> {
    Ok(EncryptionPublicKey(parse_hex32(
        s,
        "encryption public key",
    )?))
}

fn parse_field_le_mod_hex(s: &str, label: &str) -> Result<Field> {
    let bytes = parse_hex32(s, label)?;
    scalar_to_field(Scalar::from_le_bytes_mod_order(&bytes))
}

fn derive_note_public_key_from_private(priv_key: &NotePrivateKey) -> Result<NotePublicKey> {
    let bytes = derive_public_key(&priv_key.0).context("derive note public key")?;
    Ok(NotePublicKey(bytes.try_into().map_err(|v: Vec<u8>| {
        anyhow!("derive note public key: expected 32 bytes, got {}", v.len())
    })?))
}

/// Fetch ASP proofs for a given BN254 public key and membership blinding.
async fn fetch_asp_proofs(
    fetcher: &StateFetcher,
    note_pubkey: &NotePublicKey,
    membership_blinding: Field,
    from_ledger: u32,
) -> Result<(AspMembershipProof, types::AspNonMembershipProof)> {
    // -- ASP membership proof --
    let cfg = fetcher.contract_config();
    let client = fetcher.rpc();

    let leaves = fetch_asp_membership_leaves(client, &cfg.asp_membership, from_ledger)
        .await
        .context("fetch asp membership leaves")?;

    let asp_membership = fetcher
        .asp_state()
        .await
        .context("asp_state")?
        .asp_membership;

    let asp_levels = asp_membership.levels;
    let asp_root = asp_membership.root;

    let leaf_field = asp_membership_leaf(note_pubkey, &membership_blinding)
        .context("derive asp membership leaf")?;
    let leaf_idx = leaves
        .iter()
        .position(|leaf| *leaf == leaf_field)
        .ok_or_else(|| anyhow!("user public key not found in ASP membership tree"))
        .and_then(|idx| u32::try_from(idx).map_err(|_| anyhow!("leaf index overflow")))?;

    let tree = MerklePrefixTree::new(asp_levels, &leaves)?.into_built();
    let proof = tree
        .proof(leaf_idx)
        .context("asp membership Merkle proof")?;

    let membership_proof = AspMembershipProof {
        leaf: leaf_field,
        blinding: membership_blinding,
        path_elements: proof.path_elements().clone(),
        path_indices: proof.path_indices(),
        root: proof.root(),
    };

    // Sanity: membership root must match chain.
    if membership_proof.root != asp_root {
        tracing::warn!(
            local = %field_to_be_hex(membership_proof.root),
            chain = %field_to_be_hex(asp_root),
            "ASP membership root mismatch – leaves may be stale; continuing"
        );
    }

    // -- ASP non-membership proof --
    // source_account only used for simulation when the SMT is non-empty;
    // the admin address is a valid G... account that exists on testnet.
    let source_account = fetcher.contract_config().admin.as_str();
    let non_membership_root = fetcher
        .asp_state()
        .await
        .context("asp_state for non-membership root")?
        .asp_non_membership
        .root;
    let smt_depth = usize::try_from(asp_levels).map_err(|_| anyhow!("smt_depth overflow"))?;
    let non_membership_proof = fetcher
        .get_nonmembership_proof(note_pubkey, non_membership_root, smt_depth, source_account)
        .await
        .context("get_nonmembership_proof")?;

    Ok((membership_proof, non_membership_proof))
}

// ---------------------------------------------------------------------------
// Deposit
// ---------------------------------------------------------------------------

pub async fn prove_deposit(state: &AppState, req: DepositRequest) -> Result<DepositResponse> {
    let inner = &state.0;
    let fetcher = &inner.fetcher;
    let cfg = fetcher.contract_config();

    let pool_id = resolve_pool_id(cfg, req.pool_id.as_deref())?;
    let amount: ExtAmount = parse_amount(&req.amount_units)?;
    let amount_u128 = parse_u128(&req.amount_units)?;

    let priv_key = parse_note_private_key_hex(&req.note_private_key_hex)?;
    let note_pubkey = derive_note_public_key_from_private(&priv_key)?;
    let encryption_pubkey = parse_encryption_public_key_hex(&req.sender_encryption_public_hex)?;
    let membership_blinding =
        parse_field_le_mod_hex(&req.membership_blinding_hex, "membershipBlindingHex")?;

    // Fetch pool state.
    let pool_data = fetcher
        .contracts_data_for_pool(&pool_id)
        .await
        .context("contracts_data_for_pool")?;
    let pool_info = pool_data
        .pools
        .first()
        .ok_or_else(|| anyhow!("no pool info returned"))?;
    let pool_root = pool_info
        .merkle_root
        .ok_or_else(|| anyhow!("pool root is None"))?;
    let tree_depth = pool_info.merkle_levels;
    let smt_depth = pool_data.asp_membership.levels;

    // Fetch ASP proofs.
    let (membership_proof, non_membership_proof) = fetch_asp_proofs(
        fetcher,
        &note_pubkey,
        membership_blinding,
        inner.asp_membership_scan_start_ledger,
    )
    .await?;

    let output_blinding = random_field()?;
    let dummy_output_blinding = random_field()?;

    let params = DepositParams {
        priv_key,
        encryption_pubkey,
        pool_root,
        pool_address: pool_id.clone(),
        amount,
        outputs: vec![
            TransactOutput {
                amount: NoteAmount::from(amount_u128),
                blinding: output_blinding,
                recipient_note_pubkey: None,
                recipient_encryption_pubkey: None,
            },
            // Dummy output (amount=0) owned by the same key — serves as the
            // second input for the first withdraw step.
            TransactOutput {
                amount: NoteAmount::ZERO,
                blinding: dummy_output_blinding,
                recipient_note_pubkey: None,
                recipient_encryption_pubkey: None,
            },
        ],
        membership_proof,
        non_membership_proof,
        tree_depth,
        smt_depth,
    };

    let hash_fn =
        |ext: &types::ExtData| stellar::hash_ext_data_offchain(ext).map_err(|e| anyhow!("{e}"));
    let artifacts = deposit(params, hash_fn).context("deposit proof build")?;

    tracing::info!("running Groth16 prover for deposit...");
    let proof_bytes = inner
        .prover
        .prove(&artifacts.circuit_inputs)
        .context("prove deposit")?;
    let proof_hex = hex::encode(&proof_bytes);

    let prepared = &artifacts.prepared;
    let public = OnchainProofPublicInputs {
        root: prepared.pool_root,
        input_nullifiers: prepared.input_nullifiers,
        output_commitment0: prepared.output_commitments[0],
        output_commitment1: prepared.output_commitments[1],
        public_amount: prepared.public_amount_field,
        ext_data_hash_be: prepared.ext_data_hash_be,
        asp_membership_root: prepared.asp_membership_root,
        asp_non_membership_root: prepared.asp_non_membership_root,
    };

    let transact_input = PoolTransactInput {
        proof_uncompressed: proof_bytes,
        ext_data: artifacts.ext_data.clone(),
        public,
    };

    let prepared_tx = fetcher
        .prepare_pool_transact(&pool_id, &transact_input, &req.stellar_address)
        .await
        .context("prepare_pool_transact")?;

    let note_commitment_hex = field_to_be_hex(artifacts.prepared.output_commitments[0]);
    let dummy_commitment_hex = field_to_be_hex(artifacts.prepared.output_commitments[1]);

    Ok(DepositResponse {
        note_blinding_hex: field_to_be_hex(output_blinding),
        note_commitment_hex,
        dummy_blinding_hex: field_to_be_hex(dummy_output_blinding),
        dummy_commitment_hex,
        amount_units: req.amount_units,
        pool_root_hex: field_to_be_hex(pool_root),
        proof_hex,
        unsigned_xdr: prepared_tx.tx_xdr,
        auth_entries: prepared_tx.auth_entries,
        latest_ledger: prepared_tx.latest_ledger,
    })
}

// ---------------------------------------------------------------------------
// Withdraw (single step)
// ---------------------------------------------------------------------------

pub async fn prove_withdraw(state: &AppState, req: WithdrawRequest) -> Result<WithdrawResponse> {
    let inner = &state.0;
    let fetcher = &inner.fetcher;
    let cfg = fetcher.contract_config();

    let pool_id = resolve_pool_id(cfg, req.pool_id.as_deref())?;
    let withdraw_amount: ExtAmount = parse_amount(&req.withdraw_amount_units)?;
    let withdraw_amount_u128 = parse_u128(&req.withdraw_amount_units)?;
    let note_amount_u128 = parse_u128(&req.note_amount_units)?;

    let change_amount_u128 = note_amount_u128
        .checked_sub(withdraw_amount_u128)
        .ok_or_else(|| anyhow!("withdraw amount exceeds note amount"))?;

    let priv_key = parse_note_private_key_hex(&req.note_private_key_hex)?;
    let note_pubkey = derive_note_public_key_from_private(&priv_key)?;
    let encryption_pubkey = parse_encryption_public_key_hex(&req.sender_encryption_public_hex)?;
    let membership_blinding =
        parse_field_le_mod_hex(&req.membership_blinding_hex, "membershipBlindingHex")?;

    // Parse note and optional companion dummy blinding.
    let note_blinding_field = parse_field_hex(&req.note_blinding_hex)?;
    let dummy_input = if let Some(dummy_blinding_hex) = &req.dummy_blinding_hex {
        let dummy_blinding_field = parse_field_hex(dummy_blinding_hex)?;
        let dummy_leaf_index = req
            .note_leaf_index
            .checked_add(1)
            .ok_or_else(|| anyhow!("note_leaf_index overflow"))?;
        Some((dummy_leaf_index, dummy_blinding_field))
    } else {
        None
    };

    // Fetch pool state.
    let pool_data = fetcher
        .contracts_data_for_pool(&pool_id)
        .await
        .context("contracts_data_for_pool")?;
    let pool_info = pool_data
        .pools
        .first()
        .ok_or_else(|| anyhow!("no pool info"))?;
    let pool_root = pool_info
        .merkle_root
        .ok_or_else(|| anyhow!("pool root is None"))?;
    let tree_depth = pool_info.merkle_levels;
    let smt_depth = pool_data.asp_membership.levels;

    // Reconstruct pool Merkle tree from commitment events.
    let commitments = fetch_pool_commitments(fetcher.rpc(), &pool_id, inner.min_deployment_ledger)
        .await
        .context("fetch pool commitments")?;

    let mut leaves: Vec<Field> = Vec::new();
    for (idx, commitment) in &commitments {
        let i = usize::try_from(*idx).map_err(|_| anyhow!("commitment index overflow"))?;
        if i >= leaves.len() {
            leaves.resize(i.saturating_add(1), Field::ZERO);
        }
        leaves[i] = *commitment;
    }

    tracing::info!(
        "[withdraw] reconstructed pool tree: leaves={} requested_leaf={} dummy_leaf={:?} tree_depth={tree_depth}",
        leaves.len(),
        req.note_leaf_index,
        dummy_input.as_ref().map(|(idx, _)| *idx),
    );

    // Fail fast with an actionable message instead of a generic "index out of range".
    if (req.note_leaf_index as usize) >= leaves.len()
        || dummy_input
            .as_ref()
            .is_some_and(|(idx, _)| (*idx as usize) >= leaves.len())
    {
        return Err(anyhow!(
            "note leaf index out of range: requested leaf={} dummy={:?} but pool only has {} commitments. \
             This usually means the deposit's commitment events have not been indexed yet, or the note \
             belongs to a different pool. Indices present: {:?}",
            req.note_leaf_index,
            dummy_input.as_ref().map(|(idx, _)| *idx),
            leaves.len(),
            commitments.iter().map(|(i, _)| *i).collect::<Vec<_>>(),
        ));
    }

    let tree = MerklePrefixTree::new(tree_depth, &leaves)?.into_built();

    // Consistency check: the tree we rebuilt from events must hash to the same
    // root the pool reports on-chain. A mismatch means our commitment set is
    // stale/incomplete and any proof we generate will fail verification.
    match tree.root() {
        Ok(reconstructed_root) => {
            if reconstructed_root == pool_root {
                tracing::info!("[withdraw] reconstructed root matches on-chain pool root ✓");
            } else {
                tracing::warn!(
                    "[withdraw] ROOT MISMATCH: reconstructed={reconstructed_root:?} on_chain_pool_root={pool_root:?}; \
                     proof will likely fail verification (incomplete/stale commitment set)"
                );
            }
        }
        Err(e) => tracing::warn!("[withdraw] could not compute reconstructed root for check: {e}"),
    }

    let merkle_proof = tree
        .proof(req.note_leaf_index)
        .with_context(|| format!("pool Merkle proof for leaf {}", req.note_leaf_index))?;

    // Fetch ASP proofs.
    let (membership_proof, non_membership_proof) = fetch_asp_proofs(
        fetcher,
        &note_pubkey,
        membership_blinding,
        inner.asp_membership_scan_start_ledger,
    )
    .await?;

    // Outputs: change note + deterministic dummy (so next step can reconstruct).
    let change_blinding = random_field()?;
    let next_dummy_blinding = random_field()?;

    let mut inputs = vec![TransactInputNote {
        amount: NoteAmount::from(note_amount_u128),
        blinding: note_blinding_field,
        merkle_path_elements: merkle_proof.path_elements(),
        merkle_path_indices: merkle_proof.path_indices(),
    }];

    if let Some((dummy_leaf_index, dummy_blinding_field)) = dummy_input {
        let dummy_merkle_proof = tree
            .proof(dummy_leaf_index)
            .with_context(|| format!("pool Merkle proof for dummy leaf {}", dummy_leaf_index))?;
        inputs.push(TransactInputNote {
            amount: NoteAmount::ZERO,
            blinding: dummy_blinding_field,
            merkle_path_elements: dummy_merkle_proof.path_elements(),
            merkle_path_indices: dummy_merkle_proof.path_indices(),
        });
    }

    let params = WithdrawParams {
        priv_key,
        encryption_pubkey,
        pool_root,
        withdraw_recipient: req.recipient_stellar_address.clone(),
        withdraw_amount,
        inputs,
        outputs: Some(vec![
            TransactOutput {
                amount: NoteAmount::from(change_amount_u128),
                blinding: change_blinding,
                recipient_note_pubkey: None,
                recipient_encryption_pubkey: None,
            },
            TransactOutput {
                amount: NoteAmount::ZERO,
                blinding: next_dummy_blinding,
                recipient_note_pubkey: None,
                recipient_encryption_pubkey: None,
            },
        ]),
        membership_proof,
        non_membership_proof,
        tree_depth,
        smt_depth,
    };

    let hash_fn =
        |ext: &types::ExtData| stellar::hash_ext_data_offchain(ext).map_err(|e| anyhow!("{e}"));
    let artifacts = withdraw(params, hash_fn).context("withdraw proof build")?;

    tracing::info!("running Groth16 prover for withdraw...");
    let proof_bytes = inner
        .prover
        .prove(&artifacts.circuit_inputs)
        .context("prove withdraw")?;
    let proof_hex = hex::encode(&proof_bytes);

    let prepared = &artifacts.prepared;
    let change_commitment_hex = field_to_be_hex(prepared.output_commitments[0]);
    let next_dummy_commitment_hex = field_to_be_hex(prepared.output_commitments[1]);

    // Build the relay body that will be POSTed to the relayer's /relay endpoint.
    let ext = &artifacts.ext_data;
    let relay_body = serde_json::json!({
        "poolId": pool_id,
        "proofUncompressedHex": proof_hex,
        "extData": {
            "recipient": ext.recipient,
            "extAmount": ext.ext_amount.to_string(),
            "encryptedOutput0": ext.encrypted_output0,
            "encryptedOutput1": ext.encrypted_output1,
        },
        "public": {
            "root": field_to_be_hex(prepared.pool_root),
            "inputNullifiers": [
                field_to_be_hex(prepared.input_nullifiers[0]),
                field_to_be_hex(prepared.input_nullifiers[1]),
            ],
            "outputCommitment0": field_to_be_hex(prepared.output_commitments[0]),
            "outputCommitment1": field_to_be_hex(prepared.output_commitments[1]),
            "publicAmount": field_to_be_hex(prepared.public_amount_field),
            "extDataHashBe": prepared.ext_data_hash_be,
            "aspMembershipRoot": field_to_be_hex(prepared.asp_membership_root),
            "aspNonMembershipRoot": field_to_be_hex(prepared.asp_non_membership_root),
        }
    });

    Ok(WithdrawResponse {
        change_note_blinding_hex: field_to_be_hex(change_blinding),
        change_note_commitment_hex: change_commitment_hex,
        change_amount_units: change_amount_u128.to_string(),
        next_dummy_blinding_hex: field_to_be_hex(next_dummy_blinding),
        next_dummy_commitment_hex,
        relay_body,
    })
}

// ---------------------------------------------------------------------------
// Transfer (private note -> note)
// ---------------------------------------------------------------------------

pub async fn prove_transfer(state: &AppState, req: TransferRequest) -> Result<TransferResponse> {
    let inner = &state.0;
    let fetcher = &inner.fetcher;
    let cfg = fetcher.contract_config();

    let pool_id = resolve_pool_id(cfg, req.pool_id.as_deref())?;
    let transfer_amount_u128 = parse_u128(&req.transfer_amount_units)?;
    let input_note_specs = req.input_notes.as_ref().cloned().unwrap_or_else(|| {
        vec![crate::types::TransferInputNoteRequest {
            note_blinding_hex: req.note_blinding_hex.clone(),
            note_amount_units: req.note_amount_units.clone(),
            note_leaf_index: req.note_leaf_index,
        }]
    });
    if input_note_specs.is_empty() || input_note_specs.len() > 2 {
        return Err(anyhow!(
            "transfer inputNotes must contain one or two notes, got {}",
            input_note_specs.len()
        ));
    }
    let mut seen_leaf_indices: Vec<u32> = Vec::new();
    let mut input_total_u128 = 0u128;
    for note in &input_note_specs {
        if seen_leaf_indices.contains(&note.note_leaf_index) {
            return Err(anyhow!("duplicate transfer input note leaf index {}", note.note_leaf_index));
        }
        seen_leaf_indices.push(note.note_leaf_index);
        let amount = parse_u128(&note.note_amount_units)?;
        if amount == 0 {
            return Err(anyhow!("transfer input note amount must be positive"));
        }
        input_total_u128 = input_total_u128
            .checked_add(amount)
            .ok_or_else(|| anyhow!("transfer input amount overflow"))?;
    }
    let sender_change_amount_u128 = input_total_u128
        .checked_sub(transfer_amount_u128)
        .ok_or_else(|| anyhow!("transfer amount exceeds input note total"))?;

    let priv_key = parse_note_private_key_hex(&req.note_private_key_hex)?;
    let note_pubkey = derive_note_public_key_from_private(&priv_key)?;
    let encryption_pubkey = parse_encryption_public_key_hex(&req.sender_encryption_public_hex)?;
    let membership_blinding =
        parse_field_le_mod_hex(&req.membership_blinding_hex, "membershipBlindingHex")?;

    let pool_data = fetcher
        .contracts_data_for_pool(&pool_id)
        .await
        .context("contracts_data_for_pool")?;
    let pool_info = pool_data
        .pools
        .first()
        .ok_or_else(|| anyhow!("no pool info"))?;
    let pool_root = pool_info
        .merkle_root
        .ok_or_else(|| anyhow!("pool root is None"))?;
    let tree_depth = pool_info.merkle_levels;
    let smt_depth = pool_data.asp_membership.levels;

    let commitments = fetch_pool_commitments(fetcher.rpc(), &pool_id, inner.min_deployment_ledger)
        .await
        .context("fetch pool commitments")?;

    let mut leaves: Vec<Field> = Vec::new();
    for (idx, commitment) in &commitments {
        let i = usize::try_from(*idx).map_err(|_| anyhow!("commitment index overflow"))?;
        if i >= leaves.len() {
            leaves.resize(i.saturating_add(1), Field::ZERO);
        }
        leaves[i] = *commitment;
    }

    tracing::info!(
        "[transfer] reconstructed pool tree: leaves={} requested_leaves={:?} tree_depth={tree_depth}",
        leaves.len(),
        seen_leaf_indices,
    );

    let tree = MerklePrefixTree::new(tree_depth, &leaves)?.into_built();
    match tree.root() {
        Ok(reconstructed_root) => {
            if reconstructed_root == pool_root {
                tracing::info!("[transfer] reconstructed root matches on-chain pool root ✓");
            } else {
                tracing::warn!(
                    "[transfer] ROOT MISMATCH: reconstructed={reconstructed_root:?} on_chain_pool_root={pool_root:?}; \
                     proof will likely fail verification (incomplete/stale commitment set)"
                );
            }
        }
        Err(e) => tracing::warn!("[transfer] could not compute reconstructed root for check: {e}"),
    }

    let (membership_proof, non_membership_proof) = fetch_asp_proofs(
        fetcher,
        &note_pubkey,
        membership_blinding,
        inner.asp_membership_scan_start_ledger,
    )
    .await?;

    let recipient_blinding = random_field()?;
    let sender_change_blinding = random_field()?;
    let mut inputs = Vec::with_capacity(input_note_specs.len());
    for note in &input_note_specs {
        if (note.note_leaf_index as usize) >= leaves.len() {
            return Err(anyhow!(
                "note leaf index out of range: requested leaf={} but pool only has {} commitments. \
                 This usually means the note's commitment event has not been indexed yet, or the note \
                 belongs to a different pool. Indices present: {:?}",
                note.note_leaf_index,
                leaves.len(),
                commitments.iter().map(|(i, _)| *i).collect::<Vec<_>>(),
            ));
        }
        let merkle_proof = tree
            .proof(note.note_leaf_index)
            .with_context(|| format!("pool Merkle proof for leaf {}", note.note_leaf_index))?;
        inputs.push(TransactInputNote {
            amount: NoteAmount::from(parse_u128(&note.note_amount_units)?),
            blinding: parse_field_hex(&note.note_blinding_hex)?,
            merkle_path_elements: merkle_proof.path_elements(),
            merkle_path_indices: merkle_proof.path_indices(),
        });
    }

    let params = TransferParams {
        priv_key,
        encryption_pubkey,
        pool_root,
        pool_address: pool_id.clone(),
        inputs,
        outputs: vec![
            TransactOutput {
                amount: NoteAmount::from(transfer_amount_u128),
                blinding: recipient_blinding,
                recipient_note_pubkey: Some(parse_note_public_key_hex(
                    &req.recipient_note_public_hex,
                )?),
                recipient_encryption_pubkey: Some(parse_encryption_public_key_hex(
                    &req.recipient_x25519_public_hex,
                )?),
            },
            TransactOutput {
                amount: NoteAmount::from(sender_change_amount_u128),
                blinding: sender_change_blinding,
                recipient_note_pubkey: None,
                recipient_encryption_pubkey: None,
            },
        ],
        membership_proof,
        non_membership_proof,
        tree_depth,
        smt_depth,
    };

    let hash_fn =
        |ext: &types::ExtData| stellar::hash_ext_data_offchain(ext).map_err(|e| anyhow!("{e}"));
    let artifacts = transfer(params, hash_fn).context("transfer proof build")?;

    tracing::info!("running Groth16 prover for transfer...");
    let proof_bytes = inner
        .prover
        .prove(&artifacts.circuit_inputs)
        .context("prove transfer")?;
    let proof_hex = hex::encode(&proof_bytes);

    let prepared = &artifacts.prepared;
    let recipient_commitment_hex = field_to_be_hex(prepared.output_commitments[0]);
    let sender_change_commitment_hex = field_to_be_hex(prepared.output_commitments[1]);

    let ext = &artifacts.ext_data;
    let relay_body = serde_json::json!({
        "poolId": pool_id,
        "proofUncompressedHex": proof_hex,
        "extData": {
            "recipient": ext.recipient,
            "extAmount": ext.ext_amount.to_string(),
            "encryptedOutput0": ext.encrypted_output0,
            "encryptedOutput1": ext.encrypted_output1,
        },
        "public": {
            "root": field_to_be_hex(prepared.pool_root),
            "inputNullifiers": [
                field_to_be_hex(prepared.input_nullifiers[0]),
                field_to_be_hex(prepared.input_nullifiers[1]),
            ],
            "outputCommitment0": field_to_be_hex(prepared.output_commitments[0]),
            "outputCommitment1": field_to_be_hex(prepared.output_commitments[1]),
            "publicAmount": field_to_be_hex(prepared.public_amount_field),
            "extDataHashBe": prepared.ext_data_hash_be,
            "aspMembershipRoot": field_to_be_hex(prepared.asp_membership_root),
            "aspNonMembershipRoot": field_to_be_hex(prepared.asp_non_membership_root),
        }
    });

    Ok(TransferResponse {
        recipient_note_blinding_hex: field_to_be_hex(recipient_blinding),
        recipient_note_commitment_hex: recipient_commitment_hex,
        recipient_amount_units: transfer_amount_u128.to_string(),
        sender_change_blinding_hex: field_to_be_hex(sender_change_blinding),
        sender_change_commitment_hex,
        sender_change_amount_units: sender_change_amount_u128.to_string(),
        relay_body,
    })
}

// ---------------------------------------------------------------------------
// Register (public-key-registry)
// ---------------------------------------------------------------------------

pub async fn prove_register(state: &AppState, req: RegisterRequest) -> Result<RegisterResponse> {
    let fetcher = state.fetcher();
    let note_key_bytes = parse_hex32(&req.note_public_key_hex, "notePublicKeyHex")?;
    let enc_key_bytes = parse_hex32(&req.encryption_public_key_hex, "encryptionPublicKeyHex")?;
    let _membership_blinding =
        parse_field_le_mod_hex(&req.membership_blinding_hex, "membershipBlindingHex")?;

    let prepared = fetcher
        .prepare_register(&req.stellar_address, note_key_bytes, enc_key_bytes)
        .await
        .context("prepare_register")?;

    Ok(RegisterResponse {
        unsigned_xdr: prepared.tx_xdr,
        auth_entries: prepared.auth_entries,
        latest_ledger: prepared.latest_ledger,
    })
}

pub async fn prove_register_asp_membership(
    state: &AppState,
    req: RegisterAspMembershipRequest,
) -> Result<RegisterAspMembershipResponse> {
    let fetcher = state.fetcher();
    let note_pubkey = parse_note_public_key_hex(&req.note_public_key_hex)?;
    let membership_blinding =
        parse_field_le_mod_hex(&req.membership_blinding_hex, "membershipBlindingHex")?;
    let leaf = asp_membership_leaf(&note_pubkey, &membership_blinding)
        .context("derive asp membership leaf")?;
    let leaf_hex = field_to_be_hex(leaf);

    let cfg = fetcher.contract_config();
    let from_ledger = cfg
        .asp_membership_scan_start_ledger()
        .context("asp membership scan start ledger")?;
    let leaves = fetch_asp_membership_leaves(fetcher.rpc(), &cfg.asp_membership, from_ledger)
        .await
        .context("fetch asp membership leaves")?;
    if leaves.iter().any(|existing| *existing == leaf) {
        return Ok(RegisterAspMembershipResponse {
            already_member: true,
            membership_leaf_hex: leaf_hex,
            unsigned_xdr: None,
            auth_entries: Vec::new(),
            latest_ledger: None,
        });
    }

    let prepared = fetcher
        .prepare_asp_membership_insert(&req.admin_stellar_address, leaf)
        .await
        .context("prepare asp membership insert")?;

    Ok(RegisterAspMembershipResponse {
        already_member: false,
        membership_leaf_hex: leaf_hex,
        unsigned_xdr: Some(prepared.tx_xdr),
        auth_entries: prepared.auth_entries,
        latest_ledger: Some(prepared.latest_ledger),
    })
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn resolve_pool_id<'a>(cfg: &'a ContractConfig, requested: Option<&str>) -> Result<String> {
    if let Some(id) = requested {
        return Ok(id.to_owned());
    }
    cfg.pools
        .iter()
        .find(|p| p.enabled)
        .or_else(|| cfg.pools.first())
        .map(|p| p.pool_contract_id.clone())
        .ok_or_else(|| anyhow!("no pool configured in deployments.json"))
}

fn parse_field_hex(s: &str) -> Result<Field> {
    let hex_str = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(hex_str).map_err(|e| anyhow!("hex decode: {e}"))?;
    if bytes.len() != 32 {
        return Err(anyhow!("field hex must be 32 bytes, got {}", bytes.len()));
    }
    let mut be = [0u8; 32];
    be.copy_from_slice(&bytes);
    // Field::try_from_le_bytes expects little-endian; input is big-endian.
    be.reverse();
    Field::try_from_le_bytes(be).map_err(|e| anyhow!("parse field: {e}"))
}

fn random_field() -> Result<Field> {
    use ark_ff::UniformRand;
    let mut rng = ark_std::rand::rngs::OsRng;
    let scalar: Scalar = Scalar::rand(&mut rng);
    scalar_to_field(scalar)
}
