//! E2E: Bulk payment flow — deposit 1000, pay 100 to each of 10 recipients.
//!
//! Validates the core "private wallet" idea on top of SPP:
//!   1. Deposit 1000 units (creates a shielded note).
//!   2. Execute 10 sequential private withdrawals of 100 units each.
//!      Every step consumes the current change note + a zero-value dummy note,
//!      produces a new change note + a fresh dummy, and sends 100 publicly to
//!      the recipient via `ext_amount`.  No new circuits required.
//!
//! Key design: all input notes (real and dummy) are owned by USER_SKEY.
//! This keeps the ASP membership trees identical across every step, so the
//! ASP is bootstrapped only once (during the deposit step) and remains
//! valid for all 10 subsequent payment proofs.
//!
//! Pool Merkle-tree slot layout (pool appends 2 leaves per transact call):
//!   [0, 1]       deposit dummy inputs  (bootstrapped directly, never spent)
//!   [2, 3]       deposit outputs       (1000-note + dummy, both owned by USER_SKEY)
//!   [4, 5]       payment-0 outputs     (change 900 + dummy)
//!   …
//!   [22, 23]     payment-9 outputs     (change 0 + dummy)

use super::utils::{
    LEVELS, NonMembership, build_membership_trees, bytes32_to_bigint, deploy_contracts,
    generate_proof, non_membership_overrides_from_pubs, scalar_to_u256, test_env, u256_to_scalar,
    wrap_groth16_proof,
};
use anyhow::Result;
use asp_membership::ASPMembershipClient;
use asp_non_membership::ASPNonMembershipClient;
use circuits::test::utils::{
    general::{poseidon2_hash2, scalar_to_bigint},
    keypair::derive_public_key,
    merkle_tree::merkle_root,
    transaction::commitment,
    transaction_case::{InputNote, OutputNote, TxCase, prepare_transaction_witness},
};
use pool::{ExtData, PoolContractClient, Proof, hash_ext_data};
use soroban_sdk::{Address, Bytes, I256, U256, Vec as SorobanVec, testutils::Address as _};
use zkhash::fields::bn256::FpBN256 as Scalar;

// ── Constants ────────────────────────────────────────────────────────────────

const DEPOSIT_AMOUNT: u64 = 1_000;
const PAYMENT_AMOUNT: u64 = 100;
const N_PAYMENTS: usize = 10;

// All inputs (real and dummy) are owned by USER_SKEY, keeping ASP roots
// consistent across deposit and all payment steps.
const USER_SKEY: u64 = 1001;

// Poseidon-hash "empty slot" value that the pool's Merkle tree uses for
// un-filled leaf positions.
const POSEIDON_ZERO: [u8; 32] = [
    37, 48, 34, 136, 219, 153, 53, 3, 68, 151, 65, 131, 206, 49, 13, 99, 181, 58, 187, 158, 240,
    248, 87, 87, 83, 238, 211, 110, 1, 24, 249, 206,
];

// ── Helper ───────────────────────────────────────────────────────────────────

/// Field-encode a negative amount for withdrawal's `public_amount`.
fn neg_amount(amount: u64) -> Scalar {
    -Scalar::from(amount)
}

// ── State machine ────────────────────────────────────────────────────────────

struct TxState<'e> {
    env: &'e soroban_sdk::Env,
    contracts: &'e super::utils::DeployedContracts,
    leaves: Vec<Scalar>,
    next_leaf_idx: usize,
}

impl<'e> TxState<'e> {
    fn new(env: &'e soroban_sdk::Env, contracts: &'e super::utils::DeployedContracts) -> Self {
        let poseidon_zero = u256_to_scalar(&U256::from_be_bytes(
            env,
            &Bytes::from_array(env, &POSEIDON_ZERO),
        ));
        Self {
            env,
            contracts,
            leaves: vec![poseidon_zero; 1 << LEVELS],
            next_leaf_idx: 0,
        }
    }

    /// Directly insert a leaf pair into the pool contract (no proof required).
    fn bootstrap_pair(&mut self, l0: Scalar, l1: Scalar) {
        let env = self.env;
        let idx = self.next_leaf_idx;
        self.leaves[idx] = l0;
        self.leaves[idx.checked_add(1).expect("leaf index overflow")] = l1;
        let l0u = scalar_to_u256(env, l0);
        let l1u = scalar_to_u256(env, l1);
        env.as_contract(&self.contracts.pool, || {
            let _ = pool::merkle_with_history::MerkleTreeWithHistory::insert_two_leaves(
                env, l0u, l1u,
            );
        });
        self.next_leaf_idx = self.next_leaf_idx.checked_add(2).expect("next_leaf overflow");
    }

    /// Populate the ASP trees for a given TxCase.  Call once before the first
    /// transact.  All subsequent transacts that use the same priv_keys will
    /// produce matching ASP roots automatically.
    fn bootstrap_asp(&self, case: &TxCase) -> Result<()> {
        let env = self.env;
        let asp_m = ASPMembershipClient::new(env, &self.contracts.asp_membership);
        let asp_nm = ASPNonMembershipClient::new(env, &self.contracts.asp_non_membership);

        let witness = prepare_transaction_witness(case, self.leaves.clone(), LEVELS)?;
        let mut membership_trees =
            build_membership_trees(case, |j| 0xFEED_FACEu64 ^ ((j as u64) << 40));
        // Fix membership leaf positions to 0 and 1 for all steps, matching
        // the pattern used in e2e_pool_2tx_plan.rs.  This keeps ASP roots
        // identical across deposit and all payment steps.
        membership_trees[0].index = 0;
        if membership_trees.len() > 1 {
            membership_trees[1].index = 1;
        }

        let mut memb_leaves = membership_trees[0].leaves;
        for (k, mt) in membership_trees.iter().enumerate().take(case.inputs.len()) {
            memb_leaves[mt.index] = poseidon2_hash2(
                witness.public_keys[k],
                mt.blinding,
                Some(Scalar::from(1u64)),
            );
        }
        for leaf in memb_leaves {
            asp_m.insert_leaf(&scalar_to_u256(env, leaf));
        }

        for (key, value) in non_membership_overrides_from_pubs(&witness.public_keys) {
            let mut pk = [0u8; 32];
            let mut pv = [0u8; 32];
            let kb = key.to_bytes_be().1;
            let vb = value.to_bytes_be().1;
            pk[32usize.saturating_sub(kb.len())..].copy_from_slice(&kb);
            pv[32usize.saturating_sub(vb.len())..].copy_from_slice(&vb);
            asp_nm.insert_leaf(
                &U256::from_be_bytes(env, &Bytes::from_array(env, &pk)),
                &U256::from_be_bytes(env, &Bytes::from_array(env, &pv)),
            );
        }
        Ok(())
    }

    /// Generate a Groth16 proof and execute one on-chain `transact`.
    fn transact(&mut self, case: &TxCase, public_amount: Scalar, ext_data: &ExtData) -> Result<()> {
        let env = self.env;
        let pool_client = PoolContractClient::new(env, &self.contracts.pool);
        let asp_m = ASPMembershipClient::new(env, &self.contracts.asp_membership);
        let asp_nm = ASPNonMembershipClient::new(env, &self.contracts.asp_non_membership);

        let ext_data_hash_bytes = hash_ext_data(env, ext_data);
        let mut membership_trees =
            build_membership_trees(case, |j| 0xFEED_FACEu64 ^ ((j as u64) << 40));
        // Keep membership leaf positions fixed at 0, 1 across all steps
        // so ASP roots stay consistent with the bootstrap done at deposit time.
        membership_trees[0].index = 0;
        if membership_trees.len() > 1 {
            membership_trees[1].index = 1;
        }
        let non_membership: Vec<NonMembership> = case
            .inputs
            .iter()
            .map(|n| NonMembership {
                key_non_inclusion: scalar_to_bigint(derive_public_key(n.priv_key)),
            })
            .collect();

        let witness = prepare_transaction_witness(case, self.leaves.clone(), LEVELS)?;
        let result = generate_proof(
            case,
            self.leaves.clone(),
            public_amount,
            &membership_trees,
            &non_membership,
            Some(bytes32_to_bigint(&ext_data_hash_bytes)),
        )?;
        assert!(result.verified, "Proof must verify locally");

        let circuit_root = scalar_to_u256(env, witness.root);
        assert_eq!(
            circuit_root,
            pool_client.get_root(),
            "off-chain root must match pool before transact"
        );

        let asp_membership_root = asp_m.get_root();
        let asp_non_membership_root = asp_nm.get_root();
        let groth16_proof = wrap_groth16_proof(env, result);

        let mut input_nullifiers = SorobanVec::new(env);
        for nul in &witness.nullifiers {
            input_nullifiers.push_back(scalar_to_u256(env, *nul));
        }

        let out0_cm =
            commitment(case.outputs[0].amount, case.outputs[0].pub_key, case.outputs[0].blinding);
        let out1_cm =
            commitment(case.outputs[1].amount, case.outputs[1].pub_key, case.outputs[1].blinding);

        let proof = Proof {
            proof: groth16_proof,
            root: circuit_root,
            input_nullifiers,
            output_commitment0: scalar_to_u256(env, out0_cm),
            output_commitment1: scalar_to_u256(env, out1_cm),
            public_amount: scalar_to_u256(env, public_amount),
            ext_data_hash: ext_data_hash_bytes,
            asp_membership_root,
            asp_non_membership_root,
        };

        let sender = Address::generate(env);
        match pool_client.try_transact(&proof, ext_data, &sender) {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => panic!("transact contract error: {e:?}"),
            Err(e) => panic!("transact invoke failed: {e:?}"),
        }

        // Update off-chain leaves with pool's newly inserted outputs.
        let idx0 = self.next_leaf_idx;
        let idx1 = idx0.checked_add(1).expect("leaf index overflow");
        self.leaves[idx0] = out0_cm;
        self.leaves[idx1] = out1_cm;
        self.next_leaf_idx = self.next_leaf_idx.checked_add(2).expect("next_leaf overflow");

        // Confirm sync.
        assert_eq!(
            merkle_root(self.leaves.clone()),
            u256_to_scalar(&pool_client.get_root()),
            "leaves must stay in sync with pool after transact"
        );
        Ok(())
    }
}

// ── Test ─────────────────────────────────────────────────────────────────────

/// Full bulk-payment E2E: deposit 1000 units then pay 100 units to each of 10
/// distinct recipients using sequential 2-in/2-out transacts.
#[test]
#[cfg_attr(miri, ignore)]
fn test_e2e_deposit_and_pay_10_recipients() -> Result<()> {
    let env = test_env();
    env.mock_all_auths();

    let user_pub = derive_public_key(Scalar::from(USER_SKEY));
    let recipients: Vec<Address> =
        (0..N_PAYMENTS).map(|_| Address::generate(&env)).collect();

    let contracts = deploy_contracts(&env);
    let mut state = TxState::new(&env, &contracts);

    // Deposit bootstrap: pre-insert 2 dummy input notes (amount=0, owned by
    // USER_SKEY so they share the same ASP membership as real payment notes).
    let dep_in_0 = commitment(Scalar::from(0u64), user_pub, Scalar::from(100u64));
    let dep_in_1 = commitment(Scalar::from(0u64), user_pub, Scalar::from(101u64));
    state.bootstrap_pair(dep_in_0, dep_in_1);
    // Pool counter = 2; deposit transact will insert at [2, 3].

    // ── Deposit ──────────────────────────────────────────────────────────────
    // Both inputs use USER_SKEY so the ASP bootstrap works for all future steps.
    let deposit_case = TxCase::new(
        vec![
            InputNote {
                leaf_index: 0,
                priv_key: Scalar::from(USER_SKEY),
                blinding: Scalar::from(100u64),
                amount: Scalar::from(0u64),
            },
            InputNote {
                leaf_index: 1,
                priv_key: Scalar::from(USER_SKEY),
                blinding: Scalar::from(101u64),
                amount: Scalar::from(0u64),
            },
        ],
        vec![
            OutputNote {
                pub_key: user_pub,
                blinding: Scalar::from(200u64),
                amount: Scalar::from(DEPOSIT_AMOUNT),
            },
            // Dummy output also owned by USER_SKEY so it can serve as a
            // dummy input in payment 0 with priv_key = USER_SKEY.
            OutputNote {
                pub_key: user_pub,
                blinding: Scalar::from(201u64),
                amount: Scalar::from(0u64),
            },
        ],
    );

    let deposit_ext = ExtData {
        recipient: Address::generate(&env),
        ext_amount: I256::from_i128(&env, DEPOSIT_AMOUNT as i128),
        encrypted_output0: Bytes::new(&env),
        encrypted_output1: Bytes::new(&env),
    };

    state.bootstrap_asp(&deposit_case)?;
    state.transact(&deposit_case, Scalar::from(DEPOSIT_AMOUNT), &deposit_ext)?;
    // Pool counter = 4; leaves[2] = 1000-note, leaves[3] = dummy-0.
    println!("Deposit OK — {DEPOSIT_AMOUNT} units in pool");

    // ── Sequential payments ───────────────────────────────────────────────────
    // Each step spends:
    //   - input 0: the change note from the previous step (priv_key=USER_SKEY)
    //   - input 1: the dummy output from the previous step (priv_key=USER_SKEY)
    // Both inputs use USER_SKEY → same ASP structure → roots match on-chain.
    for i in 0..N_PAYMENTS {
        let current_balance = DEPOSIT_AMOUNT
            .checked_sub(
                PAYMENT_AMOUNT
                    .checked_mul(i as u64)
                    .expect("payment mul overflow"),
            )
            .expect("balance underflow");
        let change = current_balance
            .checked_sub(PAYMENT_AMOUNT)
            .expect("change underflow");

        let in_idx_0 = 2usize
            .checked_add(i.checked_mul(2).expect("i*2 overflow"))
            .expect("in_idx_0 overflow");
        let in_idx_1 = in_idx_0.checked_add(1).expect("in_idx_1 overflow");

        // Blindings for the INPUTS of this step = blindings from the OUTPUTS
        // of the previous step.
        let (in_blind_0, in_blind_1): (u64, u64) = if i == 0 {
            (200, 201) // deposit outputs
        } else {
            let prev = (i as u64).checked_sub(1).expect("i>0 ensures no underflow");
            (
                300u64.checked_add(prev).expect("in_blind_0 overflow"),
                400u64.checked_add(prev).expect("in_blind_1 overflow"),
            )
        };
        let out_change_blind: u64 = 300u64.checked_add(i as u64).expect("out_change overflow");
        let out_dummy_blind: u64 = 400u64.checked_add(i as u64).expect("out_dummy overflow");

        let pay_case = TxCase::new(
            vec![
                InputNote {
                    leaf_index: in_idx_0,
                    priv_key: Scalar::from(USER_SKEY),
                    blinding: Scalar::from(in_blind_0),
                    amount: Scalar::from(current_balance),
                },
                InputNote {
                    leaf_index: in_idx_1,
                    priv_key: Scalar::from(USER_SKEY),
                    blinding: Scalar::from(in_blind_1),
                    amount: Scalar::from(0u64),
                },
            ],
            vec![
                OutputNote {
                    pub_key: user_pub,
                    blinding: Scalar::from(out_change_blind),
                    amount: Scalar::from(change),
                },
                // Dummy output owned by USER_SKEY so the next step can use
                // USER_SKEY as priv_key for its dummy input.
                OutputNote {
                    pub_key: user_pub,
                    blinding: Scalar::from(out_dummy_blind),
                    amount: Scalar::from(0u64),
                },
            ],
        );

        let pay_ext = ExtData {
            recipient: recipients[i].clone(),
            ext_amount: I256::from_i128(&env, -(PAYMENT_AMOUNT as i128)),
            encrypted_output0: Bytes::new(&env),
            encrypted_output1: Bytes::new(&env),
        };

        state.transact(&pay_case, neg_amount(PAYMENT_AMOUNT), &pay_ext)?;

        println!(
            "Payment {}/{N_PAYMENTS}: {PAYMENT_AMOUNT} units → recipient {i}  (change left: {change})",
            i.checked_add(1).expect("display counter overflow"),
        );
    }

    println!("All {N_PAYMENTS} payments complete. Final pool change: 0 units.");
    Ok(())
}
