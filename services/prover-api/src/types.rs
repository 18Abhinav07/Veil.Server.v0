use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Keys
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeriveNotePublicKeyRequest {
    /// BN254 note private key hex. Transient key material; never persist it.
    pub note_private_key_hex: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeriveNotePublicKeyResponse {
    pub note_public_key_hex: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DecryptOutputNoteRequest {
    /// Recipient BN254 note private key hex. Transient key material; never persist it.
    pub note_private_key_hex: String,
    /// Recipient X25519 private key hex. Transient key material; never persist it.
    pub encryption_private_key_hex: String,
    /// Recipient output commitment hex from the pool event.
    pub commitment_hex: String,
    /// Leaf index of the recipient output commitment.
    pub leaf_index: u32,
    /// Encrypted output bytes from the transfer response / pool event.
    pub encrypted_output: Vec<u8>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DecryptOutputNoteResponse {
    pub amount_units: String,
    pub blinding_hex: String,
    pub commitment_hex: String,
    pub expected_nullifier_hex: String,
}

// ---------------------------------------------------------------------------
// Deposit
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DepositRequest {
    /// Sender BN254 note private key hex. This is transient spend material and
    /// must never be persisted by the API.
    pub note_private_key_hex: String,
    /// Sender X25519 encryption public key hex.
    pub sender_encryption_public_hex: String,
    /// Sender ASP membership blinding hex.
    pub membership_blinding_hex: String,
    /// Deposit amount in USDC base units (7 decimals, so 1 USDC = 10_000_000).
    pub amount_units: String,
    /// Depositor's Stellar address (G...) — used as the transaction source.
    pub stellar_address: String,
    /// Optional pool contract id; defaults to the first enabled pool.
    pub pool_id: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DepositResponse {
    /// Output note blinding hex (big-endian 0x-prefixed) — save this for withdrawals.
    pub note_blinding_hex: String,
    /// Output note commitment hex.
    pub note_commitment_hex: String,
    /// Deposited amount (echoed back).
    pub amount_units: String,
    /// Pool Merkle root used in the proof.
    pub pool_root_hex: String,
    /// Proof (512 hex chars = 256 bytes uncompressed Groth16).
    pub proof_hex: String,
    /// Unsigned Soroban transaction XDR (base64) — sign with Freighter.
    pub unsigned_xdr: String,
    /// Base64 Soroban auth entries from simulation (Freighter re-signs these).
    pub auth_entries: Vec<String>,
    /// Latest ledger from simulation (auth entries expire after latest_ledger + ~100).
    pub latest_ledger: u32,
    /// Companion dummy note blinding (leaf_index + 1) — needed as second input for first withdraw.
    pub dummy_blinding_hex: String,
    /// Companion dummy note commitment hex.
    pub dummy_commitment_hex: String,
}

// ---------------------------------------------------------------------------
// Withdraw (single step — call N times for bulk)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WithdrawRequest {
    /// Sender BN254 note private key hex.
    pub note_private_key_hex: String,
    /// Sender X25519 encryption public key hex.
    pub sender_encryption_public_hex: String,
    /// Sender ASP membership blinding hex.
    pub membership_blinding_hex: String,
    /// Note blinding hex from the deposit (or previous withdraw change note).
    pub note_blinding_hex: String,
    /// Note amount in USDC base units.
    pub note_amount_units: String,
    /// Leaf index of the note in the pool Merkle tree.
    pub note_leaf_index: u32,
    /// Optional dummy companion note blinding hex (always amount=0, leaf = note_leaf_index + 1).
    ///
    /// Legacy frontend deposits create a companion dummy note and pass it here.
    /// Lane-2 received notes may not have an adjacent dummy owned by the same
    /// recipient, so the prover can omit this and let the core flow pad a
    /// synthetic zero input.
    pub dummy_blinding_hex: Option<String>,
    /// Amount to withdraw in USDC base units.
    pub withdraw_amount_units: String,
    /// Recipient Stellar address (G...).
    pub recipient_stellar_address: String,
    /// Optional pool contract id; defaults to the first enabled pool.
    pub pool_id: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WithdrawResponse {
    /// Change note blinding hex (use this for the next withdraw step).
    pub change_note_blinding_hex: String,
    /// Change note commitment hex.
    pub change_note_commitment_hex: String,
    /// Change note amount in USDC base units.
    pub change_amount_units: String,
    /// Dummy companion note blinding for the next step (always amount=0).
    pub next_dummy_blinding_hex: String,
    /// Dummy companion note commitment hex for the next step.
    pub next_dummy_commitment_hex: String,
    /// Relay body — POST this directly to the relayer's /relay endpoint.
    pub relay_body: serde_json::Value,
}

// ---------------------------------------------------------------------------
// Transfer (private note -> note)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransferInputNoteRequest {
    /// Input note blinding hex.
    pub note_blinding_hex: String,
    /// Input note amount in USDC base units.
    pub note_amount_units: String,
    /// Leaf index of the input note in the pool Merkle tree.
    pub note_leaf_index: u32,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransferRequest {
    /// Sender BN254 note private key hex.
    pub note_private_key_hex: String,
    /// Sender X25519 encryption public key hex.
    pub sender_encryption_public_hex: String,
    /// Sender ASP membership blinding hex.
    pub membership_blinding_hex: String,
    /// Input note blinding hex.
    pub note_blinding_hex: String,
    /// Input note amount in USDC base units.
    pub note_amount_units: String,
    /// Leaf index of the input note in the pool Merkle tree.
    pub note_leaf_index: u32,
    /// Amount to transfer privately in USDC base units.
    pub transfer_amount_units: String,
    /// Recipient BN254 note public key hex.
    pub recipient_note_public_hex: String,
    /// Recipient X25519 encryption public key hex.
    pub recipient_x25519_public_hex: String,
    /// Optional pool contract id; defaults to the first enabled pool.
    pub pool_id: Option<String>,
    /// Optional explicit input note list. If omitted, the legacy single-note fields are used.
    pub input_notes: Option<Vec<TransferInputNoteRequest>>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TransferResponse {
    /// Recipient note blinding hex.
    pub recipient_note_blinding_hex: String,
    /// Recipient note commitment hex.
    pub recipient_note_commitment_hex: String,
    /// Recipient note amount in USDC base units.
    pub recipient_amount_units: String,
    /// Sender change note blinding hex, if any change remains.
    pub sender_change_blinding_hex: String,
    /// Sender change note commitment hex.
    pub sender_change_commitment_hex: String,
    /// Sender change amount in USDC base units.
    pub sender_change_amount_units: String,
    /// Relay body — POST this directly to the relayer's /relay endpoint.
    pub relay_body: serde_json::Value,
}

// ---------------------------------------------------------------------------
// Register (public-key-registry)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterRequest {
    /// Stellar address for the transaction source.
    pub stellar_address: String,
    /// BN254 note public key hex.
    pub note_public_key_hex: String,
    /// X25519 encryption public key hex.
    pub encryption_public_key_hex: String,
    /// ASP membership blinding hex. Used to derive the membership leaf for the
    /// registration service; not stored by prover-api.
    pub membership_blinding_hex: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterResponse {
    /// Unsigned Soroban transaction XDR (base64).
    pub unsigned_xdr: String,
    /// Auth entries.
    pub auth_entries: Vec<String>,
    /// Latest ledger.
    pub latest_ledger: u32,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterAspMembershipRequest {
    /// Stellar admin/service address for the ASP membership insert transaction.
    pub admin_stellar_address: String,
    /// BN254 note public key hex.
    pub note_public_key_hex: String,
    /// ASP membership blinding hex.
    pub membership_blinding_hex: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterAspMembershipResponse {
    pub already_member: bool,
    pub membership_leaf_hex: String,
    pub unsigned_xdr: Option<String>,
    pub auth_entries: Vec<String>,
    pub latest_ledger: Option<u32>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transfer_request_accepts_production_keys_without_seed_fields() {
        let req: TransferRequest = serde_json::from_value(serde_json::json!({
            "notePrivateKeyHex": "11".repeat(32),
            "senderEncryptionPublicHex": "22".repeat(32),
            "membershipBlindingHex": "33".repeat(32),
            "noteBlindingHex": "0x44".to_owned() + &"44".repeat(31),
            "noteAmountUnits": "1000000000",
            "noteLeafIndex": 4,
            "transferAmountUnits": "250000000",
            "recipientNotePublicHex": "55".repeat(32),
            "recipientX25519PublicHex": "66".repeat(32),
            "poolId": "CPOOL"
        }))
        .expect("production key transfer request should deserialize");

        assert_eq!(req.transfer_amount_units, "250000000");
    }

    #[test]
    fn transfer_request_accepts_optional_two_input_notes() {
        let req: TransferRequest = serde_json::from_value(serde_json::json!({
            "notePrivateKeyHex": "11".repeat(32),
            "senderEncryptionPublicHex": "22".repeat(32),
            "membershipBlindingHex": "33".repeat(32),
            "noteBlindingHex": "0x44".to_owned() + &"44".repeat(31),
            "noteAmountUnits": "1000000000",
            "noteLeafIndex": 4,
            "inputNotes": [
                {
                    "noteBlindingHex": "0x44".to_owned() + &"44".repeat(31),
                    "noteAmountUnits": "1000000000",
                    "noteLeafIndex": 4
                },
                {
                    "noteBlindingHex": "0x77".to_owned() + &"77".repeat(31),
                    "noteAmountUnits": "250000000",
                    "noteLeafIndex": 9
                }
            ],
            "transferAmountUnits": "1250000000",
            "recipientNotePublicHex": "55".repeat(32),
            "recipientX25519PublicHex": "66".repeat(32),
            "poolId": "CPOOL"
        }))
        .expect("two-input transfer request should deserialize");

        let input_notes = req.input_notes.expect("inputNotes should deserialize");
        assert_eq!(input_notes.len(), 2);
        assert_eq!(input_notes[1].note_amount_units, "250000000");
        assert_eq!(input_notes[1].note_leaf_index, 9);
    }

    #[test]
    fn register_request_accepts_public_keys_without_seed() {
        let req: RegisterRequest = serde_json::from_value(serde_json::json!({
            "stellarAddress": "GAT4VWR53RQEYILFJVKUZVJFYGEPRANKIFUSHZYWE3IG6RQF7INNKCKC",
            "notePublicKeyHex": "11".repeat(32),
            "encryptionPublicKeyHex": "22".repeat(32),
            "membershipBlindingHex": "33".repeat(32)
        }))
        .expect("production key register request should deserialize");

        assert_eq!(
            req.stellar_address,
            "GAT4VWR53RQEYILFJVKUZVJFYGEPRANKIFUSHZYWE3IG6RQF7INNKCKC"
        );
    }

    #[test]
    fn register_asp_membership_request_accepts_admin_and_public_member_data() {
        let req: RegisterAspMembershipRequest = serde_json::from_value(serde_json::json!({
            "adminStellarAddress": "GAT4VWR53RQEYILFJVKUZVJFYGEPRANKIFUSHZYWE3IG6RQF7INNKCKC",
            "notePublicKeyHex": "11".repeat(32),
            "membershipBlindingHex": "22".repeat(32)
        }))
        .expect("asp membership request should deserialize");

        assert_eq!(req.note_public_key_hex, "11".repeat(32));
    }

    #[test]
    fn derive_note_public_key_request_accepts_private_key_hex() {
        let req: DeriveNotePublicKeyRequest = serde_json::from_value(serde_json::json!({
            "notePrivateKeyHex": "11".repeat(32)
        }))
        .expect("derive note public key request should deserialize");

        assert_eq!(req.note_private_key_hex, "11".repeat(32));
    }

    #[test]
    fn decrypt_output_note_request_accepts_recipient_keys_without_seed() {
        let req: DecryptOutputNoteRequest = serde_json::from_value(serde_json::json!({
            "notePrivateKeyHex": "11".repeat(32),
            "encryptionPrivateKeyHex": "22".repeat(32),
            "commitmentHex": "0x33".to_owned() + &"33".repeat(31),
            "leafIndex": 81,
            "encryptedOutput": [1, 2, 3, 4]
        }))
        .expect("decrypt output note request should deserialize");

        assert_eq!(req.leaf_index, 81);
        assert_eq!(req.encrypted_output, vec![1, 2, 3, 4]);
    }
}
