use axum::Json;
use prover::{crypto::derive_public_key, notes::try_decrypt_and_derive_user_note};
use types::{EncryptionPrivateKey, Field, NoteKeyPair, NotePrivateKey, NotePublicKey};

use crate::{
    error::{ProverError, ProverResult},
    types::{
        DecryptOutputNoteRequest, DecryptOutputNoteResponse, DeriveNotePublicKeyRequest,
        DeriveNotePublicKeyResponse,
    },
};

fn parse_hex32(input: &str) -> Result<[u8; 32], String> {
    let trimmed = input.trim().trim_start_matches("0x");
    let bytes = hex::decode(trimmed).map_err(|e| format!("invalid hex: {e}"))?;
    bytes
        .try_into()
        .map_err(|bytes: Vec<u8>| format!("expected 32 bytes, got {}", bytes.len()))
}

pub async fn derive_note_public_key_handler(
    Json(req): Json<DeriveNotePublicKeyRequest>,
) -> ProverResult<Json<DeriveNotePublicKeyResponse>> {
    let private_key = parse_hex32(&req.note_private_key_hex)
        .map_err(|e| ProverError::BadRequest(format!("notePrivateKeyHex: {e}")))?;
    let public_key = derive_public_key(&private_key)
        .map_err(|e| ProverError::ProofFailed(format!("derive note public key: {e}")))?;

    Ok(Json(DeriveNotePublicKeyResponse {
        note_public_key_hex: hex::encode(public_key),
    }))
}

fn parse_commitment_hex(input: &str) -> Result<Field, String> {
    Field::try_from_be_bytes(parse_hex32(input).map_err(|e| format!("commitmentHex: {e}"))?)
        .map_err(|e| format!("commitmentHex: {e}"))
}

fn prefixed_field_hex(field: Field) -> String {
    format!("0x{}", hex::encode(field.to_be_bytes()))
}

pub async fn decrypt_output_note_handler(
    Json(req): Json<DecryptOutputNoteRequest>,
) -> ProverResult<Json<DecryptOutputNoteResponse>> {
    let note_private_key = NotePrivateKey(
        parse_hex32(&req.note_private_key_hex)
            .map_err(|e| ProverError::BadRequest(format!("notePrivateKeyHex: {e}")))?,
    );
    let note_public_key = NotePublicKey(
        derive_public_key(&note_private_key.0)
            .map_err(|e| ProverError::ProofFailed(format!("derive note public key: {e}")))?
            .try_into()
            .map_err(|bytes: Vec<u8>| {
                ProverError::Internal(format!(
                    "derive note public key: expected 32 bytes, got {}",
                    bytes.len()
                ))
            })?,
    );
    let encryption_private_key = EncryptionPrivateKey(
        parse_hex32(&req.encryption_private_key_hex)
            .map_err(|e| ProverError::BadRequest(format!("encryptionPrivateKeyHex: {e}")))?,
    );
    let commitment = parse_commitment_hex(&req.commitment_hex)
        .map_err(|e| ProverError::BadRequest(e.to_string()))?;
    if req.encrypted_output.is_empty() {
        return Err(ProverError::BadRequest(
            "encryptedOutput must not be empty".to_string(),
        ));
    }

    let note_keypair = NoteKeyPair {
        private: note_private_key,
        public: note_public_key,
    };
    let derived = try_decrypt_and_derive_user_note(
        &note_keypair,
        &encryption_private_key,
        &commitment,
        req.leaf_index,
        &req.encrypted_output,
    )
    .map_err(|e| ProverError::ProofFailed(format!("decrypt output note: {e}")))?
    .ok_or_else(|| {
        ProverError::ProofFailed(
            "encrypted output is not addressed to this wallet or does not match commitment"
                .to_string(),
        )
    })?;

    Ok(Json(DecryptOutputNoteResponse {
        amount_units: derived.amount.to_string(),
        blinding_hex: prefixed_field_hex(derived.blinding),
        commitment_hex: prefixed_field_hex(commitment),
        expected_nullifier_hex: prefixed_field_hex(derived.expected_nullifier),
    }))
}
