use anchor_lang::prelude::*;
use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use solana_keccak_hasher as keccak;
use solana_poseidon::{hashv, Endianness, Parameters};

use crate::ASSET_DOMAIN;

/// Poseidon over BN254 (circom params) — byte-identical to the Noir circuit's hash.
pub(crate) fn poseidon(values: &[&[u8]]) -> Result<[u8; 32]> {
    Ok(hashv(Parameters::Bn254X5, Endianness::BigEndian, values)
        .map_err(|_| ProgramError::InvalidArgument)?
        .to_bytes())
}

/// Keccak-256 reduced into the BN254 scalar field.
pub(crate) fn keccak_field(values: &[&[u8]]) -> [u8; 32] {
    field_bytes(Fr::from_be_bytes_mod_order(
        &keccak::hashv(values).to_bytes(),
    ))
}

/// Whether bytes are the unique big-endian encoding of a BN254 scalar.
pub(crate) fn is_canonical_field(bytes: &[u8; 32]) -> bool {
    field_bytes(Fr::from_be_bytes_mod_order(bytes)) == *bytes
}

pub(crate) fn u64_be32(value: u64) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes[24..32].copy_from_slice(&value.to_be_bytes());
    bytes
}

/// Split a pubkey into field-safe halves before hashing it with Poseidon.
fn split32(bytes: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let mut high = [0u8; 32];
    let mut low = [0u8; 32];
    high[16..32].copy_from_slice(&bytes[0..16]);
    low[16..32].copy_from_slice(&bytes[16..32]);
    (high, low)
}

pub(crate) fn asset_id(mint: &Pubkey) -> Result<[u8; 32]> {
    let (high, low) = split32(&mint.to_bytes());
    poseidon(&[&u64_be32(ASSET_DOMAIN), &high, &low])
}

/// Encode signed public flow as a canonical BN254 field element.
pub(crate) fn public_amount_field(amount: i128) -> [u8; 32] {
    let magnitude = Fr::from(amount.unsigned_abs());
    let field = if amount >= 0 { magnitude } else { -magnitude };
    field_bytes(field)
}

fn field_bytes(value: Fr) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&value.into_bigint().to_bytes_be());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn field_encoding_is_canonical_below_the_modulus_only() {
        assert!(is_canonical_field(&[0; 32]));
        assert!(is_canonical_field(&field_bytes(Fr::from(u64::MAX))));

        let modulus = Fr::MODULUS.to_bytes_be();
        let mut encoded = [0; 32];
        encoded[32 - modulus.len()..].copy_from_slice(&modulus);
        assert!(!is_canonical_field(&encoded));
    }
}
