use anchor_lang::prelude::*;
use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use solana_keccak_hasher as keccak;
use solana_poseidon::{hashv, Endianness, Parameters};

/// Poseidon over BN254 (circom params) — byte-identical to the Noir circuit's hash.
pub fn poseidon(vals: &[&[u8]]) -> Result<[u8; 32]> {
    Ok(hashv(Parameters::Bn254X5, Endianness::BigEndian, vals)
        .map_err(|_| ProgramError::InvalidArgument)?
        .to_bytes())
}

/// Keccak-256 reduced into the BN254 scalar field.
pub fn keccak_field(vals: &[&[u8]]) -> [u8; 32] {
    field_bytes(Fr::from_be_bytes_mod_order(&keccak::hashv(vals).to_bytes()))
}

/// Whether bytes are the unique big-endian encoding of a BN254 scalar.
pub fn is_canonical_field(bytes: &[u8; 32]) -> bool {
    field_bytes(Fr::from_be_bytes_mod_order(bytes)) == *bytes
}

/// A u64 as a 32-byte big-endian field element.
pub fn u64_be32(x: u64) -> [u8; 32] {
    let mut b = [0u8; 32];
    b[24..32].copy_from_slice(&x.to_be_bytes());
    b
}

/// Split 32 bytes into two field-safe halves (each < 2^128 < P), so a 32-byte pubkey/mint hashes
/// with Poseidon without exceeding the field.
pub fn split32(b: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let mut hi = [0u8; 32];
    let mut lo = [0u8; 32];
    hi[16..32].copy_from_slice(&b[0..16]);
    lo[16..32].copy_from_slice(&b[16..32]);
    (hi, lo)
}

/// Signed public flow as a canonical BN254 field element: `x` for x >= 0,
/// else `P - |x|`. Take the magnitude as a full `u128` (no `as u64` truncation) and let `Fr` reduce;
/// arkworks `into_bigint().to_bytes_be()` avoids the ark-serialize flag footgun.
pub fn public_amount_field(net: i128) -> [u8; 32] {
    let mag = Fr::from(net.unsigned_abs());
    let f = if net >= 0 { mag } else { -mag };
    field_bytes(f)
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
