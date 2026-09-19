use anchor_lang::prelude::*;
use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use solana_poseidon::{hashv, Endianness, Parameters};

/// Poseidon over BN254 (circom params) — byte-identical to the Noir circuit's hash.
pub fn poseidon(vals: &[&[u8]]) -> Result<[u8; 32]> {
    Ok(hashv(Parameters::Bn254X5, Endianness::BigEndian, vals)
        .map_err(|_| ProgramError::InvalidArgument)?
        .to_bytes())
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

/// Signed net public flow (extAmount - fee) as a canonical BN254 field element: `x` for x >= 0,
/// else `P - |x|`. Take the magnitude as a full `u128` (no `as u64` truncation) and let `Fr` reduce;
/// arkworks `into_bigint().to_bytes_be()` avoids the ark-serialize flag footgun.
pub fn public_amount_field(net: i128) -> [u8; 32] {
    let mag = Fr::from(net.unsigned_abs());
    let f = if net >= 0 { mag } else { -mag };
    let mut out = [0u8; 32];
    out.copy_from_slice(&f.into_bigint().to_bytes_be());
    out
}
