use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};

pub(crate) fn field_bytes(value: Fr) -> [u8; 32] {
    let bytes = value.into_bigint().to_bytes_be();
    let mut encoded = [0_u8; 32];
    encoded[32 - bytes.len()..].copy_from_slice(&bytes);
    encoded
}

pub(crate) fn parse_field(encoded: &[u8; 32]) -> Option<Fr> {
    let value = Fr::from_be_bytes_mod_order(encoded);
    (field_bytes(value) == *encoded).then_some(value)
}
