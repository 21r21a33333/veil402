use ark_bn254::Fr;
use ark_ff::PrimeField;
use solana_keccak_hasher::hashv;
use solana_pubkey::Pubkey;

use super::{DOMAIN, External, Pool};
use crate::{Error, Field, protocol::note};

pub(super) fn asset(mint: &Pubkey) -> Result<Field, Error> {
    let bytes = mint.to_bytes();
    let mut high = [0_u8; 32];
    let mut low = [0_u8; 32];
    high[16..].copy_from_slice(&bytes[..16]);
    low[16..].copy_from_slice(&bytes[16..]);
    note::poseidon(&[
        &note::ASSET_DOMAIN,
        &Field::from_bytes(high)?,
        &Field::from_bytes(low)?,
    ])
}

pub(super) fn external(pool: &Pool, external: &External, amount: i64) -> Result<Field, Error> {
    let amount = amount.to_be_bytes();
    let first_len = u32::try_from(external.encrypted[0].len())
        .map_err(|_| Error::Withdrawal("encrypted note length is not representable"))?
        .to_be_bytes();
    let second_len = u32::try_from(external.encrypted[1].len())
        .map_err(|_| Error::Withdrawal("encrypted note length is not representable"))?
        .to_be_bytes();
    let digest = hashv(&[
        DOMAIN,
        &pool.domain,
        pool.program.as_ref(),
        pool.address.as_ref(),
        pool.mint.as_ref(),
        pool.verifier.as_ref(),
        external.recipient.as_ref(),
        &amount,
        &first_len,
        &external.encrypted[0],
        &second_len,
        &external.encrypted[1],
    ]);
    Ok(Field::from_fr(Fr::from_be_bytes_mod_order(digest.as_ref())))
}
