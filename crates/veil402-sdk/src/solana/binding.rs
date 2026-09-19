use ark_bn254::Fr;
use ark_ff::PrimeField;
use solana_keccak_hasher::hashv;
use solana_pubkey::Pubkey;

use super::{DOMAIN, Pool, Withdrawal};
use crate::{Error, Field, protocol::note};

pub(super) fn asset(mint: &Pubkey) -> Result<Field, Error> {
    let bytes = mint.to_bytes();
    let mut high = [0_u8; 32];
    let mut low = [0_u8; 32];
    high[16..].copy_from_slice(&bytes[..16]);
    low[16..].copy_from_slice(&bytes[16..]);
    note::poseidon(&[&Field::from_bytes(high)?, &Field::from_bytes(low)?])
}

pub(super) fn withdrawal(pool: &Pool, withdrawal: &Withdrawal) -> Result<Field, Error> {
    let amount = withdrawal.public_amount().to_be_bytes();
    let length = u32::try_from(withdrawal.encrypted_note.len())
        .map_err(|_| Error::Withdrawal("encrypted note length is not representable"))?
        .to_be_bytes();
    let digest = hashv(&[
        DOMAIN,
        &pool.domain,
        pool.program.as_ref(),
        pool.address.as_ref(),
        pool.mint.as_ref(),
        withdrawal.recipient.as_ref(),
        &amount,
        &length,
        &withdrawal.encrypted_note,
    ]);
    Ok(Field::from_fr(Fr::from_be_bytes_mod_order(digest.as_ref())))
}
