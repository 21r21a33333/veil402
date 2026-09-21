use borsh::BorshSerialize;
use sha2::{Digest, Sha256};
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use super::{Pool, Withdrawal};
use crate::{Error, Proof};

const SYSTEM_PROGRAM: Pubkey = Pubkey::from_str_const("11111111111111111111111111111111");

#[derive(BorshSerialize)]
struct ExtData<'a> {
    recipient: [u8; 32],
    encrypted_note: &'a [u8],
}

#[derive(BorshSerialize)]
struct Args<'a> {
    proof: &'a [u8],
    root: [u8; 32],
    nullifier: [u8; 32],
    out_commitment: [u8; 32],
    ext_amount: i64,
    ext_data: ExtData<'a>,
}

pub(super) fn withdraw(
    pool: &Pool,
    proof: &Proof,
    withdrawal: &Withdrawal,
    payer: Pubkey,
) -> Result<Instruction, Error> {
    if proof.public.hash != pool.bind(withdrawal)? {
        return Err(Error::Withdrawal("proof is bound to different public data"));
    }
    if proof.public.amount != crate::Field::from_signed(withdrawal.public_amount()) {
        return Err(Error::Withdrawal("proof is bound to a different amount"));
    }

    let (nullifier_record, _) = Pubkey::find_program_address(
        &[
            b"nullifier",
            pool.address.as_ref(),
            proof.public.nullifier.as_bytes(),
        ],
        &pool.program,
    );
    let recipient_ata = spl_associated_token_account_interface::address::get_associated_token_address_with_program_id(
        &withdrawal.recipient,
        &pool.mint,
        &spl_token_interface::id(),
    );

    let args = Args {
        proof: &proof.bytes,
        root: proof.public.root.to_bytes(),
        nullifier: proof.public.nullifier.to_bytes(),
        out_commitment: proof.public.commitment.to_bytes(),
        ext_amount: withdrawal.public_amount(),
        ext_data: ExtData {
            recipient: withdrawal.recipient.to_bytes(),
            encrypted_note: &withdrawal.encrypted_note,
        },
    };
    let mut data = Sha256::digest(b"global:transact")[..8].to_vec();
    data.extend(
        borsh::to_vec(&args).map_err(|_| Error::Withdrawal("instruction encoding failed"))?,
    );

    Ok(Instruction {
        program_id: pool.program,
        accounts: vec![
            AccountMeta::new_readonly(pool.address, false),
            AccountMeta::new(pool.tree, false),
            AccountMeta::new(pool.vault, false),
            AccountMeta::new_readonly(pool.mint, false),
            AccountMeta::new(nullifier_record, false),
            AccountMeta::new(recipient_ata, false),
            AccountMeta::new_readonly(pool.verifier, false),
            AccountMeta::new(payer, true),
            AccountMeta::new_readonly(spl_token_interface::id(), false),
            AccountMeta::new_readonly(SYSTEM_PROGRAM, false),
        ],
        data,
    })
}
