use borsh::BorshSerialize;
use sha2::{Digest, Sha256};
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use super::{External, Pool};
use crate::{Error, Field, Proof};

const SYSTEM_PROGRAM: Pubkey = Pubkey::from_str_const("11111111111111111111111111111111");

#[derive(BorshSerialize)]
struct ExtData<'a> {
    recipient: [u8; 32],
    encrypted_notes: [&'a [u8]; 2],
}

#[derive(BorshSerialize)]
struct Args<'a> {
    proof: &'a [u8],
    root: [u8; 32],
    nullifiers: [[u8; 32]; 2],
    out_commitments: [[u8; 32]; 2],
    ext_amount: i64,
    ext_data: ExtData<'a>,
}

pub(super) fn transact(
    pool: &Pool,
    proof: &Proof,
    external: &External,
    amount: i64,
    payer: Pubkey,
) -> Result<Instruction, Error> {
    if proof.public.hash != pool.bind(external, amount)? {
        return Err(Error::Transaction(
            "proof is bound to different public data",
        ));
    }
    if proof.public.amount != Field::from_signed(amount) {
        return Err(Error::Transaction("proof is bound to a different amount"));
    }

    let nullifier_records = proof.public.nullifiers.map(|nullifier| {
        Pubkey::find_program_address(
            &[b"nullifier", pool.address.as_ref(), nullifier.as_bytes()],
            &pool.program,
        )
        .0
    });
    let recipient_ata = if amount < 0 {
        spl_associated_token_account_interface::address::get_associated_token_address_with_program_id(
            &external.recipient,
            &pool.mint,
            &spl_token_interface::id(),
        )
    } else {
        pool.vault
    };

    let args = Args {
        proof: &proof.bytes,
        root: proof.public.root.to_bytes(),
        nullifiers: proof.public.nullifiers.map(Field::to_bytes),
        out_commitments: proof.public.commitments.map(Field::to_bytes),
        ext_amount: amount,
        ext_data: ExtData {
            recipient: external.recipient.to_bytes(),
            encrypted_notes: [&external.encrypted[0], &external.encrypted[1]],
        },
    };
    let mut data = Sha256::digest(b"global:transact")[..8].to_vec();
    data.extend(
        borsh::to_vec(&args).map_err(|_| Error::Transaction("instruction encoding failed"))?,
    );

    Ok(Instruction {
        program_id: pool.program,
        accounts: vec![
            AccountMeta::new_readonly(pool.address, false),
            AccountMeta::new(pool.tree, false),
            AccountMeta::new(pool.vault, false),
            AccountMeta::new_readonly(pool.mint, false),
            AccountMeta::new(nullifier_records[0], false),
            AccountMeta::new(nullifier_records[1], false),
            AccountMeta::new(recipient_ata, false),
            AccountMeta::new_readonly(pool.verifier, false),
            AccountMeta::new(payer, true),
            AccountMeta::new_readonly(spl_token_interface::id(), false),
            AccountMeta::new_readonly(SYSTEM_PROGRAM, false),
        ],
        data,
    })
}
