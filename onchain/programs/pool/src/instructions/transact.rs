use anchor_lang::prelude::*;
use anchor_spl::token::{self, Mint, Token, TokenAccount, TransferChecked};

use crate::{
    tree, utils, verifier, MerkleTree, NewNullifier, NullifierRecord, Pool, PoolError,
    BINDING_DOMAIN, MAX_ENCRYPTED_NOTE_LEN, PROOF_BYTES, VERSION_SEED,
};

/// Public transaction data bound into the proof.
#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct ExtData {
    pub recipient: Pubkey,
    pub encrypted_notes: [Vec<u8>; 2],
}

impl ExtData {
    fn hash(
        &self,
        domain: &[u8; 32],
        pool: &Pubkey,
        mint: &Pubkey,
        verifier: &Pubkey,
        ext_amount: i64,
    ) -> Result<[u8; 32]> {
        let amount = ext_amount.to_be_bytes();
        let first_len = u32::try_from(self.encrypted_notes[0].len())
            .map_err(|_| error!(PoolError::NoteTooLarge))?
            .to_be_bytes();
        let second_len = u32::try_from(self.encrypted_notes[1].len())
            .map_err(|_| error!(PoolError::NoteTooLarge))?
            .to_be_bytes();
        Ok(utils::keccak_field(&[
            BINDING_DOMAIN,
            domain,
            crate::ID.as_ref(),
            pool.as_ref(),
            mint.as_ref(),
            verifier.as_ref(),
            self.recipient.as_ref(),
            &amount,
            &first_len,
            &self.encrypted_notes[0],
            &second_len,
            &self.encrypted_notes[1],
        ]))
    }
}

pub(crate) fn handle(
    ctx: Context<Transact>,
    proof: Vec<u8>,
    root: [u8; 32],
    nullifiers: [[u8; 32]; 2],
    out_commitments: [[u8; 32]; 2],
    ext_amount: i64,
    ext_data: ExtData,
) -> Result<()> {
    // Deposits use `shield`; transact only spends private value or transfers it privately.
    require!(ext_amount <= 0, PoolError::ExtAmountMustBeNonPositive);
    require!(proof.len() == PROOF_BYTES, PoolError::InvalidProofLength);
    require!(
        utils::is_canonical_field(&root)
            && nullifiers.iter().all(utils::is_canonical_field)
            && out_commitments.iter().all(utils::is_canonical_field),
        PoolError::InvalidField
    );
    require!(
        nullifiers.iter().all(|nullifier| *nullifier != [0; 32]),
        PoolError::ZeroNullifier
    );
    require!(
        nullifiers[0] != nullifiers[1],
        PoolError::DuplicateNullifier
    );
    require!(
        ext_data
            .encrypted_notes
            .iter()
            .all(|note| note.len() <= MAX_ENCRYPTED_NOTE_LEN),
        PoolError::NoteTooLarge
    );
    if ext_amount < 0 {
        require_keys_neq!(
            ctx.accounts.recipient_ata.key(),
            ctx.accounts.vault.key(),
            PoolError::SelfTransfer
        );
    }

    require!(
        tree::contains_root(&ctx.accounts.tree.to_account_info(), &root)?,
        PoolError::UnknownRoot
    );
    let public_amount = utils::public_amount_field(i128::from(ext_amount));
    let external_data_hash = ext_data.hash(
        &ctx.accounts.pool.domain,
        &ctx.accounts.pool.key(),
        &ctx.accounts.pool.asset.mint,
        &ctx.accounts.pool.verifier,
        ext_amount,
    )?;
    let public_inputs = verifier::PublicInputs::new(
        root,
        nullifiers,
        out_commitments,
        public_amount,
        external_data_hash,
    );
    public_inputs.verify(&ctx.accounts.verifier_program, &proof)?;

    // Initializing one PDA per nullifier makes the double-spend check atomic with the transaction.
    ctx.accounts.nullifier_0_record.nullifier = nullifiers[0];
    ctx.accounts.nullifier_1_record.nullifier = nullifiers[1];

    if ext_amount < 0 {
        let withdrawal_amount = ext_amount.unsigned_abs();
        require!(
            ctx.accounts.vault.amount >= withdrawal_amount,
            PoolError::InsufficientVault
        );
        require_keys_eq!(
            ctx.accounts.recipient_ata.owner,
            ext_data.recipient,
            PoolError::RecipientMismatch
        );
        let bump = ctx.accounts.pool.bump;
        let seeds: &[&[u8]] = &[b"pool", VERSION_SEED, core::slice::from_ref(&bump)];
        token::transfer_checked(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                TransferChecked {
                    from: ctx.accounts.vault.to_account_info(),
                    mint: ctx.accounts.mint.to_account_info(),
                    to: ctx.accounts.recipient_ata.to_account_info(),
                    authority: ctx.accounts.pool.to_account_info(),
                },
                &[seeds],
            ),
            withdrawal_amount,
            ctx.accounts.mint.decimals,
        )?;
    }

    for (commitment, encrypted_note) in out_commitments.into_iter().zip(ext_data.encrypted_notes) {
        tree::insert(
            &ctx.accounts.tree.to_account_info(),
            commitment,
            encrypted_note,
        )?;
    }
    emit!(NewNullifier {
        nullifier: nullifiers[0]
    });
    emit!(NewNullifier {
        nullifier: nullifiers[1]
    });
    Ok(())
}

#[derive(Accounts)]
#[instruction(proof: Vec<u8>, root: [u8; 32], nullifiers: [[u8; 32]; 2])]
pub struct Transact<'info> {
    #[account(seeds = [b"pool", VERSION_SEED], bump = pool.bump)]
    pub pool: Account<'info, Pool>,
    #[account(mut, seeds = [b"tree", pool.key().as_ref()], bump)]
    pub tree: Account<'info, MerkleTree>,
    #[account(mut, associated_token::mint = mint, associated_token::authority = pool)]
    pub vault: Account<'info, TokenAccount>,
    #[account(address = pool.asset.mint)]
    pub mint: Account<'info, Mint>,
    #[account(init, payer = payer, space = 8 + NullifierRecord::INIT_SPACE, seeds = [b"nullifier", pool.key().as_ref(), nullifiers[0].as_ref()], bump)]
    pub nullifier_0_record: Account<'info, NullifierRecord>,
    #[account(init, payer = payer, space = 8 + NullifierRecord::INIT_SPACE, seeds = [b"nullifier", pool.key().as_ref(), nullifiers[1].as_ref()], bump)]
    pub nullifier_1_record: Account<'info, NullifierRecord>,
    #[account(mut, token::mint = mint)]
    pub recipient_ata: Account<'info, TokenAccount>,
    /// CHECK: executable and constrained to the verifier configured by the trusted initializer.
    #[account(address = pool.verifier @ PoolError::WrongVerifier, executable)]
    pub verifier_program: UncheckedAccount<'info>,
    #[account(mut)]
    pub payer: Signer<'info>,
    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
}
