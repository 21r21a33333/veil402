use anchor_lang::prelude::*;
use anchor_spl::token::{self, Mint, Token, TokenAccount, TransferChecked};

use crate::{
    tree, utils, MerkleTree, Pool, PoolError, MAX_ENCRYPTED_NOTE_LEN, NOTE_DOMAIN, VERSION_SEED,
};

pub(crate) fn handle(
    ctx: Context<Shield>,
    npk: [u8; 32],
    amount: u64,
    encrypted_note: Vec<u8>,
) -> Result<()> {
    require!(amount > 0, PoolError::ZeroAmount);
    require!(utils::is_canonical_field(&npk), PoolError::InvalidField);
    require!(
        encrypted_note.len() <= MAX_ENCRYPTED_NOTE_LEN,
        PoolError::NoteTooLarge
    );

    token::transfer_checked(
        CpiContext::new(
            ctx.accounts.token_program.to_account_info(),
            TransferChecked {
                from: ctx.accounts.depositor_ata.to_account_info(),
                mint: ctx.accounts.mint.to_account_info(),
                to: ctx.accounts.vault.to_account_info(),
                authority: ctx.accounts.depositor.to_account_info(),
            },
        ),
        amount,
        ctx.accounts.mint.decimals,
    )?;

    let commitment = utils::poseidon(&[
        &utils::u64_be32(NOTE_DOMAIN),
        &npk,
        &ctx.accounts.pool.asset.id,
        &utils::u64_be32(amount),
    ])?;
    tree::insert(
        &ctx.accounts.tree.to_account_info(),
        commitment,
        encrypted_note,
    )
}

#[derive(Accounts)]
pub struct Shield<'info> {
    #[account(seeds = [b"pool", VERSION_SEED], bump = pool.bump)]
    pub pool: Account<'info, Pool>,
    #[account(mut, seeds = [b"tree", pool.key().as_ref()], bump)]
    pub tree: Account<'info, MerkleTree>,
    #[account(mut, associated_token::mint = mint, associated_token::authority = pool)]
    pub vault: Account<'info, TokenAccount>,
    #[account(address = pool.asset.mint)]
    pub mint: Account<'info, Mint>,
    #[account(mut)]
    pub depositor: Signer<'info>,
    #[account(mut, token::mint = mint, token::authority = depositor)]
    pub depositor_ata: Account<'info, TokenAccount>,
    pub token_program: Program<'info, Token>,
}
