use anchor_lang::prelude::*;
use anchor_spl::associated_token::AssociatedToken;
use anchor_spl::token::{Mint, Token, TokenAccount};

use crate::{tree, utils, Asset, MerkleTree, Pool, PoolError, VERSION_SEED};

pub(crate) fn handle(ctx: Context<InitPool>, domain: [u8; 32]) -> Result<()> {
    let pool = &mut ctx.accounts.pool;
    pool.verifier = ctx.accounts.verifier_program.key();
    pool.asset = Asset {
        mint: ctx.accounts.mint.key(),
        id: utils::asset_id(&ctx.accounts.mint.key())?,
    };
    pool.domain = domain;
    pool.bump = ctx.bumps.pool;

    tree::initialize(&ctx.accounts.tree.to_account_info())
}

#[derive(Accounts)]
pub struct InitPool<'info> {
    #[account(init, payer = authority, space = 8 + Pool::INIT_SPACE, seeds = [b"pool", VERSION_SEED], bump)]
    pub pool: Account<'info, Pool>,
    #[account(init, payer = authority, space = tree::account_space(), seeds = [b"tree", pool.key().as_ref()], bump)]
    pub tree: Account<'info, MerkleTree>,
    pub mint: Account<'info, Mint>,
    #[account(init, payer = authority, associated_token::mint = mint, associated_token::authority = pool)]
    pub vault: Account<'info, TokenAccount>,
    /// CHECK: executable Sunspot verifier program; stored and checked on every transact.
    #[account(executable)]
    pub verifier_program: UncheckedAccount<'info>,
    #[account(mut)]
    pub authority: Signer<'info>,
    pub pool_program: Program<'info, crate::program::Pool>,
    #[account(
        constraint = pool_program.programdata_address()? == Some(program_data.key())
            @ PoolError::UnauthorizedInitializer,
        constraint = program_data.upgrade_authority_address == Some(authority.key())
            @ PoolError::UnauthorizedInitializer,
    )]
    pub program_data: Account<'info, ProgramData>,
    pub token_program: Program<'info, Token>,
    pub associated_token_program: Program<'info, AssociatedToken>,
    pub system_program: Program<'info, System>,
}
