use anchor_lang::prelude::*;
use anchor_lang::solana_program::{instruction::Instruction, program::invoke};
use anchor_spl::associated_token::AssociatedToken;
use anchor_spl::token::{self, Mint, Token, TokenAccount, Transfer};

mod state;
mod util;
use state::*;

declare_id!("D5JudnUPhvtNhVX7g6zYY8E4XcQBhLHgosAGB6mnhqrK");

const BINDING_DOMAIN: &[u8] = b"veil402:transact:v1";

// Veil402 shielded pool. Notes are hidden UTXOs whose commitments live in an audited Poseidon
// Merkle tree (Light Protocol's light-concurrent-merkle-tree, reused as-is). Spending reveals a
// nullifier + a Groth16 proof verified by CPI into the Sunspot verifier.

/// Public withdrawal data bound into the proof.
#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct ExtData {
    pub recipient: Pubkey,
    pub encrypted_note: Vec<u8>,
}

impl ExtData {
    fn hash(
        &self,
        domain: &[u8; 32],
        pool: &Pubkey,
        mint: &Pubkey,
        ext_amount: i64,
    ) -> Result<[u8; 32]> {
        let amount = ext_amount.to_be_bytes();
        let length = u32::try_from(self.encrypted_note.len())
            .map_err(|_| error!(PoolError::NoteTooLarge))?
            .to_be_bytes();
        Ok(util::keccak_field(&[
            BINDING_DOMAIN,
            domain,
            crate::ID.as_ref(),
            pool.as_ref(),
            mint.as_ref(),
            self.recipient.as_ref(),
            &amount,
            &length,
            &self.encrypted_note,
        ]))
    }
}

fn asset_id_of(mint: &Pubkey) -> Result<[u8; 32]> {
    let (hi, lo) = util::split32(&mint.to_bytes());
    util::poseidon(&[&hi, &lo])
}

/// Public witness assembled from checked values: 12-byte gnark header (5 inputs), then
/// root, nullifier, out_commitment, public_amount, ext_data_hash.
fn public_witness(
    root: &[u8; 32],
    nullifier: &[u8; 32],
    out_commitment: &[u8; 32],
    public_amount: &[u8; 32],
    edh: &[u8; 32],
) -> [u8; 172] {
    let mut pw = [0u8; 172];
    pw[0..12].copy_from_slice(&[0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 5]);
    pw[12..44].copy_from_slice(root);
    pw[44..76].copy_from_slice(nullifier);
    pw[76..108].copy_from_slice(out_commitment);
    pw[108..140].copy_from_slice(public_amount);
    pw[140..172].copy_from_slice(edh);
    pw
}

fn verify_cpi(verifier: &AccountInfo, proof: &[u8], pw: &[u8]) -> Result<()> {
    let mut data = Vec::with_capacity(proof.len() + pw.len());
    data.extend_from_slice(proof);
    data.extend_from_slice(pw);
    invoke(
        &Instruction {
            program_id: *verifier.key,
            accounts: vec![],
            data,
        },
        std::slice::from_ref(verifier),
    )
    .map_err(|_| error!(PoolError::InvalidProof))
}

#[program]
pub mod pool {
    use super::*;

    pub fn init_pool(ctx: Context<InitPool>, domain: [u8; 32]) -> Result<()> {
        let pool = &mut ctx.accounts.pool;
        pool.authority = ctx.accounts.authority.key();
        pool.verifier = ctx.accounts.verifier_program.key();
        pool.mint = ctx.accounts.mint.key();
        pool.asset_id = asset_id_of(&ctx.accounts.mint.key())?;
        pool.domain = domain;
        pool.bump = ctx.bumps.pool;

        state::init_tree(&ctx.accounts.tree.to_account_info())
    }

    pub fn shield(
        ctx: Context<Shield>,
        npk: [u8; 32],
        amount: u64,
        encrypted_note: Vec<u8>,
    ) -> Result<()> {
        require!(amount > 0, PoolError::ZeroAmount);
        require!(util::is_canonical_field(&npk), PoolError::InvalidField);
        require!(
            encrypted_note.len() <= MAX_ENCRYPTED_NOTE_LEN,
            PoolError::NoteTooLarge
        );

        token::transfer(
            CpiContext::new(
                ctx.accounts.token_program.to_account_info(),
                Transfer {
                    from: ctx.accounts.depositor_ata.to_account_info(),
                    to: ctx.accounts.vault.to_account_info(),
                    authority: ctx.accounts.depositor.to_account_info(),
                },
            ),
            amount,
        )?;

        let commitment =
            util::poseidon(&[&npk, &ctx.accounts.pool.asset_id, &util::u64_be32(amount)])?;
        let leaf_index = state::append_leaf(&ctx.accounts.tree.to_account_info(), &commitment)?;
        emit!(NewCommitment {
            commitment,
            leaf_index,
            encrypted_note
        });
        Ok(())
    }

    pub fn transact(
        ctx: Context<Transact>,
        proof: Vec<u8>,
        root: [u8; 32],
        nullifier: [u8; 32],
        out_commitment: [u8; 32],
        ext_amount: i64,
        ext_data: ExtData,
    ) -> Result<()> {
        // 0. Validate the public leg. Deposits go through `shield`, so transact only spends
        //    (ext_amount <= 0). Cap the note ciphertext.
        require!(ext_amount <= 0, PoolError::ExtAmountMustBeNonPositive);
        require!(proof.len() == PROOF_BYTES, PoolError::InvalidProofLength);
        require!(
            util::is_canonical_field(&root)
                && util::is_canonical_field(&nullifier)
                && util::is_canonical_field(&out_commitment),
            PoolError::InvalidField
        );
        require!(nullifier != [0; 32], PoolError::ZeroNullifier);
        require!(
            ext_data.encrypted_note.len() <= MAX_ENCRYPTED_NOTE_LEN,
            PoolError::NoteTooLarge
        );
        if ext_amount < 0 {
            require_keys_neq!(
                ctx.accounts.recipient_ata.key(),
                ctx.accounts.vault.key(),
                PoolError::SelfTransfer
            );
        }

        // 1. Known root (from the tree's history) + correct verifier.
        require!(
            state::is_known_root(&ctx.accounts.tree.to_account_info(), &root)?,
            PoolError::UnknownRoot
        );
        require_keys_eq!(
            ctx.accounts.verifier_program.key(),
            ctx.accounts.pool.verifier,
            PoolError::WrongVerifier
        );

        // 2. Recompute bound values and verify the proof against them.
        let public_amount = util::public_amount_field(i128::from(ext_amount));
        let edh = ext_data.hash(
            &ctx.accounts.pool.domain,
            &ctx.accounts.pool.key(),
            &ctx.accounts.pool.mint,
            ext_amount,
        )?;
        let pw = public_witness(&root, &nullifier, &out_commitment, &public_amount, &edh);
        verify_cpi(&ctx.accounts.verifier_program, &proof, &pw)?;

        // 3. Spend the nullifier (PDA `init` = double-spend guard).
        ctx.accounts.nullifier_record.nullifier = nullifier;

        // 4. Pay out on withdrawal (vault PDA signs); recipient is bound in ext_data_hash.
        if ext_amount < 0 {
            let w = ext_amount.unsigned_abs();
            require!(ctx.accounts.vault.amount >= w, PoolError::InsufficientVault);
            require_keys_eq!(
                ctx.accounts.recipient_ata.owner,
                ext_data.recipient,
                PoolError::RecipientMismatch
            );
            let bump = ctx.accounts.pool.bump;
            let seeds: &[&[u8]] = &[b"pool", core::slice::from_ref(&bump)];
            token::transfer(
                CpiContext::new_with_signer(
                    ctx.accounts.token_program.to_account_info(),
                    Transfer {
                        from: ctx.accounts.vault.to_account_info(),
                        to: ctx.accounts.recipient_ata.to_account_info(),
                        authority: ctx.accounts.pool.to_account_info(),
                    },
                    &[seeds],
                ),
                w,
            )?;
        }

        // 5. Append the output commitment + emit.
        let leaf_index = state::append_leaf(&ctx.accounts.tree.to_account_info(), &out_commitment)?;
        emit!(NewCommitment {
            commitment: out_commitment,
            leaf_index,
            encrypted_note: ext_data.encrypted_note
        });
        emit!(NewNullifier { nullifier });
        Ok(())
    }
}

#[derive(Accounts)]
pub struct InitPool<'info> {
    #[account(init, payer = authority, space = 8 + Pool::INIT_SPACE, seeds = [b"pool"], bump)]
    pub pool: Account<'info, Pool>,
    #[account(init, payer = authority, space = 8 + TREE_BYTES, seeds = [b"tree"], bump)]
    pub tree: Account<'info, MerkleTree>,
    pub mint: Account<'info, Mint>,
    #[account(init, payer = authority, associated_token::mint = mint, associated_token::authority = pool)]
    pub vault: Account<'info, TokenAccount>,
    /// CHECK: executable Sunspot verifier program; stored and checked on every transact.
    #[account(executable)]
    pub verifier_program: UncheckedAccount<'info>,
    #[account(mut)]
    pub authority: Signer<'info>,
    pub token_program: Program<'info, Token>,
    pub associated_token_program: Program<'info, AssociatedToken>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Shield<'info> {
    #[account(seeds = [b"pool"], bump = pool.bump)]
    pub pool: Account<'info, Pool>,
    #[account(mut, seeds = [b"tree"], bump)]
    pub tree: Account<'info, MerkleTree>,
    #[account(mut, associated_token::mint = mint, associated_token::authority = pool)]
    pub vault: Account<'info, TokenAccount>,
    #[account(address = pool.mint)]
    pub mint: Account<'info, Mint>,
    #[account(mut)]
    pub depositor: Signer<'info>,
    #[account(mut, token::mint = mint, token::authority = depositor)]
    pub depositor_ata: Account<'info, TokenAccount>,
    pub token_program: Program<'info, Token>,
}

#[derive(Accounts)]
#[instruction(proof: Vec<u8>, root: [u8; 32], nullifier: [u8; 32])]
pub struct Transact<'info> {
    #[account(seeds = [b"pool"], bump = pool.bump)]
    pub pool: Account<'info, Pool>,
    #[account(mut, seeds = [b"tree"], bump)]
    pub tree: Account<'info, MerkleTree>,
    #[account(mut, associated_token::mint = mint, associated_token::authority = pool)]
    pub vault: Account<'info, TokenAccount>,
    #[account(address = pool.mint)]
    pub mint: Account<'info, Mint>,
    #[account(init, payer = payer, space = 8 + NullifierRecord::INIT_SPACE, seeds = [b"nullifier", pool.key().as_ref(), nullifier.as_ref()], bump)]
    pub nullifier_record: Account<'info, NullifierRecord>,
    #[account(mut, token::mint = mint)]
    pub recipient_ata: Account<'info, TokenAccount>,
    /// CHECK: executable and validated against pool.verifier before the CPI.
    #[account(executable)]
    pub verifier_program: UncheckedAccount<'info>,
    #[account(mut)]
    pub payer: Signer<'info>,
    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
}
