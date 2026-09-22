use anchor_lang::prelude::*;
mod error;
mod events;
mod instructions;
mod state;
mod tree;
mod utils;
mod verifier;

pub use error::PoolError;
pub use events::{NewCommitment, NewNullifier};
pub use instructions::*;
pub use state::{Asset, MerkleTree, NullifierRecord, Pool};

declare_id!("D5JudnUPhvtNhVX7g6zYY8E4XcQBhLHgosAGB6mnhqrK");

pub(crate) const BINDING_DOMAIN: &[u8] = b"veil402:transact:v4";
pub(crate) const VERSION_SEED: &[u8] = b"v4";
pub(crate) const NOTE_DOMAIN: u64 = 5;
pub(crate) const ASSET_DOMAIN: u64 = 7;
pub(crate) const MAX_ENCRYPTED_NOTE_LEN: usize = 128;
pub(crate) const PROOF_BYTES: usize = 388;

// Veil402 shielded pool. Notes are hidden UTXOs whose commitments live in an audited Poseidon
// Merkle tree (Light Protocol's light-concurrent-merkle-tree, reused as-is). Spending reveals a
// nullifier + a Groth16 proof verified by CPI into the Sunspot verifier.

#[program]
pub mod pool {
    use super::*;

    pub fn init_pool(ctx: Context<InitPool>, domain: [u8; 32]) -> Result<()> {
        instructions::initialize::handle(ctx, domain)
    }

    pub fn shield(
        ctx: Context<Shield>,
        npk: [u8; 32],
        amount: u64,
        encrypted_note: Vec<u8>,
    ) -> Result<()> {
        instructions::shield::handle(ctx, npk, amount, encrypted_note)
    }

    pub fn transact(
        ctx: Context<Transact>,
        proof: Vec<u8>,
        root: [u8; 32],
        nullifiers: [[u8; 32]; 2],
        out_commitments: [[u8; 32]; 2],
        ext_amount: i64,
        ext_data: ExtData,
    ) -> Result<()> {
        instructions::transact::handle(
            ctx,
            proof,
            root,
            nullifiers,
            out_commitments,
            ext_amount,
            ext_data,
        )
    }
}
