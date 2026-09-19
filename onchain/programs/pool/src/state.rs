use anchor_lang::prelude::*;
use light_concurrent_merkle_tree::zero_copy::{
    ConcurrentMerkleTreeZeroCopy, ConcurrentMerkleTreeZeroCopyMut,
};
use light_hasher::Poseidon;

pub const TREE_HEIGHT: usize = 20; // ~1M leaves
pub const CANOPY: usize = 0;
pub const CHANGELOG_SIZE: usize = 8; // small: keeps the account < the 10KB CPI-init limit
pub const ROOTS_SIZE: usize = 64; // recent-root window
pub const TREE_BYTES: usize = 8224; // = size_in_account(20, 8, 64, 0), verified

pub const MAX_ENCRYPTED_NOTE_LEN: usize = 512; // bounds tx/log bloat; an opening is a few fields + key + MAC

const DISCRIMINATOR: usize = 8; // Anchor account discriminator; Light's tree lives after it

type CmtMut<'a> = ConcurrentMerkleTreeZeroCopyMut<'a, Poseidon, TREE_HEIGHT>;
type Cmt<'a> = ConcurrentMerkleTreeZeroCopy<'a, Poseidon, TREE_HEIGHT>;

/// Initialize Light's concurrent Merkle tree into the tree account (past the discriminator).
pub fn init_tree(account: &AccountInfo) -> Result<()> {
    let mut data = account.try_borrow_mut_data()?;
    let mut t = CmtMut::from_bytes_zero_copy_init(
        &mut data[DISCRIMINATOR..],
        TREE_HEIGHT,
        CANOPY,
        CHANGELOG_SIZE,
        ROOTS_SIZE,
    )
    .map_err(|_| error!(PoolError::TreeError))?;
    t.init().map_err(|_| error!(PoolError::TreeError))?;
    Ok(())
}

/// Append one commitment; returns its leaf index.
pub fn append_leaf(account: &AccountInfo, leaf: &[u8; 32]) -> Result<u64> {
    let mut data = account.try_borrow_mut_data()?;
    let mut t = CmtMut::from_bytes_zero_copy_mut(&mut data[DISCRIMINATOR..])
        .map_err(|_| error!(PoolError::TreeError))?;
    let (leaf_index, _seq) = t.append(leaf).map_err(|_| error!(PoolError::TreeError))?;
    Ok(leaf_index as u64)
}

/// Whether `root` is in the tree's recent-root history (rejects the zero default).
pub fn is_known_root(account: &AccountInfo, root: &[u8; 32]) -> Result<bool> {
    if *root == [0u8; 32] {
        return Ok(false);
    }
    let data = account.try_borrow_data()?;
    let t = Cmt::from_bytes_zero_copy(&data[DISCRIMINATOR..])
        .map_err(|_| error!(PoolError::TreeError))?;
    Ok(t.roots.iter().any(|r| r == root))
}

/// Pool config (small, normal account). The tree lives in a separate account managed by Light.
#[account]
#[derive(InitSpace)]
pub struct Pool {
    pub authority: Pubkey,
    pub verifier: Pubkey,
    pub mint: Pubkey,
    pub asset_id: [u8; 32],
    pub bump: u8,
}

/// Marker for the tree account. Its data (past the discriminator) holds Light's serialized tree.
#[account]
pub struct MerkleTree {}

/// One PDA per spent nullifier; its existence (via `init`) is the double-spend guard.
#[account]
#[derive(InitSpace)]
pub struct NullifierRecord {
    pub nullifier: [u8; 32],
}

#[event]
pub struct NewCommitment {
    pub commitment: [u8; 32],
    pub leaf_index: u64,
    pub encrypted_note: Vec<u8>,
}
#[event]
pub struct NewNullifier {
    pub nullifier: [u8; 32],
}

#[error_code]
pub enum PoolError {
    #[msg("merkle tree operation failed")]
    TreeError,
    #[msg("root is not in the recent-root window")]
    UnknownRoot,
    #[msg("verifier program does not match the configured one")]
    WrongVerifier,
    #[msg("zk proof verification failed")]
    InvalidProof,
    #[msg("insufficient vault balance for withdrawal")]
    InsufficientVault,
    #[msg("recipient account does not match ext_data")]
    RecipientMismatch,
    #[msg("deposits must use shield; transact requires ext_amount <= 0")]
    ExtAmountMustBeNonPositive,
    #[msg("encrypted note exceeds the maximum length")]
    NoteTooLarge,
    #[msg("amount must be greater than zero")]
    ZeroAmount,
}
