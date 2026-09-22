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

pub const MAX_ENCRYPTED_NOTE_LEN: usize = 128;
pub const PROOF_BYTES: usize = 388;

const DISCRIMINATOR: usize = 8; // Anchor account discriminator; Light's tree lives after it

type CmtMut<'a> = ConcurrentMerkleTreeZeroCopyMut<'a, Poseidon, TREE_HEIGHT>;
type Cmt<'a> = ConcurrentMerkleTreeZeroCopy<'a, Poseidon, TREE_HEIGHT>;

/// Initialize Light's concurrent Merkle tree into the tree account (past the discriminator).
pub fn init_tree(account: &AccountInfo) -> Result<()> {
    let mut data = account.try_borrow_mut_data()?;
    let mut tree = CmtMut::from_bytes_zero_copy_init(
        &mut data[DISCRIMINATOR..],
        TREE_HEIGHT,
        CANOPY,
        CHANGELOG_SIZE,
        ROOTS_SIZE,
    )
    .map_err(|_| error!(PoolError::TreeError))?;
    tree.init().map_err(|_| error!(PoolError::TreeError))?;
    Ok(())
}

/// Append one commitment; returns its leaf index.
pub fn append_leaf(account: &AccountInfo, leaf: &[u8; 32]) -> Result<u64> {
    let mut data = account.try_borrow_mut_data()?;
    let mut tree = CmtMut::from_bytes_zero_copy_mut(&mut data[DISCRIMINATOR..])
        .map_err(|_| error!(PoolError::TreeError))?;
    let leaf_index = tree.next_index();
    tree.append(leaf)
        .map_err(|_| error!(PoolError::TreeError))?;
    Ok(leaf_index as u64)
}

/// Whether `root` is in the tree's recent-root history (rejects the zero default).
pub fn is_known_root(account: &AccountInfo, root: &[u8; 32]) -> Result<bool> {
    if *root == [0u8; 32] {
        return Ok(false);
    }
    let data = account.try_borrow_data()?;
    let tree = Cmt::from_bytes_zero_copy(&data[DISCRIMINATOR..])
        .map_err(|_| error!(PoolError::TreeError))?;
    Ok(tree.roots.iter().any(|known_root| known_root == root))
}

/// Pool config (small, normal account). The tree lives in a separate account managed by Light.
#[account]
#[derive(InitSpace)]
pub struct Pool {
    pub authority: Pubkey,
    pub verifier: Pubkey,
    pub mint: Pubkey,
    pub asset_id: [u8; 32],
    pub domain: [u8; 32],
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
    #[msg("proof has an invalid length")]
    InvalidProofLength,
    #[msg("field element is not canonically encoded")]
    InvalidField,
    #[msg("nullifier must not be zero")]
    ZeroNullifier,
    #[msg("input nullifiers must be distinct")]
    DuplicateNullifier,
    #[msg("withdrawal recipient must not be the pool vault")]
    SelfTransfer,
}

#[cfg(test)]
mod tests {
    use core::mem::size_of;

    use anchor_lang::{error::Error, prelude::AccountInfo};

    use super::*;

    #[test]
    fn final_leaf_succeeds_and_tree_exhaustion_never_wraps() -> Result<()> {
        let key = Pubkey::new_unique();
        let owner = crate::ID;
        let mut lamports = 0;
        let mut data = vec![0; DISCRIMINATOR + TREE_BYTES];
        let account = AccountInfo::new(
            &key,
            false,
            true,
            &mut lamports,
            &mut data,
            &owner,
            false,
            0,
        );
        init_tree(&account)?;

        // Light's zero-copy header is repr(C): height, canopy depth, then the
        // next leaf index. Move the fixture directly to the final valid slot;
        // iterating through 2^20 leaves would test time, not boundary behavior.
        let next_index_offset = DISCRIMINATOR + 2 * size_of::<usize>();
        let final_index = (1_usize << TREE_HEIGHT) - 1;
        account.try_borrow_mut_data()?[next_index_offset..next_index_offset + size_of::<usize>()]
            .copy_from_slice(&final_index.to_le_bytes());

        assert_eq!(append_leaf(&account, &[1; 32])?, final_index as u64);
        let error = match append_leaf(&account, &[2; 32]) {
            Ok(_) => return Err(error!(PoolError::TreeError)),
            Err(error) => error,
        };
        match error {
            Error::AnchorError(error) => assert_eq!(error.error_name, "TreeError"),
            error => return Err(error),
        }

        let data = account.try_borrow_data()?;
        let tree = Cmt::from_bytes_zero_copy(&data[DISCRIMINATOR..])
            .map_err(|_| error!(PoolError::TreeError))?;
        assert_eq!(tree.next_index(), 1 << TREE_HEIGHT);
        Ok(())
    }
}
