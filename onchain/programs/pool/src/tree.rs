use anchor_lang::prelude::*;
use light_concurrent_merkle_tree::zero_copy::{
    ConcurrentMerkleTreeZeroCopy, ConcurrentMerkleTreeZeroCopyMut,
};
use light_concurrent_merkle_tree::ConcurrentMerkleTree;
use light_hasher::Poseidon;

use crate::{NewCommitment, PoolError};

const TREE_HEIGHT: usize = 20;
const CANOPY: usize = 0;
const CHANGELOG_SIZE: usize = 8;
const ROOTS_SIZE: usize = 64;
const DISCRIMINATOR: usize = 8;

type Cmt<'a> = ConcurrentMerkleTreeZeroCopy<'a, Poseidon, TREE_HEIGHT>;

pub(crate) fn account_space() -> usize {
    DISCRIMINATOR
        + ConcurrentMerkleTree::<Poseidon, TREE_HEIGHT>::size_in_account(
            TREE_HEIGHT,
            CHANGELOG_SIZE,
            ROOTS_SIZE,
            CANOPY,
        )
}

pub(crate) fn initialize(account: &AccountInfo) -> Result<()> {
    initialize_with_height::<TREE_HEIGHT>(account)
}

fn initialize_with_height<const HEIGHT: usize>(account: &AccountInfo) -> Result<()> {
    let mut data = account.try_borrow_mut_data()?;
    let mut tree = ConcurrentMerkleTreeZeroCopyMut::<Poseidon, HEIGHT>::from_bytes_zero_copy_init(
        &mut data[DISCRIMINATOR..],
        HEIGHT,
        CANOPY,
        CHANGELOG_SIZE,
        ROOTS_SIZE,
    )
    .map_err(|_| error!(PoolError::TreeError))?;
    tree.init().map_err(|_| error!(PoolError::TreeError))?;
    Ok(())
}

pub(crate) fn append(account: &AccountInfo, leaf: &[u8; 32]) -> Result<u64> {
    append_with_height::<TREE_HEIGHT>(account, leaf)
}

fn append_with_height<const HEIGHT: usize>(account: &AccountInfo, leaf: &[u8; 32]) -> Result<u64> {
    let mut data = account.try_borrow_mut_data()?;
    let mut tree = ConcurrentMerkleTreeZeroCopyMut::<Poseidon, HEIGHT>::from_bytes_zero_copy_mut(
        &mut data[DISCRIMINATOR..],
    )
    .map_err(|_| error!(PoolError::TreeError))?;
    let leaf_index = tree.next_index();
    tree.append(leaf)
        .map_err(|_| error!(PoolError::TreeError))?;
    u64::try_from(leaf_index).map_err(|_| error!(PoolError::TreeError))
}

pub(crate) fn insert(
    account: &AccountInfo,
    commitment: [u8; 32],
    encrypted_note: Vec<u8>,
) -> Result<()> {
    let leaf_index = append(account, &commitment)?;
    emit!(NewCommitment {
        commitment,
        leaf_index,
        encrypted_note,
    });
    Ok(())
}

pub(crate) fn contains_root(account: &AccountInfo, root: &[u8; 32]) -> Result<bool> {
    if *root == [0u8; 32] {
        return Ok(false);
    }
    let data = account.try_borrow_data()?;
    let tree = Cmt::from_bytes_zero_copy(&data[DISCRIMINATOR..])
        .map_err(|_| error!(PoolError::TreeError))?;
    Ok(tree.roots.iter().any(|known_root| known_root == root))
}

#[cfg(test)]
mod tests {
    use anchor_lang::error::Error;

    use super::*;

    #[test]
    fn final_leaf_succeeds_and_tree_exhaustion_never_wraps() -> Result<()> {
        const HEIGHT: usize = 2;
        let key = Pubkey::new_unique();
        let owner = crate::ID;
        let mut lamports = 0;
        let tree_bytes = ConcurrentMerkleTree::<Poseidon, HEIGHT>::size_in_account(
            HEIGHT,
            CHANGELOG_SIZE,
            ROOTS_SIZE,
            CANOPY,
        );
        let mut data = vec![0; DISCRIMINATOR + tree_bytes];
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
        initialize_with_height::<HEIGHT>(&account)?;

        for (index, leaf) in [[1; 32], [2; 32], [3; 32], [4; 32]].iter().enumerate() {
            assert_eq!(
                append_with_height::<HEIGHT>(&account, leaf)?,
                u64::try_from(index).map_err(|_| error!(PoolError::TreeError))?
            );
        }
        let error = match append_with_height::<HEIGHT>(&account, &[5; 32]) {
            Ok(_) => return Err(error!(PoolError::TreeError)),
            Err(error) => error,
        };
        match error {
            Error::AnchorError(error) => assert_eq!(error.error_name, "TreeError"),
            error => return Err(error),
        }

        let data = account.try_borrow_data()?;
        let tree = ConcurrentMerkleTreeZeroCopy::<Poseidon, HEIGHT>::from_bytes_zero_copy(
            &data[DISCRIMINATOR..],
        )
        .map_err(|_| error!(PoolError::TreeError))?;
        assert_eq!(tree.next_index(), 1 << HEIGHT);
        Ok(())
    }
}
