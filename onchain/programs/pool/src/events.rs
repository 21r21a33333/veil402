use anchor_lang::prelude::*;

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
