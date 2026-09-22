use anchor_lang::prelude::*;

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, InitSpace)]
pub struct Asset {
    pub mint: Pubkey,
    pub id: [u8; 32],
}

/// Pool config. The Merkle tree lives in a separate account managed by Light Protocol.
#[account]
#[derive(InitSpace)]
pub struct Pool {
    pub verifier: Pubkey,
    pub asset: Asset,
    pub domain: [u8; 32],
    pub bump: u8,
}

/// Marker for the tree account. Light's serialized tree follows its Anchor discriminator.
#[account]
pub struct MerkleTree {}

/// One PDA per spent nullifier; its existence is the double-spend guard.
#[account]
#[derive(InitSpace)]
pub struct NullifierRecord {
    pub nullifier: [u8; 32],
}
