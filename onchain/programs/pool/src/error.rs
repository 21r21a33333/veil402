use anchor_lang::prelude::*;

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
    #[msg("initializer is not the program upgrade authority")]
    UnauthorizedInitializer,
}
