use thiserror::Error;

/// Error returned by Veil operations.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// A field encoding was not canonical for BN254.
    #[error("invalid BN254 field encoding")]
    Field,

    /// Poseidon rejected the supplied inputs.
    #[error("Poseidon input is invalid")]
    Poseidon,

    /// The transaction violates a protocol invariant.
    #[error("invalid transaction: {0}")]
    Transaction(&'static str),

    /// A withdrawal or its Solana instruction is invalid.
    #[error("invalid withdrawal: {0}")]
    Withdrawal(&'static str),

    /// The proving artifacts are missing, corrupt, or incompatible.
    #[error("invalid proving artifacts: {0}")]
    Artifacts(&'static str),

    /// Noir rejected the transaction or could not generate its witness.
    #[error("witness generation failed")]
    Witness,

    /// The local prover could not be started or returned an invalid response.
    #[error("local prover failed: {0}")]
    Prover(&'static str),

    /// Proof generation exceeded the configured deadline.
    #[error("proof generation timed out")]
    Timeout,
}
