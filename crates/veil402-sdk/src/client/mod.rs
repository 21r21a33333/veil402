use std::{path::PathBuf, sync::Arc, time::Duration};

use tokio::sync::Mutex;

use crate::{
    protocol::{Output, Public, PublicInputs, Spend, Transaction},
    proving::{Artifacts, Witness, Worker},
    solana::{Pool, Prepared, Withdrawal},
};
use solana_pubkey::Pubkey;

mod error;

pub use error::Error;

/// Paths and limits needed by the local prover.
#[derive(Clone, Debug)]
pub struct Config {
    worker: PathBuf,
    artifacts: PathBuf,
    timeout: Duration,
}

impl Config {
    /// Creates a configuration for a worker executable and artifact bundle.
    pub fn new(worker: impl Into<PathBuf>, artifacts: impl Into<PathBuf>) -> Self {
        Self {
            worker: worker.into(),
            artifacts: artifacts.into(),
            timeout: Duration::from_secs(120),
        }
    }

    /// Sets the deadline for one proof request.
    #[must_use]
    pub const fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
}

/// A locally generated and verified transaction proof.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Proof {
    /// Raw Groth16 proof bytes accepted by the on-chain verifier.
    pub bytes: Vec<u8>,
    /// Public inputs bound by the proof.
    pub public: PublicInputs,
    /// Versioned artifact identity used for proving.
    pub artifact: String,
}

/// Entry point for client-side Veil operations.
pub struct Veil {
    artifacts: Arc<Artifacts>,
    directory: PathBuf,
    executable: PathBuf,
    timeout: Duration,
    worker: Mutex<Option<Worker>>,
}

impl Veil {
    /// Opens and validates the configured proving artifacts.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Artifacts`] when the artifact bundle is unavailable, corrupt, or was
    /// produced by a different Noir version.
    pub fn open(config: Config) -> Result<Self, Error> {
        let artifacts = Artifacts::open(&config.artifacts)?;
        Ok(Self {
            artifacts: Arc::new(artifacts),
            directory: config.artifacts,
            executable: config.worker,
            timeout: config.timeout,
            worker: Mutex::new(None),
        })
    }

    /// Generates and locally verifies a proof for a transaction.
    ///
    /// # Errors
    ///
    /// Returns an [`Error`] when validation, witness generation, worker communication, proving,
    /// local verification, or the configured deadline fails.
    pub async fn prove(&self, transaction: Transaction) -> Result<Proof, Error> {
        let artifacts = Arc::clone(&self.artifacts);
        let witness = tokio::task::spawn_blocking(move || Witness::build(&artifacts, &transaction))
            .await
            .map_err(|_| Error::Witness)??;

        let mut slot = self.worker.lock().await;
        let mut worker = match slot.take() {
            Some(worker) => worker,
            None => {
                Worker::start(
                    &self.executable,
                    &self.directory,
                    &self.artifacts.manifest.id,
                    self.timeout,
                )
                .await?
            }
        };
        let (bytes, public) = worker.prove(&witness, self.timeout).await?;
        if public != witness.public.witness_bytes() {
            return Err(Error::Prover("public witness does not match transaction"));
        }
        *slot = Some(worker);

        Ok(Proof {
            bytes,
            public: witness.public.clone(),
            artifact: self.artifacts.manifest.id.clone(),
        })
    }

    /// Proves a withdrawal and builds the exact Solana instruction that consumes it.
    ///
    /// Account creation and transaction submission remain the caller's responsibility.
    ///
    /// # Errors
    ///
    /// Returns an [`Error`] when the withdrawal is invalid, proof generation fails, or the
    /// resulting instruction cannot be encoded.
    pub async fn withdraw(
        &self,
        pool: &Pool,
        input: Spend,
        send: Output,
        withdrawal: Withdrawal,
        payer: Pubkey,
    ) -> Result<Prepared, Error> {
        let public = Public {
            amount: withdrawal.public_amount(),
            hash: pool.bind(&withdrawal)?,
        };
        let proof = self
            .prove(Transaction {
                input,
                send,
                public,
            })
            .await?;
        let instruction = pool.instruction(&proof, &withdrawal, payer)?;
        Ok(Prepared { proof, instruction })
    }
}
