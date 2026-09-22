use std::{path::PathBuf, sync::Arc, time::Duration};

use tokio::sync::Mutex;

use crate::{
    protocol::{Plan, Public, PublicInputs, Transaction},
    proving::{Artifacts, Witness, Worker},
    solana::{External, Pool, Prepared, Withdrawal},
};
use solana_pubkey::Pubkey;

mod error;

pub use error::Error;

/// Paths and limits needed by the local prover.
#[derive(Clone, Debug)]
pub struct Config {
    worker_executable: PathBuf,
    artifact_directory: PathBuf,
    timeout: Duration,
}

impl Config {
    /// Creates a configuration for a worker executable and artifact bundle.
    pub fn new(worker: impl Into<PathBuf>, artifacts: impl Into<PathBuf>) -> Self {
        Self {
            worker_executable: worker.into(),
            artifact_directory: artifacts.into(),
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
    artifact_directory: PathBuf,
    worker_executable: PathBuf,
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
        let artifacts = Artifacts::open(&config.artifact_directory)?;
        Ok(Self {
            artifacts: Arc::new(artifacts),
            artifact_directory: config.artifact_directory,
            worker_executable: config.worker_executable,
            timeout: config.timeout,
            worker: Mutex::new(None),
        })
    }

    async fn prove(&self, transaction: Plan, public: Public) -> Result<Proof, Error> {
        let artifacts = Arc::clone(&self.artifacts);
        let witness =
            tokio::task::spawn_blocking(move || Witness::build(&artifacts, &transaction, &public))
                .await
                .map_err(|_| Error::Witness)??;

        let mut slot = self.worker.lock().await;
        let mut worker = match slot.take() {
            Some(worker) => worker,
            None => {
                Worker::start(
                    &self.worker_executable,
                    &self.artifact_directory,
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

    /// Proves a private transfer and builds the exact Solana instruction that consumes it.
    ///
    /// Account creation and transaction submission remain the caller's responsibility.
    ///
    /// # Errors
    ///
    /// Returns an [`Error`] when the transaction is invalid, proof generation fails, or the
    /// resulting instruction cannot be encoded.
    pub async fn transfer(
        &self,
        pool: &Pool,
        transaction: Transaction,
        payer: Pubkey,
    ) -> Result<Prepared, Error> {
        self.prepare(pool, transaction, pool.address(), 0, payer)
            .await
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
        transaction: Transaction,
        withdrawal: Withdrawal,
        payer: Pubkey,
    ) -> Result<Prepared, Error> {
        if withdrawal.recipient() == pool.address() {
            return Err(Error::Withdrawal("recipient resolves to the pool vault"));
        }
        self.prepare(
            pool,
            transaction,
            withdrawal.recipient(),
            withdrawal.public_amount(),
            payer,
        )
        .await
    }

    async fn prepare(
        &self,
        pool: &Pool,
        transaction: Transaction,
        recipient: Pubkey,
        amount: i64,
        payer: Pubkey,
    ) -> Result<Prepared, Error> {
        let plan = transaction.plan(pool.asset())?;
        let external = External::new(&plan, recipient)?;
        let public = Public {
            amount,
            hash: pool.bind(&external, amount)?,
        };
        let proof = self.prove(plan, public).await?;
        let instruction = pool.instruction(&proof, &external, amount, payer)?;
        Ok(Prepared { proof, instruction })
    }
}
