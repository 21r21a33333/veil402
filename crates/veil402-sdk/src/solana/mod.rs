//! Solana pool configuration and transaction instruction construction.

mod binding;
mod instruction;

use crate::{Error, Field, Proof, protocol::Plan};
use solana_instruction::Instruction;
use solana_pubkey::Pubkey;

pub(crate) const DOMAIN: &[u8] = b"veil402:transact:v4";
pub(crate) const VERSION_SEED: &[u8] = b"v4";

/// Largest encrypted note accepted for each v4 output.
pub const MAX_ENCRYPTED_NOTE_LEN: usize = 128;

/// Immutable configuration for one deployed pool.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Pool {
    pub(crate) program: Pubkey,
    pub(crate) verifier: Pubkey,
    pub(crate) mint: Pubkey,
    pub(crate) domain: [u8; 32],
    pub(crate) address: Pubkey,
    pub(crate) tree: Pubkey,
    pub(crate) vault: Pubkey,
    asset: Field,
}

impl Pool {
    /// Creates a v4 pool configuration and derives its canonical addresses.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Poseidon`] when the mint cannot be mapped to the circuit asset field.
    pub fn new(
        program: Pubkey,
        verifier: Pubkey,
        mint: Pubkey,
        domain: [u8; 32],
    ) -> Result<Self, Error> {
        let (address, _) = Pubkey::find_program_address(&[b"pool", VERSION_SEED], &program);
        let (tree, _) = Pubkey::find_program_address(&[b"tree", address.as_ref()], &program);
        let vault = spl_associated_token_account_interface::address::get_associated_token_address_with_program_id(
            &address,
            &mint,
            &spl_token_interface::id(),
        );
        let asset = binding::asset(&mint)?;
        Ok(Self {
            program,
            verifier,
            mint,
            domain,
            address,
            tree,
            vault,
            asset,
        })
    }

    /// Returns the pool PDA.
    #[must_use]
    pub const fn address(&self) -> Pubkey {
        self.address
    }

    /// Returns the Merkle-tree PDA.
    #[must_use]
    pub const fn tree(&self) -> Pubkey {
        self.tree
    }

    /// Returns the pool token vault.
    #[must_use]
    pub const fn vault(&self) -> Pubkey {
        self.vault
    }

    /// Returns the circuit asset identifier for this pool mint.
    #[must_use]
    pub const fn asset(&self) -> Field {
        self.asset
    }

    pub(crate) fn bind(&self, external: &External, amount: i64) -> Result<Field, Error> {
        binding::external(self, external, amount)
    }

    pub(crate) fn instruction(
        &self,
        proof: &Proof,
        external: &External,
        amount: i64,
        payer: Pubkey,
    ) -> Result<Instruction, Error> {
        instruction::transact(self, proof, external, amount, payer)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct External {
    pub(crate) recipient: Pubkey,
    pub(crate) encrypted: [Vec<u8>; 2],
}

impl External {
    pub(crate) fn new(plan: &Plan, recipient: Pubkey) -> Result<Self, Error> {
        let encrypted = plan.encrypted();
        if encrypted
            .iter()
            .any(|payload| payload.len() > MAX_ENCRYPTED_NOTE_LEN)
        {
            return Err(Error::Transaction("encrypted note exceeds 128 bytes"));
        }
        Ok(External {
            recipient,
            encrypted: [encrypted[0].to_vec(), encrypted[1].to_vec()],
        })
    }
}

/// Public withdrawal details bound into the proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Withdrawal {
    recipient: Pubkey,
    amount: i64,
}

impl Withdrawal {
    /// Validates a withdrawal destination and amount.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Withdrawal`] for a zero or unrepresentable amount.
    pub fn new(recipient: Pubkey, amount: u64) -> Result<Self, Error> {
        if amount == 0 {
            return Err(Error::Withdrawal("amount must be greater than zero"));
        }
        let amount = i64::try_from(amount)
            .map_err(|_| Error::Withdrawal("amount exceeds the signed protocol range"))?;
        Ok(Self { recipient, amount })
    }

    /// Returns the recipient wallet.
    #[must_use]
    pub const fn recipient(&self) -> Pubkey {
        self.recipient
    }

    /// Returns the withdrawn token amount.
    #[must_use]
    pub const fn amount(&self) -> u64 {
        self.amount.unsigned_abs()
    }

    pub(crate) const fn public_amount(self) -> i64 {
        -self.amount
    }
}

/// A locally verified proof and the instruction that consumes it.
#[derive(Clone, Debug)]
pub struct Prepared {
    /// Proof and public values used by the instruction.
    pub proof: Proof,
    /// Ready-to-sign pool transaction instruction.
    pub instruction: Instruction,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derives_versioned_pool_addresses() -> Result<(), Error> {
        let program = Pubkey::new_from_array([1; 32]);
        let pool = Pool::new(
            program,
            Pubkey::new_from_array([2; 32]),
            Pubkey::new_from_array([3; 32]),
            [4; 32],
        )?;
        let (expected, _) = Pubkey::find_program_address(&[b"pool", b"v4"], &program);
        assert_eq!(pool.address(), expected);
        Ok(())
    }
}
