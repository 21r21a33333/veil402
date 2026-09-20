//! Solana pool configuration and withdrawal instruction construction.

mod binding;
mod instruction;

use crate::{Error, Field, Proof};
use solana_instruction::Instruction;
use solana_pubkey::Pubkey;

pub(crate) const DOMAIN: &[u8] = b"veil402:transact:v1";

/// Largest encrypted note accepted by the v1 transaction instruction.
pub const MAX_ENCRYPTED_NOTE_LEN: usize = 128;

/// Immutable configuration for one deployed pool.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Pool {
    program: Pubkey,
    verifier: Pubkey,
    mint: Pubkey,
    domain: [u8; 32],
    address: Pubkey,
    tree: Pubkey,
    vault: Pubkey,
    asset: Field,
}

impl Pool {
    /// Creates a pool configuration and derives its canonical addresses.
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
        let (address, _) = Pubkey::find_program_address(&[b"pool"], &program);
        let (tree, _) = Pubkey::find_program_address(&[b"tree"], &program);
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

    pub(crate) fn bind(&self, withdrawal: &Withdrawal) -> Result<Field, Error> {
        if withdrawal.recipient == self.address {
            return Err(Error::Withdrawal("recipient resolves to the pool vault"));
        }
        binding::withdrawal(self, withdrawal)
    }

    pub(crate) fn instruction(
        &self,
        proof: &Proof,
        withdrawal: &Withdrawal,
        payer: Pubkey,
    ) -> Result<Instruction, Error> {
        instruction::withdraw(self, proof, withdrawal, payer)
    }
}

/// Public withdrawal data bound into a proof.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Withdrawal {
    recipient: Pubkey,
    amount: i64,
    encrypted_note: Vec<u8>,
}

impl Withdrawal {
    /// Validates withdrawal data.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Withdrawal`] for a zero or unrepresentable amount, or an oversized note.
    pub fn new(recipient: Pubkey, amount: u64, encrypted_note: Vec<u8>) -> Result<Self, Error> {
        if amount == 0 {
            return Err(Error::Withdrawal("amount must be greater than zero"));
        }
        if encrypted_note.len() > MAX_ENCRYPTED_NOTE_LEN {
            return Err(Error::Withdrawal("encrypted note exceeds 128 bytes"));
        }
        let amount = i64::try_from(amount)
            .map_err(|_| Error::Withdrawal("amount exceeds the signed protocol range"))?;
        Ok(Self {
            recipient,
            amount,
            encrypted_note,
        })
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

    /// Returns the encrypted output note.
    #[must_use]
    pub fn encrypted_note(&self) -> &[u8] {
        &self.encrypted_note
    }

    pub(crate) const fn public_amount(&self) -> i64 {
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
    fn rejects_pool_as_withdrawal_recipient() -> Result<(), Error> {
        let pool = Pool::new(
            Pubkey::new_from_array([1; 32]),
            Pubkey::new_from_array([2; 32]),
            Pubkey::new_from_array([3; 32]),
            [4; 32],
        )?;
        let withdrawal = Withdrawal::new(pool.address(), 1, Vec::new())?;

        assert!(matches!(
            pool.bind(&withdrawal),
            Err(Error::Withdrawal("recipient resolves to the pool vault"))
        ));
        Ok(())
    }
}
