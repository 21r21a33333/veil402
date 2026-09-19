use super::{Field, Note, Output, Owner, TREE_DEPTH, note};
use crate::client::Error;

/// Merkle authentication data for a note.
#[derive(Debug)]
pub struct MerklePath {
    /// Zero-based leaf index.
    pub index: u32,
    /// Siblings from leaf level to root.
    pub siblings: [Field; TREE_DEPTH],
}

/// An input note together with its authorization and Merkle path.
#[derive(Debug)]
pub struct Spend {
    /// Note being spent.
    pub note: Note,
    /// Spending authority.
    pub owner: Owner,
    /// Note membership path.
    pub merkle: MerklePath,
}

/// On-chain-visible transaction values committed by the proof.
#[derive(Debug)]
pub struct Public {
    /// Net token flow: positive deposits, zero transfers, and negative withdrawals.
    pub amount: i64,
    /// Hash binding external transaction data interpreted by the contract.
    pub hash: Field,
}

/// A transaction ready to prove.
#[derive(Debug)]
pub struct Transaction {
    /// Existing note to spend.
    pub input: Spend,
    /// New note to create.
    pub send: Output,
    /// Public token flow and external-data binding.
    pub public: Public,
}

/// Circuit public inputs in verifier order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicInputs {
    /// Merkle root.
    pub root: Field,
    /// Input nullifier.
    pub nullifier: Field,
    /// Output note commitment.
    pub commitment: Field,
    /// Signed public amount represented in the field.
    pub amount: Field,
    /// External-data hash.
    pub hash: Field,
}

pub(crate) struct Values {
    pub(crate) public: PublicInputs,
    pub(crate) output_key: Field,
}

impl PublicInputs {
    /// Returns the five circuit inputs in verifier order.
    #[must_use]
    pub const fn fields(&self) -> [Field; 5] {
        [
            self.root,
            self.nullifier,
            self.commitment,
            self.amount,
            self.hash,
        ]
    }

    pub(crate) fn witness_bytes(&self) -> [u8; 172] {
        let mut bytes = [0_u8; 172];
        bytes[..12].copy_from_slice(&[0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 5]);
        for (offset, field) in self.fields().iter().enumerate() {
            let start = 12 + offset * 32;
            bytes[start..start + 32].copy_from_slice(field.as_bytes());
        }
        bytes
    }
}

impl Transaction {
    /// Derives the verifier inputs for this transaction without generating a proof.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Transaction`] when values do not balance, or [`Error::Poseidon`] when a
    /// protocol hash cannot be computed.
    pub fn inputs(&self) -> Result<PublicInputs, Error> {
        Ok(self.values()?.public)
    }

    pub(crate) fn values(&self) -> Result<Values, Error> {
        let value = i128::from(self.input.note.value) + i128::from(self.public.amount);
        if value != i128::from(self.send.value) {
            return Err(Error::Transaction("value is not conserved"));
        }

        let leaf = self.input.note.commitment(&self.input.owner)?;
        let root = note::merkle_root(leaf, self.input.merkle.index, &self.input.merkle.siblings)?;
        let nullifier = note::nullifier(&self.input.owner, self.input.merkle.index)?;
        let output_key = self.send.public_key()?;
        let commitment = note::commitment(&output_key, &self.input.note.asset, self.send.value)?;
        let amount = Field::from_signed(self.public.amount);

        Ok(Values {
            public: PublicInputs {
                root,
                nullifier,
                commitment,
                amount,
                hash: self.public.hash,
            },
            output_key,
        })
    }
}
