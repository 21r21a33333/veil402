use solana_poseidon::{Endianness, Parameters, hashv};

use super::{Field, Secret};
use crate::client::Error;

fn poseidon(inputs: &[&Field]) -> Result<Field, Error> {
    let bytes: Vec<&[u8]> = inputs
        .iter()
        .map(|field| field.as_bytes().as_slice())
        .collect();
    let hash =
        hashv(Parameters::Bn254X5, Endianness::BigEndian, &bytes).map_err(|_| Error::Poseidon)?;
    Field::from_bytes(hash.to_bytes())
}

/// Secrets that authorize spending a note.
#[derive(Debug)]
pub struct Owner {
    /// Spending key.
    pub spend: Secret,
    /// Viewing key used to derive the nullifier key.
    pub view: Secret,
}

impl Owner {
    /// Derives the public owner identifier used by recipients.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Poseidon`] if the configured hash rejects its inputs.
    pub fn public(&self) -> Result<Field, Error> {
        let spend = poseidon(&[&self.spend.expose()])?;
        let nullifier = self.nullifier_key()?;
        poseidon(&[&spend, &nullifier])
    }

    pub(crate) fn nullifier_key(&self) -> Result<Field, Error> {
        poseidon(&[&self.view.expose()])
    }
}

/// A private note owned by the caller.
#[derive(Debug)]
pub struct Note {
    /// Token amount.
    pub value: u64,
    /// Pool asset identifier.
    pub asset: Field,
    /// Per-note blinding value.
    pub random: Secret,
}

impl Note {
    pub(crate) fn commitment(&self, owner: &Owner) -> Result<Field, Error> {
        let public_key = poseidon(&[&owner.public()?, &self.random.expose()])?;
        poseidon(&[&public_key, &self.asset, &Field::from(self.value)])
    }
}

/// The note created by a transaction.
#[derive(Debug)]
pub struct Output {
    /// Recipient master public key.
    pub owner: Field,
    /// Token amount.
    pub value: u64,
    /// Per-note blinding value.
    pub random: Secret,
}

impl Output {
    pub(crate) fn public_key(&self) -> Result<Field, Error> {
        poseidon(&[&self.owner, &self.random.expose()])
    }
}

pub(crate) fn commitment(key: &Field, asset: &Field, value: u64) -> Result<Field, Error> {
    poseidon(&[key, asset, &Field::from(value)])
}

pub(crate) fn nullifier(owner: &Owner, index: u32) -> Result<Field, Error> {
    poseidon(&[&owner.nullifier_key()?, &Field::from(u64::from(index))])
}

pub(crate) fn merkle_root(mut node: Field, index: u32, siblings: &[Field]) -> Result<Field, Error> {
    for (level, sibling) in siblings.iter().enumerate() {
        node = if index & (1 << level) == 0 {
            poseidon(&[&node, sibling])?
        } else {
            poseidon(&[sibling, &node])?
        };
    }
    Ok(node)
}
