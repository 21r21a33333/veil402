use solana_poseidon::{Endianness, Parameters, hashv};

use super::{Field, Secret};
use crate::client::Error;

pub(crate) const SPEND_KEY_DOMAIN: Field = Field::from_raw_u64(1);
pub(crate) const NULLIFIER_KEY_DOMAIN: Field = Field::from_raw_u64(2);
pub(crate) const OWNER_DOMAIN: Field = Field::from_raw_u64(3);
pub(crate) const NOTE_KEY_DOMAIN: Field = Field::from_raw_u64(4);
pub(crate) const NOTE_DOMAIN: Field = Field::from_raw_u64(5);
pub(crate) const NULLIFIER_DOMAIN: Field = Field::from_raw_u64(6);
pub(crate) const ASSET_DOMAIN: Field = Field::from_raw_u64(7);

pub(crate) fn poseidon(inputs: &[&Field]) -> Result<Field, Error> {
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
    /// Generates independent spending and viewing keys from the operating system CSPRNG.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Random`] when secure randomness is unavailable.
    pub fn random() -> Result<Self, Error> {
        Ok(Self {
            spend: Secret::random()?,
            view: Secret::random()?,
        })
    }

    /// Derives the public owner identifier used by recipients.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Poseidon`] if the configured hash rejects its inputs.
    pub fn public(&self) -> Result<Field, Error> {
        let spend = poseidon(&[&SPEND_KEY_DOMAIN, &self.spend.expose()])?;
        let nullifier = self.nullifier_key()?;
        poseidon(&[&OWNER_DOMAIN, &spend, &nullifier])
    }

    pub(crate) fn nullifier_key(&self) -> Result<Field, Error> {
        poseidon(&[&NULLIFIER_KEY_DOMAIN, &self.view.expose()])
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
    /// Derives the note public key passed to `shield`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Poseidon`] if the configured hash rejects its inputs.
    pub fn public_key(&self, owner: &Owner) -> Result<Field, Error> {
        note_key(&owner.public()?, &self.random.expose())
    }

    /// Derives the note commitment inserted into the pool tree.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Poseidon`] if the configured hash rejects its inputs.
    pub fn commitment(&self, owner: &Owner) -> Result<Field, Error> {
        commitment_from_key(&self.public_key(owner)?, &self.asset, self.value)
    }
}

/// A private note created by a transaction and its matching encrypted payload.
#[derive(Debug)]
pub struct Send {
    pub(crate) owner: Field,
    pub(crate) value: u64,
    pub(crate) random: Secret,
    pub(crate) encrypted: Vec<u8>,
}

impl Send {
    /// Creates a non-zero output note.
    ///
    /// The encrypted payload is kept with its note so padding and shuffling cannot reorder them
    /// independently.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Transaction`] when `value` is zero.
    pub fn new(
        owner: Field,
        value: u64,
        random: Secret,
        encrypted: Vec<u8>,
    ) -> Result<Self, Error> {
        if value == 0 {
            return Err(Error::Transaction("send value must be greater than zero"));
        }
        Ok(Self {
            owner,
            value,
            random,
            encrypted,
        })
    }

    /// Returns the recipient's public owner identifier.
    #[must_use]
    pub const fn owner(&self) -> Field {
        self.owner
    }

    /// Returns the private token amount.
    #[must_use]
    pub const fn value(&self) -> u64 {
        self.value
    }

    /// Returns the encrypted note payload emitted on chain.
    #[must_use]
    pub fn encrypted(&self) -> &[u8] {
        &self.encrypted
    }

    pub(crate) fn dummy(length: usize, rng: &mut impl rand::RngCore) -> Result<Self, Error> {
        let mut encrypted = vec![0_u8; length];
        rng.try_fill_bytes(&mut encrypted)
            .map_err(|_| Error::Random)?;
        Ok(Self {
            owner: Field::random(rng)?,
            value: 0,
            random: Secret::random_with(rng)?,
            encrypted,
        })
    }

    pub(crate) fn public_key(&self) -> Result<Field, Error> {
        note_key(&self.owner, &self.random.expose())
    }
}

pub(crate) fn note_key(owner: &Field, random: &Field) -> Result<Field, Error> {
    poseidon(&[&NOTE_KEY_DOMAIN, owner, random])
}

pub(crate) fn commitment_from_key(key: &Field, asset: &Field, value: u64) -> Result<Field, Error> {
    poseidon(&[&NOTE_DOMAIN, key, asset, &Field::from(value)])
}

pub(crate) fn nullifier(owner: &Owner, index: u32) -> Result<Field, Error> {
    poseidon(&[
        &NULLIFIER_DOMAIN,
        &owner.nullifier_key()?,
        &Field::from(u64::from(index)),
    ])
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
