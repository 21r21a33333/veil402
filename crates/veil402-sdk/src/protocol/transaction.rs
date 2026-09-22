use rand::{RngCore, rngs::OsRng};

use super::{Field, Note, Owner, Send, TREE_DEPTH, note};
use crate::client::Error;

const SLOTS: usize = 2;

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

/// A user transaction containing only real spends and sends.
#[derive(Debug)]
pub struct Transaction {
    spends: Vec<Spend>,
    sends: Vec<Send>,
}

impl Transaction {
    /// Creates a transaction from one or two spends and up to two sends.
    ///
    /// Missing circuit slots are padded internally with fresh zero-value notes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Transaction`] for unsupported arity or caller-supplied zero notes.
    pub fn new(inputs: Vec<Spend>, outputs: Vec<Send>) -> Result<Self, Error> {
        if !(1..=SLOTS).contains(&inputs.len()) {
            return Err(Error::Transaction("transaction requires one or two spends"));
        }
        if outputs.len() > SLOTS {
            return Err(Error::Transaction("transaction supports at most two sends"));
        }
        if inputs.iter().any(|spend| spend.note.value == 0) {
            return Err(Error::Transaction("spend value must be greater than zero"));
        }
        Ok(Self {
            spends: inputs,
            sends: outputs,
        })
    }

    pub(crate) fn plan(self, asset: Field) -> Result<Plan, Error> {
        if self.spends.iter().any(|spend| spend.note.asset != asset) {
            return Err(Error::Transaction("spend asset does not match the pool"));
        }

        let payload_len = self
            .sends
            .iter()
            .map(|send| send.encrypted.len())
            .max()
            .unwrap_or(0);
        let mut rng = OsRng;
        let mut inputs = self.spends;
        while inputs.len() < SLOTS {
            inputs.push(dummy_spend(asset, &mut rng)?);
        }
        let mut outputs = self.sends;
        while outputs.len() < SLOTS {
            outputs.push(Send::dummy(payload_len, &mut rng)?);
        }

        shuffle_pair(&mut inputs, &mut rng)?;
        shuffle_pair(&mut outputs, &mut rng)?;
        Ok(Plan {
            spends: inputs
                .try_into()
                .map_err(|_| Error::Transaction("invalid spend arity"))?,
            sends: outputs
                .try_into()
                .map_err(|_| Error::Transaction("invalid send arity"))?,
            asset,
        })
    }
}

/// Circuit public inputs in verifier order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicInputs {
    /// Merkle root shared by all real inputs.
    pub root: Field,
    /// Input nullifiers in shuffled circuit order.
    pub nullifiers: [Field; SLOTS],
    /// Output commitments in shuffled circuit order.
    pub commitments: [Field; SLOTS],
    /// Signed public amount represented in the field.
    pub amount: Field,
    /// External-data hash.
    pub hash: Field,
}

impl PublicInputs {
    /// Returns the seven circuit inputs in verifier order.
    #[must_use]
    pub const fn fields(&self) -> [Field; 7] {
        [
            self.root,
            self.nullifiers[0],
            self.nullifiers[1],
            self.commitments[0],
            self.commitments[1],
            self.amount,
            self.hash,
        ]
    }

    pub(crate) fn witness_bytes(&self) -> [u8; 236] {
        let mut bytes = [0_u8; 236];
        bytes[..12].copy_from_slice(&[0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0, 7]);
        for (offset, field) in self.fields().iter().enumerate() {
            let start = 12 + offset * 32;
            bytes[start..start + 32].copy_from_slice(field.as_bytes());
        }
        bytes
    }
}

pub(crate) struct Public {
    pub(crate) amount: i64,
    pub(crate) hash: Field,
}

pub(crate) struct Plan {
    pub(crate) spends: [Spend; SLOTS],
    pub(crate) sends: [Send; SLOTS],
    pub(crate) asset: Field,
}

pub(crate) struct Values {
    pub(crate) public: PublicInputs,
    pub(crate) output_keys: [Field; SLOTS],
}

impl Plan {
    pub(crate) fn encrypted(&self) -> [&[u8]; SLOTS] {
        [&self.sends[0].encrypted, &self.sends[1].encrypted]
    }

    pub(crate) fn values(&self, public: &Public) -> Result<Values, Error> {
        let mut root = None;
        let mut nullifiers = [Field::ZERO; SLOTS];
        let mut input_total = 0_i128;

        for (slot, spend) in self.spends.iter().enumerate() {
            if u64::from(spend.merkle.index) >= (1_u64 << TREE_DEPTH) {
                return Err(Error::Transaction("leaf index exceeds tree capacity"));
            }
            let nullifier = note::nullifier(&spend.owner, spend.merkle.index)?;
            if nullifier == Field::ZERO {
                return Err(Error::Transaction("nullifier must not be zero"));
            }
            nullifiers[slot] = nullifier;
            input_total += i128::from(spend.note.value);

            if spend.note.value != 0 {
                let leaf = spend.note.commitment(&spend.owner)?;
                let candidate =
                    note::merkle_root(leaf, spend.merkle.index, &spend.merkle.siblings)?;
                if root
                    .replace(candidate)
                    .is_some_and(|current| current != candidate)
                {
                    return Err(Error::Transaction("spends do not share a Merkle root"));
                }
            }
        }
        if nullifiers[0] == nullifiers[1] {
            return Err(Error::Transaction("spend nullifiers must be distinct"));
        }

        let output_keys = [self.sends[0].public_key()?, self.sends[1].public_key()?];
        let commitments = [
            note::commitment_from_key(&output_keys[0], &self.asset, self.sends[0].value)?,
            note::commitment_from_key(&output_keys[1], &self.asset, self.sends[1].value)?,
        ];
        let output_total = self
            .sends
            .iter()
            .map(|send| i128::from(send.value))
            .sum::<i128>();
        if input_total + i128::from(public.amount) != output_total {
            return Err(Error::Transaction("value is not conserved"));
        }

        Ok(Values {
            public: PublicInputs {
                root: root.ok_or(Error::Transaction("transaction has no real input"))?,
                nullifiers,
                commitments,
                amount: Field::from_signed(public.amount),
                hash: public.hash,
            },
            output_keys,
        })
    }
}

fn dummy_spend(asset: Field, rng: &mut impl RngCore) -> Result<Spend, Error> {
    loop {
        let mut index_bytes = [0_u8; 4];
        rng.try_fill_bytes(&mut index_bytes)
            .map_err(|_| Error::Random)?;
        let index = u32::from_be_bytes(index_bytes) & ((1_u32 << TREE_DEPTH) - 1);
        let mut siblings = [Field::ZERO; TREE_DEPTH];
        for sibling in &mut siblings {
            *sibling = Field::random(rng)?;
        }
        let spend = Spend {
            note: Note {
                value: 0,
                asset,
                random: super::Secret::random_with(rng)?,
            },
            owner: Owner {
                spend: super::Secret::random_with(rng)?,
                view: super::Secret::random_with(rng)?,
            },
            merkle: MerklePath { index, siblings },
        };
        if note::nullifier(&spend.owner, spend.merkle.index)? != Field::ZERO {
            return Ok(spend);
        }
    }
}

fn shuffle_pair<T>(values: &mut [T], rng: &mut impl RngCore) -> Result<(), Error> {
    let mut choice = [0_u8; 1];
    rng.try_fill_bytes(&mut choice).map_err(|_| Error::Random)?;
    if choice[0] & 1 == 1 {
        values.swap(0, 1);
    }
    Ok(())
}
