//! Canonical client library for constructing and proving Veil transactions.

mod client;
mod protocol;
mod proving;
pub mod solana;

pub use client::{Config, Error, Proof, Veil};
pub use protocol::{
    Field, MerklePath, Note, Owner, PublicInputs, Secret, Send, Spend, TREE_DEPTH, Transaction,
};
pub use solana::{Pool, Prepared, Withdrawal};
