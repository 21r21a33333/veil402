//! Canonical client library for constructing and proving Veil transactions.

mod client;
mod protocol;
mod proving;

pub use client::{Config, Error, Proof, Veil};
pub use protocol::{
    Field, MerklePath, Note, Output, Owner, Public, PublicInputs, Secret, Spend, TREE_DEPTH,
    Transaction,
};
