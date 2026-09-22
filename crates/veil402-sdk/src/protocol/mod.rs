mod encoding;
mod field;
pub(crate) mod note;
mod transaction;

pub use field::{Field, Secret};
pub use note::{Note, Owner, Send};
pub use transaction::{MerklePath, PublicInputs, Spend, Transaction};
pub(crate) use transaction::{Plan, Public, Values};

/// Number of siblings in a transaction circuit Merkle path.
pub const TREE_DEPTH: usize = 20;
