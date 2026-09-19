mod encoding;
mod field;
mod note;
mod transaction;

pub use field::{Field, Secret};
pub use note::{Note, Output, Owner};
pub(crate) use transaction::Values;
pub use transaction::{MerklePath, Public, PublicInputs, Spend, Transaction};

/// Number of siblings in a transaction circuit Merkle path.
pub const TREE_DEPTH: usize = 20;
