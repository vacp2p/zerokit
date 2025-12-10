pub use crate::merkle_tree::{FromConfigError, ZerokitMerkleTreeError};
use crate::poseidon::error::PoseidonError;

/// Errors that can occur during hashing operations.
#[derive(Debug, thiserror::Error)]
pub enum HashError {
    #[error("Poseidon hash error: {0}")]
    Poseidon(#[from] PoseidonError),
    #[error("Generic hash error: {0}")]
    Generic(String),
}
