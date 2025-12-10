use super::poseidon::error::PoseidonError;
pub use crate::merkle_tree::{FromConfigError, ZerokitMerkleTreeError};

/// Errors that can occur during hashing operations.
#[derive(Debug, thiserror::Error)]
pub enum HashError {
    #[error("Poseidon hash error: {0}")]
    Poseidon(#[from] PoseidonError),
    #[error("Generic hash error: {0}")]
    Generic(String),
}
