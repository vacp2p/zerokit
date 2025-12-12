use crate::error::HashError;

/// Errors that can occur during Merkle tree operations
#[derive(Debug, thiserror::Error)]
pub enum ZerokitMerkleTreeError {
    #[error("Invalid index")]
    InvalidIndex,
    #[error("Invalid indices")]
    InvalidIndices,
    #[error("Leaf index out of bounds")]
    InvalidLeaf,
    #[error("Level exceeds tree depth")]
    InvalidLevel,
    #[error("Subtree index out of bounds")]
    InvalidSubTreeIndex,
    #[error("Start level is != from end level")]
    InvalidStartAndEndLevel,
    #[error("set_range got too many leaves")]
    TooManySet,
    #[error("Unknown error while computing merkle proof")]
    ComputingProofError,
    #[error("Invalid merkle proof length (!= tree depth)")]
    InvalidMerkleProof,
    #[cfg(feature = "pmtree-ft")]
    #[error("Pmtree error: {0}")]
    PmtreeErrorKind(#[from] pmtree::PmtreeErrorKind),
    #[error("Hash error: {0}")]
    HashError(#[from] HashError),
}

/// Errors that can occur while creating Merkle tree from config
#[derive(Debug, thiserror::Error)]
pub enum FromConfigError {
    #[error("Error while reading pmtree config: {0}")]
    JsonError(#[from] serde_json::Error),
    #[error("Error while creating pmtree config: missing path")]
    MissingPath,
    #[error("Error while creating pmtree config: path already exists")]
    PathExists,
    #[error("Error while creating pmtree default temp path: {0}")]
    IoError(#[from] std::io::Error),
}
