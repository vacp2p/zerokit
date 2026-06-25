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
    #[error("Tree depth exceeds maximum allowed (must be < {})", usize::BITS)]
    InvalidDepth,
    #[error("The set_range method received too many leaves")]
    TooManySet,
    #[error("Unknown error while computing merkle proof")]
    ComputingProofError,
    #[error("Invalid merkle proof length (!= tree depth)")]
    InvalidMerkleProof,
}

/// Errors that can occur while creating Merkle tree from config
#[derive(Debug, thiserror::Error)]
pub enum FromConfigError {
    #[error("Error while reading tree config: {0}")]
    JsonError(#[from] serde_json::Error),
    #[error("Error while creating tree config: missing path")]
    MissingPath,
    #[error("Error while creating tree config: path already exists")]
    PathExists,
    #[error("Error while creating tree default temp path: {0}")]
    IoError(#[from] std::io::Error),
}
