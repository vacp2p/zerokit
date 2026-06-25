/// Errors that can occur during Merkle tree operations.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ZerokitMerkleTreeError {
    #[error("Tree depth exceeds the supported maximum")]
    DepthTooLarge,
    /// The requested depth does not match the depth of the already existing (persisted) tree.
    #[error("Tree depth does not match the existing tree")]
    DepthMismatch,
    /// A leaf index is greater than or equal to the tree capacity.
    #[error("Leaf index out of bounds")]
    LeafIndexOutOfBounds,
    /// A subtree level is greater than the tree depth.
    #[error("Level exceeds tree depth")]
    LevelOutOfBounds,
    /// A contiguous write (set_range/override_range/update_next) would exceed the tree capacity.
    #[error("Leaf range exceeds tree capacity")]
    RangeTooLarge,
    /// A delete targeted an index that holds no set leaf (index >= leaves_set).
    #[error("Cannot delete an unset leaf")]
    DeleteUnsetLeaf,
    /// An override_range remove index is unset or out of range.
    #[error("Override remove index is unset or out of range")]
    InvalidRemoveIndex,
    /// override_range was called with neither leaves to write nor indices to remove.
    #[error("Override called with no leaves and no removals")]
    EmptyOverrideArgs,
    /// A Merkle proof length does not match the tree depth.
    #[error("Merkle proof length does not match tree depth")]
    InvalidMerkleProof,
    /// An internal invariant of the Merkle tree was violated.
    #[error("Internal merkle tree invariant violated: {0}")]
    Invariant(MerkleTreeInvariant),
}

/// Invariants that can be violated during Merkle tree operations of `FullMerkleTree` and `OptimalMerkleTree`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum MerkleTreeInvariant {
    /// `FullMerkleTree`: a non-root node reported no parent during a subtree-root walk.
    #[error("FullMerkleTree: parent returned None during subtree walk")]
    SubtreeWalkParentMissing,
    /// `FullMerkleTree`: `update_hashes` was given a start and end index at different levels.
    #[error("FullMerkleTree: update_hashes start and end level mismatch")]
    UpdateHashesLevelMismatch,
    /// `OptimalMerkleTree`: the proof walk did not terminate at the root.
    #[error("OptimalMerkleTree: proof walk did not terminate at root")]
    ProofWalkNotTerminated,
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
