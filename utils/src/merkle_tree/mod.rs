pub mod error;
pub mod full_merkle_tree;
#[allow(clippy::module_inception)]
pub mod merkle_tree;
pub mod optimal_merkle_tree;

pub use error::{FromConfigError, MerkleTreeInvariant, ZerokitMerkleTreeError};
pub use full_merkle_tree::{FullMerkleConfig, FullMerkleProof, FullMerkleTree};
pub use merkle_tree::{compute_tree_root, ZerokitMerkleProof, ZerokitMerkleTree};
pub use optimal_merkle_tree::{OptimalMerkleConfig, OptimalMerkleProof, OptimalMerkleTree};

pub use crate::hasher::ZerokitHasher;
