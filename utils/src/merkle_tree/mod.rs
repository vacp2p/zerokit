pub mod error;
pub mod full_merkle_tree;
#[allow(clippy::module_inception)]
pub mod merkle_tree;
pub mod optimal_merkle_tree;

pub use {
    error::{FromConfigError, ZerokitMerkleTreeError},
    full_merkle_tree::{FullMerkleConfig, FullMerkleProof, FullMerkleTree},
    merkle_tree::{FrOf, Hasher, ZerokitMerkleProof, ZerokitMerkleTree, MIN_PARALLEL_NODES},
    optimal_merkle_tree::{OptimalMerkleConfig, OptimalMerkleProof, OptimalMerkleTree},
};
