// This crate provides different implementation of Merkle tree
// Currently two interchangeable implementations are supported:
//    - FullMerkleTree: each tree node is stored
//    - OptimalMerkleTree: only nodes used to prove accumulation of set leaves are stored
// Library defaults are set in the poseidon_tree crate
//
// Merkle tree implementations are adapted from https://github.com/kilic/rln/blob/master/src/merkle.rs
// and https://github.com/worldcoin/semaphore-rs/blob/d462a4372f1fd9c27610f2acfe4841fab1d396aa/src/merkle_tree.rs

use std::{
    fmt::{Debug, Display},
    str::FromStr,
};

use crate::merkle_tree::error::ZerokitMerkleTreeError;

/// Enables parallel hashing when there are at least 8 nodes (4 pairs to hash), justifying the overhead.
pub const MIN_PARALLEL_NODES: usize = 8;

/// In the Hasher trait we define the node type, the default leaf,
/// and the hash function used to initialize a Merkle Tree implementation.
pub trait Hasher {
    /// Type of the leaf and tree node
    type Fr: Clone + Copy + Eq + Default + Debug + Display + FromStr + Send + Sync;

    /// Error type for hash operations - must be convertible to ZerokitMerkleTreeError
    type Error: Into<ZerokitMerkleTreeError> + std::error::Error + Send + Sync + 'static;

    /// Returns the default tree leaf
    fn default_leaf() -> Self::Fr;

    /// Utility to compute the hash of an intermediate node
    fn hash(input: &[Self::Fr]) -> Result<Self::Fr, Self::Error>;
}

pub type FrOf<H> = <H as Hasher>::Fr;

/// In the ZerokitMerkleTree trait we define the methods that are required to be implemented by a Merkle tree
/// Including, OptimalMerkleTree, FullMerkleTree
pub trait ZerokitMerkleTree {
    type Proof: ZerokitMerkleProof;
    type Hasher: Hasher;
    type Config: Default + FromStr;

    fn default(depth: usize) -> Result<Self, ZerokitMerkleTreeError>
    where
        Self: Sized;
    fn new(
        depth: usize,
        default_leaf: FrOf<Self::Hasher>,
        config: Self::Config,
    ) -> Result<Self, ZerokitMerkleTreeError>
    where
        Self: Sized;
    fn depth(&self) -> usize;
    fn capacity(&self) -> usize;
    fn leaves_set(&self) -> usize;
    fn root(&self) -> FrOf<Self::Hasher>;
    fn get_subtree_root(
        &self,
        n: usize,
        index: usize,
    ) -> Result<FrOf<Self::Hasher>, ZerokitMerkleTreeError>;
    fn set(&mut self, index: usize, leaf: FrOf<Self::Hasher>)
        -> Result<(), ZerokitMerkleTreeError>;
    fn set_range<I>(&mut self, start: usize, leaves: I) -> Result<(), ZerokitMerkleTreeError>
    where
        I: ExactSizeIterator<Item = FrOf<Self::Hasher>>;
    fn get(&self, index: usize) -> Result<FrOf<Self::Hasher>, ZerokitMerkleTreeError>;
    fn get_empty_leaves_indices(&self) -> Vec<usize>;
    fn override_range<I, J>(
        &mut self,
        start: usize,
        leaves: I,
        to_remove_indices: J,
    ) -> Result<(), ZerokitMerkleTreeError>
    where
        I: ExactSizeIterator<Item = FrOf<Self::Hasher>>,
        J: ExactSizeIterator<Item = usize>;
    fn update_next(&mut self, leaf: FrOf<Self::Hasher>) -> Result<(), ZerokitMerkleTreeError>;
    fn delete(&mut self, index: usize) -> Result<(), ZerokitMerkleTreeError>;
    fn proof(&self, index: usize) -> Result<Self::Proof, ZerokitMerkleTreeError>;
    fn verify(
        &self,
        leaf: &FrOf<Self::Hasher>,
        merkle_proof: &Self::Proof,
    ) -> Result<bool, ZerokitMerkleTreeError>;
    fn set_metadata(&mut self, metadata: &[u8]) -> Result<(), ZerokitMerkleTreeError>;
    fn metadata(&self) -> Result<Vec<u8>, ZerokitMerkleTreeError>;
    fn close_db_connection(&mut self) -> Result<(), ZerokitMerkleTreeError>;
}

pub trait ZerokitMerkleProof {
    type Index;
    type Hasher: Hasher;

    fn length(&self) -> usize;
    fn leaf_index(&self) -> usize;
    fn get_path_elements(&self) -> Vec<FrOf<Self::Hasher>>;
    fn get_path_index(&self) -> Vec<Self::Index>;
    fn compute_root_from(
        &self,
        leaf: &FrOf<Self::Hasher>,
    ) -> Result<FrOf<Self::Hasher>, ZerokitMerkleTreeError>;
}
