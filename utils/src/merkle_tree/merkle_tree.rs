// This crate provides different implementation of Merkle tree
// Currently two interchangeable implementations are supported:
//    - FullMerkleTree: each tree node is stored
//    - OptimalMerkleTree: only nodes used to prove accumulation of set leaves are stored
// Library defaults are set in the poseidon_tree crate
//
// Merkle tree implementations are adapted from https://github.com/kilic/rln/blob/master/src/merkle.rs
// and https://github.com/worldcoin/semaphore-rs/blob/d462a4372f1fd9c27610f2acfe4841fab1d396aa/src/merkle_tree.rs

//!
//! # To do
//!
//! * Disk based storage backend (using mmaped files should be easy)
//! * Implement serialization for tree and Merkle proof

use std::fmt::Debug;
use std::str::FromStr;

use color_eyre::Result;

/// In the Hasher trait we define the node type, the default leaf
/// and the hash function used to initialize a Merkle Tree implementation
pub trait Hasher {
    /// Type of the leaf and tree node
    type Fr: Clone + Copy + Eq + Debug + ToString;

    /// Returns the default tree leaf
    fn default_leaf() -> Self::Fr;

    /// Utility to compute the hash of an intermediate node
    fn hash(input: &[Self::Fr]) -> Self::Fr;
}

pub type FrOf<H> = <H as Hasher>::Fr;

/// In the ZerokitMerkleTree trait we define the methods that are required to be implemented by a Merkle tree
/// Including, OptimalMerkleTree, FullMerkleTree
pub trait ZerokitMerkleTree {
    type Proof: ZerokitMerkleProof;
    type Hasher: Hasher;
    type Config: Default + FromStr;

    fn default(depth: usize) -> Result<Self>
    where
        Self: Sized;
    fn new(depth: usize, default_leaf: FrOf<Self::Hasher>, config: Self::Config) -> Result<Self>
    where
        Self: Sized;
    fn depth(&self) -> usize;
    fn capacity(&self) -> usize;
    fn leaves_set(&mut self) -> usize;
    fn root(&self) -> FrOf<Self::Hasher>;
    fn compute_root(&mut self) -> Result<FrOf<Self::Hasher>>;
    fn set(&mut self, index: usize, leaf: FrOf<Self::Hasher>) -> Result<()>;
    fn set_range<I>(&mut self, start: usize, leaves: I) -> Result<()>
    where
        I: IntoIterator<Item = FrOf<Self::Hasher>>;
    fn get(&self, index: usize) -> Result<FrOf<Self::Hasher>>;
    fn override_range<I, J>(&mut self, start: usize, leaves: I, to_remove_indices: J) -> Result<()>
    where
        I: IntoIterator<Item = FrOf<Self::Hasher>>,
        J: IntoIterator<Item = usize>;
    fn update_next(&mut self, leaf: FrOf<Self::Hasher>) -> Result<()>;
    fn delete(&mut self, index: usize) -> Result<()>;
    fn proof(&self, index: usize) -> Result<Self::Proof>;
    fn verify(&self, leaf: &FrOf<Self::Hasher>, witness: &Self::Proof) -> Result<bool>;
    fn set_metadata(&mut self, metadata: &[u8]) -> Result<()>;
    fn metadata(&self) -> Result<Vec<u8>>;
    fn close_db_connection(&mut self) -> Result<()>;
}

pub trait ZerokitMerkleProof {
    type Index;
    type Hasher: Hasher;

    fn length(&self) -> usize;
    fn leaf_index(&self) -> usize;
    fn get_path_elements(&self) -> Vec<FrOf<Self::Hasher>>;
    fn get_path_index(&self) -> Vec<Self::Index>;
    fn compute_root_from(&self, leaf: &FrOf<Self::Hasher>) -> FrOf<Self::Hasher>;
}
