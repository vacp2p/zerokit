// This module provides different implementation of Merkle tree
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

use super::error::ZerokitMerkleTreeError;

/// Enables parallel hashing when there are at least 8 nodes (4 pairs to hash), justifying the overhead.
pub const MIN_PARALLEL_NODES: usize = 8;

/// In the Hasher trait we define the node type, the default leaf,
/// and the hash function used to initialize a Merkle Tree implementation.
pub trait Hasher {
    /// Type of the leaf and tree node
    type Fr: Clone + Copy + Eq + Default + Debug + Display + FromStr + Send + Sync;

    /// Returns the default tree leaf
    fn default_leaf() -> Self::Fr;

    /// Utility to compute the hash of an intermediate node
    fn hash_pair(left: Self::Fr, right: Self::Fr) -> Self::Fr;
}

pub type FrOf<H> = <H as Hasher>::Fr;

/// In the ZerokitMerkleTree trait we define the methods that are required to be implemented by a Merkle tree
/// Including, OptimalMerkleTree, FullMerkleTree
pub trait ZerokitMerkleTree {
    type Proof: ZerokitMerkleProof;
    type Hasher: Hasher;
    type Config: Default + FromStr;
    type Error: std::error::Error + From<ZerokitMerkleTreeError>;

    fn default(depth: usize) -> Result<Self, Self::Error>
    where
        Self: Sized;
    fn new(
        depth: usize,
        default_leaf: FrOf<Self::Hasher>,
        config: Self::Config,
    ) -> Result<Self, Self::Error>
    where
        Self: Sized;
    fn depth(&self) -> usize;
    fn capacity(&self) -> usize;
    fn leaves_set(&self) -> usize;
    fn root(&self) -> FrOf<Self::Hasher>;
    /// Returns the root of the subtree at `level` (`0` = root, `depth` = leaf) on the path to leaf `index`.
    fn get_subtree_root(
        &self,
        level: usize,
        index: usize,
    ) -> Result<FrOf<Self::Hasher>, Self::Error>;
    fn set(&mut self, index: usize, leaf: FrOf<Self::Hasher>) -> Result<(), Self::Error>;
    fn set_range<I>(&mut self, start: usize, leaves: I) -> Result<(), Self::Error>
    where
        I: ExactSizeIterator<Item = FrOf<Self::Hasher>>;
    fn get(&self, index: usize) -> Result<FrOf<Self::Hasher>, Self::Error>;
    fn get_empty_leaves_indices(&self) -> Vec<usize>;
    /// Overrides a range of leaves: writes `leaves` from `start`, then resets each non-overlapping
    /// index in `to_remove_indices` (writes win over deletes on overlap). Validates before mutating.
    /// The default impl composes `delete` + `set_range`; it is not crash-atomic, so a persistent
    /// backend should override it with a single atomic commit (see `PmTree`).
    fn override_range<I, J>(
        &mut self,
        start: usize,
        leaves: I,
        to_remove_indices: J,
    ) -> Result<(), Self::Error>
    where
        I: IntoIterator<Item = FrOf<Self::Hasher>>,
        J: IntoIterator<Item = usize>,
        Self: Sized,
    {
        let leaves = leaves.into_iter().collect::<Vec<_>>();
        let to_remove_indices = to_remove_indices.into_iter().collect::<Vec<_>>();

        if leaves.is_empty() && to_remove_indices.is_empty() {
            return Err(ZerokitMerkleTreeError::EmptyOverrideArgs.into());
        }
        let end = start
            .checked_add(leaves.len())
            .ok_or(ZerokitMerkleTreeError::RangeTooLarge)?;
        if end > self.capacity() {
            return Err(ZerokitMerkleTreeError::RangeTooLarge.into());
        }
        // Capture before `set_range` grows it. Only indices the written range does NOT cover are
        // actually deleted; each such index must point at a set leaf. Overlapping indices are exempt
        // (the write overwrites them), so they need not be set beforehand. Validate before mutating.
        let leaves_set = self.leaves_set();
        for &index in &to_remove_indices {
            if (index < start || index >= end) && index >= leaves_set {
                return Err(ZerokitMerkleTreeError::InvalidRemoveIndex.into());
            }
        }

        for &index in &to_remove_indices {
            if index < start || index >= end {
                self.delete(index)?;
            }
        }
        if !leaves.is_empty() {
            self.set_range(start, leaves.into_iter())?;
        }
        Ok(())
    }
    fn update_next(&mut self, leaf: FrOf<Self::Hasher>) -> Result<(), Self::Error>;
    fn delete(&mut self, index: usize) -> Result<(), Self::Error>;
    fn proof(&self, index: usize) -> Result<Self::Proof, Self::Error>;
    fn verify(
        &self,
        leaf: &FrOf<Self::Hasher>,
        merkle_proof: &Self::Proof,
    ) -> Result<bool, Self::Error>;
    fn set_metadata(&mut self, metadata: &[u8]) -> Result<(), Self::Error>;
    fn metadata(&self) -> Result<Vec<u8>, Self::Error>;
    /// Closes the tree, flushing pending writes for persistent backends.
    /// Optional: the default is a no-op (in-memory trees), and persistent backends also flush on drop.
    fn close(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
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

/// Computes a Merkle root from a leaf and a Merkle path (path elements and path index)
pub fn compute_tree_root<H: Hasher>(
    leaf: FrOf<H>,
    path_elements: &[FrOf<H>],
    path_index: &[u8],
) -> FrOf<H> {
    path_elements
        .iter()
        .zip(path_index)
        .fold(leaf, |acc, (sibling, &index)| {
            if index == 0 {
                H::hash_pair(acc, *sibling)
            } else {
                H::hash_pair(*sibling, acc)
            }
        })
}
