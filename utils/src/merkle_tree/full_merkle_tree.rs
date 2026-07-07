use std::{
    cmp::max,
    fmt::Debug,
    iter::{once, repeat_n},
    str::FromStr,
};

use rayon::iter::{IntoParallelIterator, ParallelIterator};

use super::{
    error::{FromConfigError, MerkleTreeInvariant, ZerokitMerkleTreeError},
    merkle_tree::{ZerokitMerkleProof, ZerokitMerkleTree, MIN_PARALLEL_NODES},
};
use crate::hasher::ZerokitHasher;

// Full Merkle Tree Implementation

/// Merkle tree with all leaf and intermediate hashes stored
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FullMerkleTree<H: ZerokitHasher> {
    /// The depth of the tree, i.e. the number of levels from leaf to root
    depth: usize,

    /// The value an empty leaf resets to, fixed at construction
    default_leaf: H::Scalar,

    /// The tree nodes
    nodes: Vec<H::Scalar>,

    /// The indices of leaves which are set into zero upto next_index.
    /// Set to 0 if the leaf is empty and set to 1 in otherwise.
    cached_leaves_indices: Vec<u8>,

    /// The next available (i.e., never used) tree index. Equivalently, the number of leaves added to the tree
    /// (deletions leave next_index unchanged)
    next_index: usize,

    /// Metadata that an application may use to store additional information
    metadata: Vec<u8>,
}

/// Element of a Merkle proof
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum FullMerkleBranch<H: ZerokitHasher> {
    /// Left branch taken, value is the right sibling hash.
    Left(H::Scalar),

    /// Right branch taken, value is the left sibling hash.
    Right(H::Scalar),
}

/// Merkle proof path, bottom to top.
#[derive(Clone, PartialEq, Eq)]
pub struct FullMerkleProof<H: ZerokitHasher>(Vec<FullMerkleBranch<H>>);

#[derive(Default)]
pub struct FullMerkleConfig(());

impl FromStr for FullMerkleConfig {
    type Err = FromConfigError;

    fn from_str(_s: &str) -> Result<Self, Self::Err> {
        Ok(FullMerkleConfig::default())
    }
}

/// Implementations
impl<H: ZerokitHasher> ZerokitMerkleTree for FullMerkleTree<H> {
    type Proof = FullMerkleProof<H>;
    type Hasher = H;
    type Config = FullMerkleConfig;
    type Error = ZerokitMerkleTreeError;

    fn default(depth: usize) -> Result<Self, Self::Error> {
        Self::new(depth, H::Scalar::default(), Self::Config::default())
    }

    /// Creates a new `MerkleTree`
    /// depth - the depth of the tree made only of hash nodes. 2^depth is the maximum number of leaves hash nodes
    fn new(
        depth: usize,
        default_leaf: H::Scalar,
        _config: Self::Config,
    ) -> Result<Self, Self::Error> {
        if depth >= usize::BITS as usize {
            return Err(ZerokitMerkleTreeError::DepthTooLarge);
        }

        // Compute cache node values, leaf to root
        let mut cached_nodes: Vec<H::Scalar> = Vec::with_capacity(depth + 1);
        cached_nodes.push(default_leaf);
        for i in 0..depth {
            cached_nodes.push(H::hash(&[cached_nodes[i], cached_nodes[i]]));
        }
        cached_nodes.reverse();

        // Compute node values
        let nodes = cached_nodes
            .iter()
            .enumerate()
            .flat_map(|(levels, hash)| repeat_n(hash, 1 << levels))
            .cloned()
            .collect::<Vec<_>>();
        debug_assert!(nodes.len() == (1 << (depth + 1)) - 1);

        Ok(Self {
            depth,
            default_leaf,
            nodes,
            cached_leaves_indices: vec![0; 1 << depth],
            next_index: 0,
            metadata: Vec::new(),
        })
    }

    /// Returns the depth of the tree
    fn depth(&self) -> usize {
        self.depth
    }

    /// Returns the capacity of the tree, i.e. the maximum number of accumulatable leaves
    fn capacity(&self) -> usize {
        1 << self.depth
    }

    /// Returns the total number of leaves set
    fn leaves_set(&self) -> usize {
        self.next_index
    }

    /// Returns the root of the tree
    fn root(&self) -> H::Scalar {
        self.nodes[0]
    }

    /// Returns the root of the subtree at `level` (`0` = root, `depth` = leaf) on the path to leaf `index`.
    fn get_subtree_root(&self, level: usize, index: usize) -> Result<H::Scalar, Self::Error> {
        if level > self.depth() {
            return Err(ZerokitMerkleTreeError::LevelOutOfBounds);
        }
        if index >= self.capacity() {
            return Err(ZerokitMerkleTreeError::LeafIndexOutOfBounds);
        }
        if level == 0 {
            Ok(self.root())
        } else if level == self.depth {
            self.get(index)
        } else {
            let mut idx = self.capacity() + index - 1;
            let mut nd = self.depth;
            loop {
                let parent = self.parent(idx).ok_or(ZerokitMerkleTreeError::Invariant(
                    MerkleTreeInvariant::SubtreeWalkParentMissing,
                ))?;
                nd -= 1;
                if nd == level {
                    return Ok(self.nodes[parent]);
                } else {
                    idx = parent;
                }
            }
        }
    }

    /// Sets a leaf at the specified tree index
    fn set(&mut self, leaf: usize, hash: H::Scalar) -> Result<(), Self::Error> {
        if leaf >= self.capacity() {
            return Err(ZerokitMerkleTreeError::LeafIndexOutOfBounds);
        }
        self.set_range(leaf, once(hash))?;
        self.next_index = max(self.next_index, leaf + 1);
        Ok(())
    }

    /// Sets multiple leaves from the specified tree index
    fn set_range<I: ExactSizeIterator<Item = H::Scalar>>(
        &mut self,
        start: usize,
        leaves: I,
    ) -> Result<(), Self::Error> {
        let leaf_count = leaves.len();
        let end = start
            .checked_add(leaf_count)
            .ok_or(ZerokitMerkleTreeError::RangeTooLarge)?;
        if end > self.capacity() {
            return Err(ZerokitMerkleTreeError::RangeTooLarge);
        }
        let index = self.capacity() + start - 1;
        leaves.enumerate().for_each(|(offset, hash)| {
            self.nodes[index + offset] = hash;
            self.cached_leaves_indices[start + offset] = 1;
        });
        if leaf_count != 0 {
            self.update_hashes(index, index + (leaf_count - 1))?;
            self.next_index = max(self.next_index, start + leaf_count);
        }
        Ok(())
    }

    /// Get a leaf from the specified tree index
    fn get(&self, leaf: usize) -> Result<H::Scalar, Self::Error> {
        if leaf >= self.capacity() {
            return Err(ZerokitMerkleTreeError::LeafIndexOutOfBounds);
        }
        Ok(self.nodes[self.capacity() + leaf - 1])
    }

    /// Returns the indices of the leaves that are empty
    fn get_empty_leaves_indices(&self) -> Vec<usize> {
        self.cached_leaves_indices
            .iter()
            .take(self.next_index)
            .enumerate()
            .filter_map(|(index, &v)| (v == 0u8).then_some(index))
            .collect()
    }

    // Trait method `override_range` uses the default `ZerokitMerkleTree` implementation
    // In-memory, so the default `delete` + `set_range` is sufficient (no crash-atomicity concern).

    /// Sets a leaf at the next available index
    fn update_next(&mut self, leaf: H::Scalar) -> Result<(), Self::Error> {
        if self.next_index >= self.capacity() {
            return Err(ZerokitMerkleTreeError::RangeTooLarge);
        }
        self.set(self.next_index, leaf)?;
        Ok(())
    }

    /// Deletes a leaf at a certain index by setting it to its default value (next_index is not updated)
    fn delete(&mut self, index: usize) -> Result<(), Self::Error> {
        if index >= self.next_index {
            return Err(ZerokitMerkleTreeError::DeleteUnsetLeaf);
        }
        let default_leaf = self.default_leaf;
        self.set(index, default_leaf)?;
        self.cached_leaves_indices[index] = 0;
        Ok(())
    }

    // Computes a merkle proof the leaf at the specified index
    fn proof(&self, leaf: usize) -> Result<FullMerkleProof<H>, Self::Error> {
        if leaf >= self.capacity() {
            return Err(ZerokitMerkleTreeError::LeafIndexOutOfBounds);
        }
        let mut index = self.capacity() + leaf - 1;
        let mut path = Vec::with_capacity(self.depth + 1);
        while let Some(parent) = self.parent(index) {
            // Add proof for node at index to parent
            path.push(match index & 1 {
                1 => FullMerkleBranch::Left(self.nodes[index + 1]),
                0 => FullMerkleBranch::Right(self.nodes[index - 1]),
                _ => unreachable!(),
            });
            index = parent;
        }
        Ok(FullMerkleProof(path))
    }

    // Verifies a Merkle proof with respect to the input leaf and the tree root
    fn verify(
        &self,
        leaf: &H::Scalar,
        merkle_proof: &FullMerkleProof<H>,
    ) -> Result<bool, Self::Error> {
        if merkle_proof.length() != self.depth {
            return Err(ZerokitMerkleTreeError::InvalidMerkleProof);
        }
        let expected_root = merkle_proof.compute_root_from(leaf);
        Ok(expected_root.eq(&self.root()))
    }

    fn set_metadata(&mut self, metadata: &[u8]) -> Result<(), Self::Error> {
        self.metadata = metadata.to_vec();
        Ok(())
    }

    fn metadata(&self) -> Result<Vec<u8>, Self::Error> {
        Ok(self.metadata.to_vec())
    }

    // Trait method `close` uses the default `ZerokitMerkleTree` implementation
    // In-memory, so the default `close` is sufficient (no crash-atomicity concern).
}

// Utilities for updating the tree nodes
impl<H: ZerokitHasher> FullMerkleTree<H> {
    /// For a given node index, return the parent node index
    /// Returns None if there is no parent (root node)
    fn parent(&self, index: usize) -> Option<usize> {
        if index == 0 {
            None
        } else {
            Some(((index + 1) >> 1) - 1)
        }
    }

    /// For a given node index, return index of the first (left) child.
    fn first_child(&self, index: usize) -> usize {
        (index << 1) + 1
    }

    /// Returns the depth level of a node based on its index in the flattened tree.
    fn levels(&self, index: usize) -> usize {
        // `n.next_power_of_two()` will return `n` iff `n` is a power of two.
        // The extra offset corrects this.
        (index + 2).next_power_of_two().trailing_zeros() as usize - 1
    }

    /// Updates parent hashes after modifying a range of nodes at the same level.
    ///
    /// - `start_index`: The first index at the current level that was updated.
    /// - `end_index`: The last index (inclusive) at the same level that was updated.
    fn update_hashes(
        &mut self,
        start_index: usize,
        end_index: usize,
    ) -> Result<(), ZerokitMerkleTreeError> {
        // Ensure the range is within the same tree level
        if self.levels(start_index) != self.levels(end_index) {
            return Err(ZerokitMerkleTreeError::Invariant(
                MerkleTreeInvariant::UpdateHashesLevelMismatch,
            ));
        }

        // Compute parent indices for the range
        if let (Some(start_parent), Some(end_parent)) =
            (self.parent(start_index), self.parent(end_index))
        {
            // Closure to compute the hash of a parent node given its index, by hashing its two children
            let hash_parent = |parent: usize| {
                let left = self.first_child(parent);
                H::hash(&[self.nodes[left], self.nodes[left + 1]])
            };

            // Use parallel processing when the number of pairs exceeds the threshold
            let hashes: Vec<H::Scalar> = if end_parent - start_parent + 1 >= MIN_PARALLEL_NODES {
                (start_parent..=end_parent)
                    .into_par_iter()
                    .map(hash_parent)
                    .collect()
            } else {
                // Otherwise, fallback to sequential update for small ranges
                (start_parent..=end_parent).map(hash_parent).collect()
            };

            // Write the hashes back in one contiguous slice copy
            self.nodes[start_parent..=end_parent].copy_from_slice(&hashes);

            // Recurse to update upper levels
            self.update_hashes(start_parent, end_parent)?;
        }

        Ok(())
    }
}

impl<H: ZerokitHasher> ZerokitMerkleProof for FullMerkleProof<H> {
    type Index = u8;
    type Hasher = H;

    // Returns the length of a Merkle proof
    fn length(&self) -> usize {
        self.0.len()
    }

    /// Computes the leaf index corresponding to a Merkle proof
    fn leaf_index(&self) -> usize {
        self.0.iter().rev().fold(0, |index, branch| match branch {
            FullMerkleBranch::Left(_) => index << 1,
            FullMerkleBranch::Right(_) => (index << 1) + 1,
        })
    }

    /// Returns the path elements forming a Merkle proof
    fn get_path_elements(&self) -> Vec<H::Scalar> {
        self.0
            .iter()
            .map(|x| match x {
                FullMerkleBranch::Left(value) | FullMerkleBranch::Right(value) => *value,
            })
            .collect()
    }

    /// Returns the path indexes forming a Merkle proof
    fn get_path_index(&self) -> Vec<Self::Index> {
        self.0
            .iter()
            .map(|branch| match branch {
                FullMerkleBranch::Left(_) => 0,
                FullMerkleBranch::Right(_) => 1,
            })
            .collect()
    }

    /// Computes the Merkle root corresponding by iteratively hashing a Merkle proof with a given input leaf
    fn compute_root_from(&self, hash: &H::Scalar) -> H::Scalar {
        self.0.iter().fold(*hash, |hash, branch| match branch {
            FullMerkleBranch::Left(sibling) => H::hash(&[hash, *sibling]),
            FullMerkleBranch::Right(sibling) => H::hash(&[*sibling, hash]),
        })
    }
}

// Debug formatting for printing a (Full) Merkle Proof Branch
impl<H: ZerokitHasher> Debug for FullMerkleBranch<H>
where
    H::Scalar: Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Left(arg0) => f.debug_tuple("Left").field(arg0).finish(),
            Self::Right(arg0) => f.debug_tuple("Right").field(arg0).finish(),
        }
    }
}

// Debug formatting for printing a (Full) Merkle Proof
impl<H: ZerokitHasher> Debug for FullMerkleProof<H>
where
    H::Scalar: Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Proof").field(&self.0).finish()
    }
}
