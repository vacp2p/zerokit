use std::{
    cmp::max,
    fmt::Debug,
    iter::{once, repeat_n},
    str::FromStr,
};

use color_eyre::{Report, Result};
use rayon::iter::{IntoParallelIterator, ParallelIterator};

use crate::merkle_tree::{FrOf, Hasher, ZerokitMerkleProof, ZerokitMerkleTree, PARALLEL_THRESHOLD};

////////////////////////////////////////////////////////////
///// Full Merkle Tree Implementation
////////////////////////////////////////////////////////////

/// Merkle tree with all leaf and intermediate hashes stored
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct FullMerkleTree<H>
where
    H: Hasher,
{
    /// The depth of the tree, i.e. the number of levels from leaf to root
    depth: usize,

    /// The tree nodes
    nodes: Vec<H::Fr>,

    /// The indices of leaves which are set into zero upto next_index.
    /// Set to 0 if the leaf is empty and set to 1 in otherwise.
    cached_leaves_indices: Vec<u8>,

    // The next available (i.e., never used) tree index. Equivalently, the number of leaves added to the tree
    // (deletions leave next_index unchanged)
    next_index: usize,

    // metadata that an application may use to store additional information
    metadata: Vec<u8>,
}

/// Element of a Merkle proof
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum FullMerkleBranch<H: Hasher> {
    /// Left branch taken, value is the right sibling hash.
    Left(H::Fr),

    /// Right branch taken, value is the left sibling hash.
    Right(H::Fr),
}

/// Merkle proof path, bottom to top.
#[derive(Clone, PartialEq, Eq)]
pub struct FullMerkleProof<H: Hasher>(pub Vec<FullMerkleBranch<H>>);

#[derive(Default)]
pub struct FullMerkleConfig(());

impl FromStr for FullMerkleConfig {
    type Err = Report;

    fn from_str(_s: &str) -> Result<Self> {
        Ok(FullMerkleConfig::default())
    }
}

/// Implementations
impl<H: Hasher> ZerokitMerkleTree for FullMerkleTree<H>
where
    H: Hasher,
{
    type Proof = FullMerkleProof<H>;
    type Hasher = H;
    type Config = FullMerkleConfig;

    fn default(depth: usize) -> Result<Self> {
        FullMerkleTree::<H>::new(depth, Self::Hasher::default_leaf(), Self::Config::default())
    }

    /// Creates a new `MerkleTree`
    /// depth - the height of the tree made only of hash nodes. 2^depth is the maximum number of leaves hash nodes
    fn new(depth: usize, default_leaf: FrOf<Self::Hasher>, _config: Self::Config) -> Result<Self> {
        // Compute cache node values, leaf to root
        let mut cached_nodes: Vec<H::Fr> = Vec::with_capacity(depth + 1);
        cached_nodes.push(default_leaf);
        for i in 0..depth {
            cached_nodes.push(H::hash(&[cached_nodes[i]; 2]));
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
            nodes,
            cached_leaves_indices: vec![0; 1 << depth],
            next_index: 0,
            metadata: Vec::new(),
        })
    }

    fn close_db_connection(&mut self) -> Result<()> {
        Ok(())
    }

    // Returns the depth of the tree
    fn depth(&self) -> usize {
        self.depth
    }

    // Returns the capacity of the tree, i.e. the maximum number of accumulatable leaves
    fn capacity(&self) -> usize {
        1 << self.depth
    }

    // Returns the total number of leaves set
    fn leaves_set(&self) -> usize {
        self.next_index
    }

    // Returns the root of the tree
    fn root(&self) -> FrOf<Self::Hasher> {
        self.nodes[0]
    }

    // Sets a leaf at the specified tree index
    fn set(&mut self, leaf: usize, hash: FrOf<Self::Hasher>) -> Result<()> {
        self.set_range(leaf, once(hash))?;
        self.next_index = max(self.next_index, leaf + 1);
        Ok(())
    }

    // Get a leaf from the specified tree index
    fn get(&self, leaf: usize) -> Result<FrOf<Self::Hasher>> {
        if leaf >= self.capacity() {
            return Err(Report::msg("leaf index out of bounds"));
        }
        Ok(self.nodes[self.capacity() + leaf - 1])
    }

    fn get_subtree_root(&self, n: usize, index: usize) -> Result<H::Fr> {
        if n > self.depth() {
            return Err(Report::msg("level exceeds depth size"));
        }
        if index >= self.capacity() {
            return Err(Report::msg("index exceeds set size"));
        }
        if n == 0 {
            Ok(self.root())
        } else if n == self.depth {
            self.get(index)
        } else {
            let mut idx = self.capacity() + index - 1;
            let mut nd = self.depth;
            loop {
                let parent = self.parent(idx).unwrap();
                nd -= 1;
                if nd == n {
                    return Ok(self.nodes[parent]);
                } else {
                    idx = parent;
                    continue;
                }
            }
        }
    }
    fn get_empty_leaves_indices(&self) -> Vec<usize> {
        self.cached_leaves_indices
            .iter()
            .take(self.next_index)
            .enumerate()
            .filter(|&(_, &v)| v == 0u8)
            .map(|(idx, _)| idx)
            .collect()
    }

    // Sets tree nodes, starting from start index
    // Function proper of FullMerkleTree implementation
    fn set_range<I: ExactSizeIterator<Item = FrOf<Self::Hasher>>>(
        &mut self,
        start: usize,
        hashes: I,
    ) -> Result<()> {
        let index = self.capacity() + start - 1;
        let mut count = 0;
        // first count number of hashes, and check that they fit in the tree
        // then insert into the tree
        let hashes = hashes.into_iter().collect::<Vec<_>>();
        if hashes.len() + start > self.capacity() {
            return Err(Report::msg("provided hashes do not fit in the tree"));
        }
        hashes.into_iter().for_each(|hash| {
            self.nodes[index + count] = hash;
            self.cached_leaves_indices[start + count] = 1;
            count += 1;
        });
        if count != 0 {
            self.update_hashes(index, index + (count - 1))?;
            self.next_index = max(self.next_index, start + count);
        }
        Ok(())
    }

    fn override_range<I, J>(&mut self, start: usize, leaves: I, indices: J) -> Result<()>
    where
        I: ExactSizeIterator<Item = FrOf<Self::Hasher>>,
        J: ExactSizeIterator<Item = usize>,
    {
        let indices = indices.into_iter().collect::<Vec<_>>();
        let min_index = *indices.first().unwrap();
        let leaves_vec = leaves.into_iter().collect::<Vec<_>>();

        let max_index = start + leaves_vec.len();

        let mut set_values = vec![Self::Hasher::default_leaf(); max_index - min_index];

        for i in min_index..start {
            if !indices.contains(&i) {
                let value = self.get(i)?;
                set_values[i - min_index] = value;
            }
        }

        for i in 0..leaves_vec.len() {
            set_values[start - min_index + i] = leaves_vec[i];
        }

        for i in indices {
            self.cached_leaves_indices[i] = 0;
        }

        self.set_range(start, set_values.into_iter())
            .map_err(|e| Report::msg(e.to_string()))
    }

    // Sets a leaf at the next available index
    fn update_next(&mut self, leaf: FrOf<Self::Hasher>) -> Result<()> {
        self.set(self.next_index, leaf)?;
        Ok(())
    }

    // Deletes a leaf at a certain index by setting it to its default value (next_index is not updated)
    fn delete(&mut self, index: usize) -> Result<()> {
        // We reset the leaf only if we previously set a leaf at that index
        if index < self.next_index {
            self.set(index, H::default_leaf())?;
            self.cached_leaves_indices[index] = 0;
        }
        Ok(())
    }

    // Computes a merkle proof the leaf at the specified index
    fn proof(&self, leaf: usize) -> Result<FullMerkleProof<H>> {
        if leaf >= self.capacity() {
            return Err(Report::msg("index exceeds set size"));
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
    fn verify(&self, hash: &FrOf<Self::Hasher>, proof: &FullMerkleProof<H>) -> Result<bool> {
        Ok(proof.compute_root_from(hash) == self.root())
    }

    fn compute_root(&mut self) -> Result<FrOf<Self::Hasher>> {
        Ok(self.root())
    }

    fn set_metadata(&mut self, metadata: &[u8]) -> Result<()> {
        self.metadata = metadata.to_vec();
        Ok(())
    }

    fn metadata(&self) -> Result<Vec<u8>> {
        Ok(self.metadata.to_vec())
    }
}

impl<H: Hasher> FullMerkleTree<H>
where
    H: Hasher,
{
    // Utilities for updating the tree nodes

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

    fn levels(&self, index: usize) -> usize {
        // `n.next_power_of_two()` will return `n` iff `n` is a power of two.
        // The extra offset corrects this.
        (index + 2).next_power_of_two().trailing_zeros() as usize - 1
    }

    /// Updates parent hashes after modifying a range of nodes at the same level.
    ///
    /// - `start_index`: The first index at the current level that was updated.
    /// - `end_index`: The last index (inclusive) at the same level that was updated.
    fn update_hashes(&mut self, start_index: usize, end_index: usize) -> Result<()> {
        // Ensure the range is within the same tree level
        if self.levels(start_index) != self.levels(end_index) {
            return Err(Report::msg(
                "start_index and end_index must be on the same level",
            ));
        }

        // Compute parent indices for the range
        if let (Some(start_parent), Some(end_parent)) =
            (self.parent(start_index), self.parent(end_index))
        {
            // If the number of parent nodes is large, use parallel processing
            if end_parent - start_parent + 1 >= PARALLEL_THRESHOLD {
                let updates: Vec<(usize, H::Fr)> = (start_parent..=end_parent)
                    .into_par_iter()
                    .map(|parent| {
                        let left_child = self.first_child(parent);
                        let right_child = left_child + 1;
                        let hash = H::hash(&[self.nodes[left_child], self.nodes[right_child]]);
                        (parent, hash)
                    })
                    .collect();

                for (parent, hash) in updates {
                    self.nodes[parent] = hash;
                }
            } else {
                // Otherwise, fall back to sequential update
                for parent in start_parent..=end_parent {
                    let left_child = self.first_child(parent);
                    let right_child = left_child + 1;
                    self.nodes[parent] =
                        H::hash(&[self.nodes[left_child], self.nodes[right_child]]);
                }
            }

            // Recurse to update upper levels
            self.update_hashes(start_parent, end_parent)?;
        }

        Ok(())
    }
}

impl<H: Hasher> ZerokitMerkleProof for FullMerkleProof<H> {
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
    fn get_path_elements(&self) -> Vec<FrOf<Self::Hasher>> {
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
    fn compute_root_from(&self, hash: &FrOf<Self::Hasher>) -> FrOf<Self::Hasher> {
        self.0.iter().fold(*hash, |hash, branch| match branch {
            FullMerkleBranch::Left(sibling) => H::hash(&[hash, *sibling]),
            FullMerkleBranch::Right(sibling) => H::hash(&[*sibling, hash]),
        })
    }
}

// Debug formatting for printing a (Full) Merkle Proof Branch
impl<H> Debug for FullMerkleBranch<H>
where
    H: Hasher,
    H::Fr: Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Left(arg0) => f.debug_tuple("Left").field(arg0).finish(),
            Self::Right(arg0) => f.debug_tuple("Right").field(arg0).finish(),
        }
    }
}

// Debug formatting for printing a (Full) Merkle Proof
impl<H> Debug for FullMerkleProof<H>
where
    H: Hasher,
    H::Fr: Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Proof").field(&self.0).finish()
    }
}
