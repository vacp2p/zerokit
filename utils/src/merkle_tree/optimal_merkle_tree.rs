use std::{cmp::max, collections::HashMap, fmt::Debug, str::FromStr};

use color_eyre::{Report, Result};
use rayon::iter::{IntoParallelIterator, ParallelIterator};

use crate::merkle_tree::{FrOf, Hasher, ZerokitMerkleProof, ZerokitMerkleTree, MIN_PARALLEL_NODES};

////////////////////////////////////////////////////////////
///// Optimal Merkle Tree Implementation
////////////////////////////////////////////////////////////

/// The Merkle tree structure
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct OptimalMerkleTree<H>
where
    H: Hasher,
{
    /// The depth of the tree, i.e. the number of levels from leaf to root
    depth: usize,

    /// The nodes cached from the empty part of the tree (where leaves are set to default).
    /// Since the rightmost part of the tree is usually changed much later than its creation,
    /// we can prove accumulation of elements in the leftmost part, with no need to initialize the full tree
    /// and by caching few intermediate nodes to the root computed from default leaves
    cached_nodes: Vec<H::Fr>,

    /// The tree nodes
    nodes: HashMap<(usize, usize), H::Fr>,

    /// The indices of leaves which are set into zero upto next_index.
    /// Set to 0 if the leaf is empty and set to 1 in otherwise.
    cached_leaves_indices: Vec<u8>,

    /// The next available (i.e., never used) tree index. Equivalently, the number of leaves added to the tree
    /// (deletions leave next_index unchanged)
    next_index: usize,

    /// metadata that an application may use to store additional information
    metadata: Vec<u8>,
}

/// The Merkle proof
/// Contains a vector of (node, branch_index) that defines the proof path elements and branch direction (1 or 0)
#[derive(Clone, PartialEq, Eq)]
pub struct OptimalMerkleProof<H: Hasher>(pub Vec<(H::Fr, u8)>);

#[derive(Default)]
pub struct OptimalMerkleConfig(());

impl FromStr for OptimalMerkleConfig {
    type Err = Report;

    fn from_str(_s: &str) -> Result<Self> {
        Ok(OptimalMerkleConfig::default())
    }
}

/// Implementations
impl<H: Hasher> ZerokitMerkleTree for OptimalMerkleTree<H>
where
    H: Hasher,
{
    type Proof = OptimalMerkleProof<H>;
    type Hasher = H;
    type Config = OptimalMerkleConfig;

    fn default(depth: usize) -> Result<Self> {
        OptimalMerkleTree::<H>::new(depth, H::default_leaf(), Self::Config::default())
    }

    /// Creates a new `MerkleTree`
    /// depth - the height of the tree made only of hash nodes. 2^depth is the maximum number of leaves hash nodes
    fn new(depth: usize, default_leaf: H::Fr, _config: Self::Config) -> Result<Self> {
        // Compute cache node values, leaf to root
        let mut cached_nodes: Vec<H::Fr> = Vec::with_capacity(depth + 1);
        cached_nodes.push(default_leaf);
        for i in 0..depth {
            cached_nodes.push(H::hash(&[cached_nodes[i]; 2]));
        }
        cached_nodes.reverse();

        Ok(OptimalMerkleTree {
            depth,
            cached_nodes,
            nodes: HashMap::with_capacity(1 << depth),
            cached_leaves_indices: vec![0; 1 << depth],
            next_index: 0,
            metadata: Vec::new(),
        })
    }

    fn close_db_connection(&mut self) -> Result<()> {
        Ok(())
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
    fn root(&self) -> H::Fr {
        self.get_node(0, 0)
    }

    /// Sets a leaf at the specified tree index
    fn set(&mut self, index: usize, leaf: H::Fr) -> Result<()> {
        if index >= self.capacity() {
            return Err(Report::msg("index exceeds set size"));
        }
        self.nodes.insert((self.depth, index), leaf);
        self.update_hashes(index, 1)?;
        self.next_index = max(self.next_index, index + 1);
        self.cached_leaves_indices[index] = 1;
        Ok(())
    }

    /// Get a leaf from the specified tree index
    fn get(&self, index: usize) -> Result<H::Fr> {
        if index >= self.capacity() {
            return Err(Report::msg("index exceeds set size"));
        }
        Ok(self.get_node(self.depth, index))
    }

    /// Returns the root of the subtree at level n and index
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
            Ok(self.get_node(n, index >> (self.depth - n)))
        }
    }

    /// Returns the indices of the leaves that are empty
    fn get_empty_leaves_indices(&self) -> Vec<usize> {
        self.cached_leaves_indices
            .iter()
            .take(self.next_index)
            .enumerate()
            .filter(|&(_, &v)| v == 0u8)
            .map(|(idx, _)| idx)
            .collect()
    }

    /// Sets multiple leaves from the specified tree index
    fn set_range<I: ExactSizeIterator<Item = H::Fr>>(
        &mut self,
        start: usize,
        leaves: I,
    ) -> Result<()> {
        // check if the range is valid
        let leaves_len = leaves.len();
        if start + leaves_len > self.capacity() {
            return Err(Report::msg("provided range exceeds set size"));
        }
        for (i, leaf) in leaves.enumerate() {
            self.nodes.insert((self.depth, start + i), leaf);
            self.cached_leaves_indices[start + i] = 1;
        }
        self.update_hashes(start, leaves_len)?;
        self.next_index = max(self.next_index, start + leaves_len);
        Ok(())
    }

    /// Overrides a range of leaves while resetting specified indices to default and preserving unaffected values.
    fn override_range<I, J>(&mut self, start: usize, leaves: I, indices: J) -> Result<()>
    where
        I: ExactSizeIterator<Item = FrOf<Self::Hasher>>,
        J: ExactSizeIterator<Item = usize>,
    {
        let indices = indices.into_iter().collect::<Vec<_>>();
        let min_index = *indices.first().expect("indices should not be empty");
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

    /// Sets a leaf at the next available index
    fn update_next(&mut self, leaf: H::Fr) -> Result<()> {
        self.set(self.next_index, leaf)?;
        Ok(())
    }

    /// Deletes a leaf at a certain index by setting it to its default value (next_index is not updated)
    fn delete(&mut self, index: usize) -> Result<()> {
        // We reset the leaf only if we previously set a leaf at that index
        if index < self.next_index {
            self.set(index, H::default_leaf())?;
            self.cached_leaves_indices[index] = 0;
        }
        Ok(())
    }

    /// Computes a merkle proof the leaf at the specified index
    fn proof(&self, index: usize) -> Result<Self::Proof> {
        if index >= self.capacity() {
            return Err(Report::msg("index exceeds set size"));
        }
        let mut witness = Vec::<(H::Fr, u8)>::with_capacity(self.depth);
        let mut i = index;
        let mut depth = self.depth;
        loop {
            i ^= 1;
            witness.push((
                self.get_node(depth, i),
                (1 - (i & 1)).try_into().expect("0 or 1 expected"),
            ));
            i >>= 1;
            depth -= 1;
            if depth == 0 {
                break;
            }
        }
        if i != 0 {
            Err(Report::msg("i != 0"))
        } else {
            Ok(OptimalMerkleProof(witness))
        }
    }

    /// Verifies a Merkle proof with respect to the input leaf and the tree root
    fn verify(&self, leaf: &H::Fr, witness: &Self::Proof) -> Result<bool> {
        if witness.length() != self.depth {
            return Err(Report::msg("witness length doesn't match tree depth"));
        }
        let expected_root = witness.compute_root_from(leaf);
        Ok(expected_root.eq(&self.root()))
    }

    fn set_metadata(&mut self, metadata: &[u8]) -> Result<()> {
        self.metadata = metadata.to_vec();
        Ok(())
    }

    fn metadata(&self) -> Result<Vec<u8>> {
        Ok(self.metadata.to_vec())
    }
}

// Utilities for updating the tree nodes
impl<H: Hasher> OptimalMerkleTree<H>
where
    H: Hasher,
{
    /// Returns the value of a node at a specific (depth, index).
    /// Falls back to a cached default if the node hasn't been set.
    fn get_node(&self, depth: usize, index: usize) -> H::Fr {
        *self
            .nodes
            .get(&(depth, index))
            .unwrap_or_else(|| &self.cached_nodes[depth])
    }

    /// Computes the hash of a node’s two children at the given depth.
    /// If the index is odd, it is rounded down to the nearest even index.
    fn hash_couple(&self, depth: usize, index: usize) -> H::Fr {
        let b = index & !1;
        H::hash(&[self.get_node(depth, b), self.get_node(depth, b + 1)])
    }

    /// Updates parent hashes after modifying a range of leaf nodes.
    ///
    /// - `start`: Starting leaf index that was updated.
    /// - `length`: Number of consecutive leaves that were updated.
    fn update_hashes(&mut self, start: usize, length: usize) -> Result<()> {
        // Start at the leaf level
        let mut current_depth = self.depth;

        // Round down to include the left sibling in the pair (if start is odd)
        let mut current_index = start & !1;

        // Compute the max index at this level, round up to include the last updated leaf’s right sibling (if start + length is odd)
        let mut current_index_max = (start + length + 1) & !1;

        // Traverse from the leaf level up to the root
        while current_depth > 0 {
            // Compute the parent level (one level above the current)
            let parent_depth = current_depth - 1;

            // Use parallel processing when the number of pairs exceeds the threshold
            if current_index_max - current_index >= MIN_PARALLEL_NODES {
                let updates: Vec<((usize, usize), H::Fr)> = (current_index..current_index_max)
                    .step_by(2)
                    .collect::<Vec<_>>()
                    .into_par_iter()
                    .map(|index| {
                        // Hash two child nodes at positions (current_depth, index) and (current_depth, index + 1)
                        let hash = self.hash_couple(current_depth, index);
                        // Return the computed parent hash and its position at
                        ((parent_depth, index >> 1), hash)
                    })
                    .collect();

                for (parent, hash) in updates {
                    self.nodes.insert(parent, hash);
                }
            } else {
                // Otherwise, fallback to sequential update for small ranges
                for index in (current_index..current_index_max).step_by(2) {
                    let hash = self.hash_couple(current_depth, index);
                    self.nodes.insert((parent_depth, index >> 1), hash);
                }
            }

            // Move up one level in the tree
            current_index >>= 1;
            current_index_max = (current_index_max + 1) >> 1;
            current_depth -= 1;
        }

        Ok(())
    }
}

impl<H: Hasher> ZerokitMerkleProof for OptimalMerkleProof<H>
where
    H: Hasher,
{
    type Index = u8;
    type Hasher = H;

    /// Returns the length of a Merkle proof
    fn length(&self) -> usize {
        self.0.len()
    }

    /// Computes the leaf index corresponding to a Merkle proof
    fn leaf_index(&self) -> usize {
        // In current implementation the path indexes in a proof correspond to the binary representation of the leaf index
        let mut binary_repr = self.get_path_index();
        binary_repr.reverse();
        binary_repr
            .into_iter()
            .fold(0, |acc, digit| (acc << 1) + usize::from(digit))
    }

    /// Returns the path elements forming a Merkle proof
    fn get_path_elements(&self) -> Vec<H::Fr> {
        self.0.iter().map(|x| x.0).collect()
    }

    /// Returns the path indexes forming a Merkle proof
    fn get_path_index(&self) -> Vec<u8> {
        self.0.iter().map(|x| x.1).collect()
    }

    /// Computes the Merkle root corresponding by iteratively hashing a Merkle proof with a given input leaf
    fn compute_root_from(&self, leaf: &H::Fr) -> H::Fr {
        let mut acc: H::Fr = *leaf;
        for w in self.0.iter() {
            if w.1 == 0 {
                acc = H::hash(&[acc, w.0]);
            } else {
                acc = H::hash(&[w.0, acc]);
            }
        }
        acc
    }
}

// Debug formatting for printing a (Optimal) Merkle Proof
impl<H> Debug for OptimalMerkleProof<H>
where
    H: Hasher,
    H::Fr: Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Proof").field(&self.0).finish()
    }
}
