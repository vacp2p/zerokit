use crate::{merkle_tree::{FrOf, Hasher, ZerokitMerkleProof, ZerokitMerkleTree}, merkle_tree::Batch};
use color_eyre::{Report, Result};
use std::{
    cmp::max,
    fmt::Debug,
    iter::{repeat, successors},
    str::FromStr, collections::HashMap,
};

////////////////////////////////////////////////////////////
/// Full Merkle Tree Implementation
////////////////////////////////////////////////////////////

/// Merkle tree with all leaf and intermediate hashes stored
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct FullMerkleTree<H: Hasher> {
    /// The depth of the tree, i.e. the number of levels from leaf to root
    depth: usize,

    /// The nodes cached from the empty part of the tree (where leaves are set to default).
    /// Since the rightmost part of the tree is usually changed much later than its creation,
    /// we can prove accumulation of elements in the leftmost part, with no need to initialize the full tree
    /// and by caching few intermediate nodes to the root computed from default leaves
    cached_nodes: Vec<H::Fr>,

    /// The tree nodes
    nodes: Vec<H::Fr>,

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

impl<H> Batch<H> for HashMap<usize, FrOf<H>>
where
    H: Hasher,
{
    type Key = usize;

    fn insert(&mut self, key: usize, value: FrOf<H>) {
        self.insert(key, value);
    }

    fn remove(&mut self, key: usize) {
        self.remove(&key);
    }

    fn max_index(&self) -> usize {
        *self.keys().max().unwrap_or(&0)
    }

    fn min_index(&self) -> usize {
        *self.keys().min().unwrap_or(&0)
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
    type Batch = HashMap<usize, FrOf<Self::Hasher>>;

    fn default(depth: usize) -> Result<Self> {
        FullMerkleTree::<H>::new(depth, Self::Hasher::default_leaf(), Self::Config::default())
    }

    /// Creates a new `MerkleTree`
    /// depth - the height of the tree made only of hash nodes. 2^depth is the maximum number of leaves hash nodes
    fn new(depth: usize, initial_leaf: FrOf<Self::Hasher>, _config: Self::Config) -> Result<Self> {
        // Compute cache node values, leaf to root
        let cached_nodes = successors(Some(initial_leaf), |prev| Some(H::hash(&[*prev, *prev])))
            .take(depth + 1)
            .collect::<Vec<_>>();

        // Compute node values
        let nodes = cached_nodes
            .iter()
            .rev()
            .enumerate()
            .flat_map(|(levels, hash)| repeat(hash).take(1 << levels))
            .cloned()
            .collect::<Vec<_>>();
        debug_assert!(nodes.len() == (1 << (depth + 1)) - 1);

        let next_index = 0;

        Ok(Self {
            depth,
            cached_nodes,
            nodes,
            next_index,
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
    fn leaves_set(&mut self) -> usize {
        self.next_index
    }

    #[must_use]
    // Returns the root of the tree
    fn root(&self) -> FrOf<Self::Hasher> {
        self.nodes[0]
    }

    // Sets a leaf at the specified tree index
    fn set(&mut self, leaf: usize, hash: FrOf<Self::Hasher>) -> Result<()> {
        if leaf >= self.capacity() {
            return Err(Report::msg("leaf index out of bounds"));
        }
        let capacity = self.capacity();
        self.nodes[capacity + leaf - 1] = hash;
        self.update_nodes(capacity + leaf - 1, capacity + leaf - 1)?;
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

    // Sets tree nodes, starting from start index
    // Function proper of FullMerkleTree implementation
    fn set_range(
        &mut self,
        batch: &Self::Batch,
    ) -> Result<()> {
        // first count number of hashes, and check that they fit in the tree
        // then insert into the tree
        if batch.len() > self.capacity() {
            return Err(Report::msg("provided hashes do not fit in the tree"));
        }

        for (key, value) in batch {
            self.set(*key, *value)?;
        }
        Ok(())
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
        }
        Ok(())
    }

    // Computes a merkle proof the the leaf at the specified index
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

    fn update_nodes(&mut self, start: usize, end: usize) -> Result<()> {
        if self.levels(start) != self.levels(end) {
            return Err(Report::msg("self.levels(start) != self.levels(end)"));
        }
        if let (Some(start), Some(end)) = (self.parent(start), self.parent(end)) {
            for parent in start..=end {
                let child = self.first_child(parent);
                self.nodes[parent] = H::hash(&[self.nodes[child], self.nodes[child + 1]]);
            }
            self.update_nodes(start, end)?;
        }
        Ok(())
    }
}

impl<H: Hasher> ZerokitMerkleProof for FullMerkleProof<H> {
    type Index = u8;
    type Hasher = H;

    #[must_use]
    // Returns the length of a Merkle proof
    fn length(&self) -> usize {
        self.0.len()
    }

    /// Computes the leaf index corresponding to a Merkle proof
    #[must_use]
    fn leaf_index(&self) -> usize {
        self.0.iter().rev().fold(0, |index, branch| match branch {
            FullMerkleBranch::Left(_) => index << 1,
            FullMerkleBranch::Right(_) => (index << 1) + 1,
        })
    }

    #[must_use]
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
    #[must_use]
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
    #[must_use]
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
