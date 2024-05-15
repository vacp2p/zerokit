use crate::merkle_tree::{Hasher, ZerokitMerkleProof, ZerokitMerkleTree};
use crate::FrOf;
use color_eyre::{Report, Result};
use std::collections::HashMap;
use std::str::FromStr;
use std::{cmp::max, fmt::Debug};

////////////////////////////////////////////////////////////
/// Optimal Merkle Tree Implementation
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

    // The next available (i.e., never used) tree index. Equivalently, the number of leaves added to the tree
    // (deletions leave next_index unchanged)
    next_index: usize,

    // metadata that an application may use to store additional information
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
        let mut cached_nodes: Vec<H::Fr> = Vec::with_capacity(depth + 1);
        cached_nodes.push(default_leaf);
        for i in 0..depth {
            cached_nodes.push(H::hash(&[cached_nodes[i]; 2]));
        }
        cached_nodes.reverse();
        Ok(OptimalMerkleTree {
            cached_nodes: cached_nodes.clone(),
            depth,
            nodes: HashMap::new(),
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
    fn leaves_set(&mut self) -> usize {
        self.next_index
    }

    #[must_use]
    // Returns the root of the tree
    fn root(&self) -> H::Fr {
        self.get_node(0, 0)
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
            Ok(self.get_node(n, index >> (self.depth - n)))
        }
    }

    // Sets a leaf at the specified tree index
    fn set(&mut self, index: usize, leaf: H::Fr) -> Result<()> {
        if index >= self.capacity() {
            return Err(Report::msg("index exceeds set size"));
        }
        self.nodes.insert((self.depth, index), leaf);
        self.recalculate_from(index)?;
        self.next_index = max(self.next_index, index + 1);
        Ok(())
    }

    // Get a leaf from the specified tree index
    fn get(&self, index: usize) -> Result<H::Fr> {
        if index >= self.capacity() {
            return Err(Report::msg("index exceeds set size"));
        }
        Ok(self.get_node(self.depth, index))
    }

    // Sets multiple leaves from the specified tree index
    fn set_range<I: IntoIterator<Item = H::Fr>>(&mut self, start: usize, leaves: I) -> Result<()> {
        let leaves = leaves.into_iter().collect::<Vec<_>>();
        // check if the range is valid
        if start + leaves.len() > self.capacity() {
            return Err(Report::msg("provided range exceeds set size"));
        }
        for (i, leaf) in leaves.iter().enumerate() {
            self.nodes.insert((self.depth, start + i), *leaf);
            self.recalculate_from(start + i)?;
        }
        self.next_index = max(self.next_index, start + leaves.len());
        Ok(())
    }

    fn override_range<I, J>(&mut self, start: usize, leaves: I, to_remove_indices: J) -> Result<()>
    where
        I: IntoIterator<Item = FrOf<Self::Hasher>>,
        J: IntoIterator<Item = usize>,
    {
        let leaves = leaves.into_iter().collect::<Vec<_>>();
        let to_remove_indices = to_remove_indices.into_iter().collect::<Vec<_>>();
        // check if the range is valid
        if leaves.len() + start - to_remove_indices.len() > self.capacity() {
            return Err(Report::msg("provided range exceeds set size"));
        }

        // remove leaves
        for i in &to_remove_indices {
            self.delete(*i)?;
        }

        // add leaves
        for (i, leaf) in leaves.iter().enumerate() {
            self.nodes.insert((self.depth, start + i), *leaf);
            self.recalculate_from(start + i)?;
        }

        self.next_index = max(
            self.next_index,
            start + leaves.len() - to_remove_indices.len(),
        );
        Ok(())
    }

    // Sets a leaf at the next available index
    fn update_next(&mut self, leaf: H::Fr) -> Result<()> {
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
    fn proof(&self, index: usize) -> Result<Self::Proof> {
        if index >= self.capacity() {
            return Err(Report::msg("index exceeds set size"));
        }
        let mut witness = Vec::<(H::Fr, u8)>::with_capacity(self.depth);
        let mut i = index;
        let mut depth = self.depth;
        loop {
            i ^= 1;
            witness.push((self.get_node(depth, i), (1 - (i & 1)).try_into().unwrap()));
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

    // Verifies a Merkle proof with respect to the input leaf and the tree root
    fn verify(&self, leaf: &H::Fr, witness: &Self::Proof) -> Result<bool> {
        if witness.length() != self.depth {
            return Err(Report::msg("witness length doesn't match tree depth"));
        }
        let expected_root = witness.compute_root_from(leaf);
        Ok(expected_root.eq(&self.root()))
    }

    fn compute_root(&mut self) -> Result<FrOf<Self::Hasher>> {
        self.recalculate_from(0)?;
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

impl<H: Hasher> OptimalMerkleTree<H>
where
    H: Hasher,
{
    // Utilities for updating the tree nodes

    fn get_node(&self, depth: usize, index: usize) -> H::Fr {
        let node = *self
            .nodes
            .get(&(depth, index))
            .unwrap_or_else(|| &self.cached_nodes[depth]);
        node
    }

    pub fn get_leaf(&self, index: usize) -> H::Fr {
        self.get_node(self.depth, index)
    }

    fn hash_couple(&mut self, depth: usize, index: usize) -> H::Fr {
        let b = index & !1;
        H::hash(&[self.get_node(depth, b), self.get_node(depth, b + 1)])
    }

    fn recalculate_from(&mut self, index: usize) -> Result<()> {
        let mut i = index;
        let mut depth = self.depth;
        loop {
            let h = self.hash_couple(depth, i);
            i >>= 1;
            depth -= 1;
            self.nodes.insert((depth, i), h);
            if depth == 0 {
                break;
            }
        }
        if depth != 0 {
            return Err(Report::msg("did not reach the depth"));
        }
        if i != 0 {
            return Err(Report::msg("did not go through all indexes"));
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

    #[must_use]
    // Returns the length of a Merkle proof
    fn length(&self) -> usize {
        self.0.len()
    }

    /// Computes the leaf index corresponding to a Merkle proof
    #[must_use]
    fn leaf_index(&self) -> usize {
        // In current implementation the path indexes in a proof correspond to the binary representation of the leaf index
        let mut binary_repr = self.get_path_index();
        binary_repr.reverse();
        binary_repr
            .into_iter()
            .fold(0, |acc, digit| (acc << 1) + usize::from(digit))
    }

    #[must_use]
    /// Returns the path elements forming a Merkle proof
    fn get_path_elements(&self) -> Vec<H::Fr> {
        self.0.iter().map(|x| x.0).collect()
    }

    /// Returns the path indexes forming a Merkle proof
    #[must_use]
    fn get_path_index(&self) -> Vec<u8> {
        self.0.iter().map(|x| x.1).collect()
    }

    #[must_use]
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
