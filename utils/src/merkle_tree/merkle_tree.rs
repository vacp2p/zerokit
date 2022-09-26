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

#![allow(dead_code)]

use std::collections::HashMap;
use std::io;
use std::{
    cmp::max,
    fmt::Debug,
    iter::{once, repeat, successors},
};

/// In the Hasher trait we define the node type, the default leaf
/// and the hash function used to initialize a Merkle Tree implementation
pub trait Hasher {
    /// Type of the leaf and tree node
    type Fr: Copy + Clone + Eq;

    /// Returns the default tree leaf
    fn default_leaf() -> Self::Fr;

    /// Utility to compute the hash of an intermediate node
    fn hash(input: &[Self::Fr]) -> Self::Fr;
}

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
}

/// The Merkle proof
/// Contains a vector of (node, branch_index) that defines the proof path elements and branch direction (1 or 0)
#[derive(Clone, PartialEq, Eq)]
pub struct OptimalMerkleProof<H: Hasher>(pub Vec<(H::Fr, u8)>);

/// Implementations

impl<H: Hasher> OptimalMerkleTree<H> {
    pub fn default(depth: usize) -> Self {
        OptimalMerkleTree::<H>::new(depth, H::default_leaf())
    }

    /// Creates a new `MerkleTree`
    /// depth - the height of the tree made only of hash nodes. 2^depth is the maximum number of leaves hash nodes
    pub fn new(depth: usize, default_leaf: H::Fr) -> Self {
        let mut cached_nodes: Vec<H::Fr> = Vec::with_capacity(depth + 1);
        cached_nodes.push(default_leaf);
        for i in 0..depth {
            cached_nodes.push(H::hash(&[cached_nodes[i]; 2]));
        }
        cached_nodes.reverse();
        OptimalMerkleTree {
            cached_nodes: cached_nodes.clone(),
            depth: depth,
            nodes: HashMap::new(),
            next_index: 0,
        }
    }

    // Returns the depth of the tree
    pub fn depth(&self) -> usize {
        self.depth
    }

    // Returns the capacity of the tree, i.e. the maximum number of accumulatable leaves
    pub fn capacity(&self) -> usize {
        1 << self.depth
    }

    // Returns the total number of leaves set
    pub fn leaves_set(&mut self) -> usize {
        self.next_index
    }

    #[must_use]
    // Returns the root of the tree
    pub fn root(&self) -> H::Fr {
        self.get_node(0, 0)
    }

    // Sets a leaf at the specified tree index
    pub fn set(&mut self, index: usize, leaf: H::Fr) -> io::Result<()> {
        if index >= self.capacity() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "index exceeds set size",
            ));
        }
        self.nodes.insert((self.depth, index), leaf);
        self.recalculate_from(index);
        self.next_index = max(self.next_index, index + 1);
        Ok(())
    }

    // Sets a leaf at the next available index
    pub fn update_next(&mut self, leaf: H::Fr) -> io::Result<()> {
        self.set(self.next_index, leaf)?;
        Ok(())
    }

    // Deletes a leaf at a certain index by setting it to its default value (next_index is not updated)
    pub fn delete(&mut self, index: usize) -> io::Result<()> {
        // We reset the leaf only if we previously set a leaf at that index
        if index < self.next_index {
            self.set(index, H::default_leaf())?;
        }
        Ok(())
    }

    // Computes a merkle proof the the leaf at the specified index
    pub fn proof(&self, index: usize) -> io::Result<OptimalMerkleProof<H>> {
        if index >= self.capacity() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "index exceeds set size",
            ));
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
        assert_eq!(i, 0);
        Ok(OptimalMerkleProof(witness))
    }

    // Verifies a Merkle proof with respect to the input leaf and the tree root
    pub fn verify(&self, leaf: &H::Fr, witness: &OptimalMerkleProof<H>) -> io::Result<bool> {
        if witness.length() != self.depth {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "witness length doesn't match tree depth",
            ));
        }
        let expected_root = witness.compute_root_from(leaf);
        Ok(expected_root.eq(&self.root()))
    }

    // Utilities for updating the tree nodes

    fn get_node(&self, depth: usize, index: usize) -> H::Fr {
        let node = *self
            .nodes
            .get(&(depth, index))
            .unwrap_or_else(|| &self.cached_nodes[depth]);
        node
    }

    fn get_leaf(&self, index: usize) -> H::Fr {
        self.get_node(self.depth, index)
    }

    fn hash_couple(&mut self, depth: usize, index: usize) -> H::Fr {
        let b = index & !1;
        H::hash(&[self.get_node(depth, b), self.get_node(depth, b + 1)])
    }

    fn recalculate_from(&mut self, index: usize) {
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
        assert_eq!(depth, 0);
        assert_eq!(i, 0);
    }
}

impl<H: Hasher> OptimalMerkleProof<H> {
    #[must_use]
    // Returns the length of a Merkle proof
    pub fn length(&self) -> usize {
        self.0.len()
    }

    /// Computes the leaf index corresponding to a Merkle proof
    #[must_use]
    pub fn leaf_index(&self) -> usize {
        // In current implementation the path indexes in a proof correspond to the binary representation of the leaf index
        let mut binary_repr = self.get_path_index();
        binary_repr.reverse();
        binary_repr
            .into_iter()
            .fold(0, |acc, digit| (acc << 1) + usize::from(digit))
    }

    #[must_use]
    /// Returns the path elements forming a Merkle proof
    pub fn get_path_elements(&self) -> Vec<H::Fr> {
        self.0.iter().map(|x| x.0).collect()
    }

    /// Returns the path indexes forming a Merkle proof
    #[must_use]
    pub fn get_path_index(&self) -> Vec<u8> {
        self.0.iter().map(|x| x.1).collect()
    }

    #[must_use]
    /// Computes the Merkle root corresponding by iteratively hashing a Merkle proof with a given input leaf
    pub fn compute_root_from(&self, leaf: &H::Fr) -> H::Fr {
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

/// Implementations

impl<H: Hasher> FullMerkleTree<H> {
    pub fn default(depth: usize) -> Self {
        FullMerkleTree::<H>::new(depth, H::default_leaf())
    }

    /// Creates a new `MerkleTree`
    /// depth - the height of the tree made only of hash nodes. 2^depth is the maximum number of leaves hash nodes
    pub fn new(depth: usize, initial_leaf: H::Fr) -> Self {
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

        Self {
            depth,
            cached_nodes,
            nodes,
            next_index,
        }
    }

    // Returns the depth of the tree
    pub fn depth(&self) -> usize {
        self.depth
    }

    // Returns the capacity of the tree, i.e. the maximum number of accumulatable leaves
    pub fn capacity(&self) -> usize {
        1 << self.depth
    }

    // Returns the total number of leaves set
    pub fn leaves_set(&mut self) -> usize {
        self.next_index
    }

    #[must_use]
    // Returns the root of the tree
    pub fn root(&self) -> H::Fr {
        self.nodes[0]
    }

    // Sets a leaf at the specified tree index
    pub fn set(&mut self, leaf: usize, hash: H::Fr) -> io::Result<()> {
        self.set_range(leaf, once(hash))?;
        self.next_index = max(self.next_index, leaf + 1);
        Ok(())
    }

    // Sets tree nodes, starting from start index
    // Function proper of FullMerkleTree implementation
    fn set_range<I: IntoIterator<Item = H::Fr>>(
        &mut self,
        start: usize,
        hashes: I,
    ) -> io::Result<()> {
        let index = self.capacity() + start - 1;
        let mut count = 0;
        // TODO: Error/panic when hashes is longer than available leafs
        for (leaf, hash) in self.nodes[index..].iter_mut().zip(hashes) {
            *leaf = hash;
            count += 1;
        }
        if count != 0 {
            self.update_nodes(index, index + (count - 1));
            self.next_index = max(self.next_index, start + count);
        }
        Ok(())
    }

    // Sets a leaf at the next available index
    pub fn update_next(&mut self, leaf: H::Fr) -> io::Result<()> {
        self.set(self.next_index, leaf)?;
        Ok(())
    }

    // Deletes a leaf at a certain index by setting it to its default value (next_index is not updated)
    pub fn delete(&mut self, index: usize) -> io::Result<()> {
        // We reset the leaf only if we previously set a leaf at that index
        if index < self.next_index {
            self.set(index, H::default_leaf())?;
        }
        Ok(())
    }

    // Computes a merkle proof the the leaf at the specified index
    pub fn proof(&self, leaf: usize) -> io::Result<FullMerkleProof<H>> {
        if leaf >= self.capacity() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "index exceeds set size",
            ));
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
    pub fn verify(&self, hash: &H::Fr, proof: &FullMerkleProof<H>) -> io::Result<bool> {
        Ok(proof.compute_root_from(hash) == self.root())
    }

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

    fn update_nodes(&mut self, start: usize, end: usize) {
        debug_assert_eq!(self.levels(start), self.levels(end));
        if let (Some(start), Some(end)) = (self.parent(start), self.parent(end)) {
            for parent in start..=end {
                let child = self.first_child(parent);
                self.nodes[parent] = H::hash(&[self.nodes[child], self.nodes[child + 1]]);
            }
            self.update_nodes(start, end);
        }
    }
}

impl<H: Hasher> FullMerkleProof<H> {
    #[must_use]
    // Returns the length of a Merkle proof
    pub fn length(&self) -> usize {
        self.0.len()
    }

    /// Computes the leaf index corresponding to a Merkle proof
    #[must_use]
    pub fn leaf_index(&self) -> usize {
        self.0.iter().rev().fold(0, |index, branch| match branch {
            FullMerkleBranch::Left(_) => index << 1,
            FullMerkleBranch::Right(_) => (index << 1) + 1,
        })
    }

    #[must_use]
    /// Returns the path elements forming a Merkle proof
    pub fn get_path_elements(&self) -> Vec<H::Fr> {
        self.0
            .iter()
            .map(|x| match x {
                FullMerkleBranch::Left(value) | FullMerkleBranch::Right(value) => *value,
            })
            .collect()
    }

    /// Returns the path indexes forming a Merkle proof
    #[must_use]
    pub fn get_path_index(&self) -> Vec<u8> {
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
    pub fn compute_root_from(&self, hash: &H::Fr) -> H::Fr {
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

////////////////////////////////////////////////////////////
/// Tests
////////////////////////////////////////////////////////////

// Tests adapted from https://github.com/worldcoin/semaphore-rs/blob/d462a4372f1fd9c27610f2acfe4841fab1d396aa/src/merkle_tree.rs
#[cfg(test)]
mod test {
    use super::*;
    use hex_literal::hex;
    use tiny_keccak::{Hasher as _, Keccak};

    struct Keccak256;

    impl Hasher for Keccak256 {
        type Fr = [u8; 32];

        fn default_leaf() -> Self::Fr {
            [0; 32]
        }

        fn hash(inputs: &[Self::Fr]) -> Self::Fr {
            let mut output = [0; 32];
            let mut hasher = Keccak::v256();
            for element in inputs {
                hasher.update(element);
            }
            hasher.finalize(&mut output);
            output
        }
    }

    #[test]
    fn test_root() {
        let leaves = [
            hex!("0000000000000000000000000000000000000000000000000000000000000001"),
            hex!("0000000000000000000000000000000000000000000000000000000000000002"),
            hex!("0000000000000000000000000000000000000000000000000000000000000003"),
            hex!("0000000000000000000000000000000000000000000000000000000000000004"),
        ];

        let default_tree_root =
            hex!("b4c11951957c6f8f642c4af61cd6b24640fec6dc7fc607ee8206a99e92410d30");

        let roots = [
            hex!("c1ba1812ff680ce84c1d5b4f1087eeb08147a4d510f3496b2849df3a73f5af95"),
            hex!("893760ec5b5bee236f29e85aef64f17139c3c1b7ff24ce64eb6315fca0f2485b"),
            hex!("222ff5e0b5877792c2bc1670e2ccd0c2c97cd7bb1672a57d598db05092d3d72c"),
            hex!("a9bb8c3f1f12e9aa903a50c47f314b57610a3ab32f2d463293f58836def38d36"),
        ];

        let mut tree = FullMerkleTree::<Keccak256>::new(2, [0; 32]);
        assert_eq!(tree.root(), default_tree_root);
        for i in 0..leaves.len() {
            tree.set(i, leaves[i]).unwrap();
            assert_eq!(tree.root(), roots[i]);
        }

        let mut tree = OptimalMerkleTree::<Keccak256>::new(2, [0; 32]);
        assert_eq!(tree.root(), default_tree_root);
        for i in 0..leaves.len() {
            tree.set(i, leaves[i]).unwrap();
            assert_eq!(tree.root(), roots[i]);
        }
    }

    #[test]
    fn test_proof() {
        let leaves = [
            hex!("0000000000000000000000000000000000000000000000000000000000000001"),
            hex!("0000000000000000000000000000000000000000000000000000000000000002"),
            hex!("0000000000000000000000000000000000000000000000000000000000000003"),
            hex!("0000000000000000000000000000000000000000000000000000000000000004"),
        ];

        // We thest the FullMerkleTree implementation
        let mut tree = FullMerkleTree::<Keccak256>::new(2, [0; 32]);
        for i in 0..leaves.len() {
            // We set the leaves
            tree.set(i, leaves[i]).unwrap();

            // We compute a merkle proof
            let proof = tree.proof(i).expect("index should be set");

            // We verify if the merkle proof corresponds to the right leaf index
            assert_eq!(proof.leaf_index(), i);

            // We verify the proof
            assert!(tree.verify(&leaves[i], &proof).unwrap());

            // We ensure that the Merkle proof and the leaf generate the same root as the tree
            assert_eq!(proof.compute_root_from(&leaves[i]), tree.root());

            // We check that the proof is not valid for another leaf
            assert!(!tree
                .verify(&leaves[(i + 1) % leaves.len()], &proof)
                .unwrap());
        }

        // We test the OptimalMerkleTree implementation
        let mut tree = OptimalMerkleTree::<Keccak256>::new(2, [0; 32]);
        for i in 0..leaves.len() {
            // We set the leaves
            tree.set(i, leaves[i]).unwrap();

            // We compute a merkle proof
            let proof = tree.proof(i).expect("index should be set");

            // We verify if the merkle proof corresponds to the right leaf index
            assert_eq!(proof.leaf_index(), i);

            // We verify the proof
            assert!(tree.verify(&leaves[i], &proof).unwrap());

            // We ensure that the Merkle proof and the leaf generate the same root as the tree
            assert_eq!(proof.compute_root_from(&leaves[i]), tree.root());

            // We check that the proof is not valid for another leaf
            assert!(!tree
                .verify(&leaves[(i + 1) % leaves.len()], &proof)
                .unwrap());
        }
    }
}
