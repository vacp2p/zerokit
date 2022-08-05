// Implementation adapted from https://github.com/worldcoin/semaphore-rs/blob/d462a4372f1fd9c27610f2acfe4841fab1d396aa/src/merkle_tree.rs
// In our customization, we expand MerkleTree to have a next_index counter, so that we can add a public API to add leaves to the next available counter with no need to specify the index

//! Implements basic binary Merkle trees
//!
//! # To do
//!
//! * Disk based storage backend (using mmaped files should be easy)

use semaphore::Field;
use serde::{Deserialize, Serialize};
use std::{
    cmp::max,
    fmt::Debug,
    iter::{once, repeat, successors},
};

/// Hash types, values and algorithms for a Merkle tree
pub trait Hasher {
    /// Type of the leaf and node hashes
    type Hash: Copy + Clone + Eq + Serialize;

    /// Compute the hash of an intermediate node
    fn hash_node(left: &Self::Hash, right: &Self::Hash) -> Self::Hash;
}

/// Merkle tree with all leaf and intermediate hashes stored
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct MerkleTree<H: Hasher> {
    /// total number of levels of the tree, i.e. # of layers including pre-images layer of tree leaves
    levels: usize,

    /// Hash value of empty subtrees of given levels, starting at leaf level
    empty: Vec<H::Hash>,

    /// Hash values of tree nodes and leaves, breadth first order
    nodes: Vec<H::Hash>,

    // The next available (i.e., never used) tree index. Equivalently, the number of leaves added to the tree
    // (deletions leave next_index unchanged)
    pub next_index: usize,
}

/// Element of a Merkle proof
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Branch<H: Hasher> {
    /// Left branch taken, value is the right sibling hash.
    Left(H::Hash),

    /// Right branch taken, value is the left sibling hash.
    Right(H::Hash),
}

/// Merkle proof path, bottom to top.
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct Proof<H: Hasher>(pub Vec<Branch<H>>);

/// For a given node index, return the parent node index
/// Returns None if there is no parent (root node)
const fn parent(index: usize) -> Option<usize> {
    if index == 0 {
        None
    } else {
        Some(((index + 1) >> 1) - 1)
    }
}

/// For a given node index, return index of the first (left) child.
const fn first_child(index: usize) -> usize {
    (index << 1) + 1
}

const fn levels(index: usize) -> usize {
    // `n.next_power_of_two()` will return `n` iff `n` is a power of two.
    // The extra offset corrects this.
    (index + 2).next_power_of_two().trailing_zeros() as usize - 1
}

impl<H: Hasher> MerkleTree<H> {
    /// Creates a new `MerkleTree`
    /// tree_height - the height of the tree made only of hash nodes. 2^tree_height is the maximum number of leaves hash nodes
    pub fn new(tree_height: usize, initial_leaf: H::Hash) -> Self {
        // total number of levels of the tree, i.e. # of layers including pre-images layer of tree leaves, thus equal to tree_height+1
        let levels = tree_height + 1;
        // Compute empty node values, leaf to root
        let empty = successors(Some(initial_leaf), |prev| Some(H::hash_node(prev, prev)))
            .take(levels)
            .collect::<Vec<_>>();

        // Compute node values
        let nodes = empty
            .iter()
            .rev()
            .enumerate()
            .flat_map(|(levels, hash)| repeat(hash).take(1 << levels))
            .cloned()
            .collect::<Vec<_>>();
        debug_assert!(nodes.len() == (1 << levels) - 1);

        let next_index = 0;

        Self {
            levels,
            empty,
            nodes,
            next_index,
        }
    }

    #[must_use]
    pub fn num_leaves(&self) -> usize {
        self.levels
            .checked_sub(1)
            .map(|n| 1 << n)
            .unwrap_or_default()
    }

    #[must_use]
    pub fn root(&self) -> H::Hash {
        self.nodes[0]
    }

    pub fn set(&mut self, leaf: usize, hash: H::Hash) {
        self.set_range(leaf, once(hash));
        self.next_index = max(self.next_index, leaf + 1);
    }

    pub fn set_range<I: IntoIterator<Item = H::Hash>>(&mut self, start: usize, hashes: I) {
        let index = self.num_leaves() + start - 1;
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
    }

    fn update_nodes(&mut self, start: usize, end: usize) {
        debug_assert_eq!(levels(start), levels(end));
        if let (Some(start), Some(end)) = (parent(start), parent(end)) {
            for parent in start..=end {
                let child = first_child(parent);
                self.nodes[parent] = H::hash_node(&self.nodes[child], &self.nodes[child + 1]);
            }
            self.update_nodes(start, end);
        }
    }

    #[must_use]
    pub fn proof(&self, leaf: usize) -> Option<Proof<H>> {
        if leaf >= self.num_leaves() {
            return None;
        }
        let mut index = self.num_leaves() + leaf - 1;
        let mut path = Vec::with_capacity(self.levels);
        while let Some(parent) = parent(index) {
            // Add proof for node at index to parent
            path.push(match index & 1 {
                1 => Branch::Left(self.nodes[index + 1]),
                0 => Branch::Right(self.nodes[index - 1]),
                _ => unreachable!(),
            });
            index = parent;
        }
        Some(Proof(path))
    }

    #[must_use]
    pub fn verify(&self, hash: H::Hash, proof: &Proof<H>) -> bool {
        proof.root(hash) == self.root()
    }

    #[must_use]
    pub fn leaves(&self) -> &[H::Hash] {
        &self.nodes[(self.num_leaves() - 1)..]
    }
}

impl<H: Hasher> Proof<H> {
    /// Compute the leaf index for this proof
    #[must_use]
    pub fn leaf_index(&self) -> usize {
        self.0.iter().rev().fold(0, |index, branch| match branch {
            Branch::Left(_) => index << 1,
            Branch::Right(_) => (index << 1) + 1,
        })
    }

    #[must_use]
    pub fn get_path_elements(&self) -> Vec<H::Hash> {
        self.0
            .iter()
            .map(|x| match x {
                Branch::Left(value) | Branch::Right(value) => *value,
            })
            .collect()
    }

    /// Compute path index (TODO: do we want to keep this here?)
    #[must_use]
    pub fn get_path_index(&self) -> Vec<u8> {
        self.0
            .iter()
            .map(|branch| match branch {
                Branch::Left(_) => 0,
                Branch::Right(_) => 1,
            })
            .collect()
    }

    /// Compute the Merkle root given a leaf hash
    #[must_use]
    pub fn root(&self, hash: H::Hash) -> H::Hash {
        self.0.iter().fold(hash, |hash, branch| match branch {
            Branch::Left(sibling) => H::hash_node(&hash, sibling),
            Branch::Right(sibling) => H::hash_node(sibling, &hash),
        })
    }
}

impl<H> Debug for Branch<H>
where
    H: Hasher,
    H::Hash: Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Left(arg0) => f.debug_tuple("Left").field(arg0).finish(),
            Self::Right(arg0) => f.debug_tuple("Right").field(arg0).finish(),
        }
    }
}

impl<H> Debug for Proof<H>
where
    H: Hasher,
    H::Hash: Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Proof").field(&self.0).finish()
    }
}

#[cfg(test)]
pub mod test {
    use super::*;
    use hex_literal::hex;
    use tiny_keccak::{Hasher as _, Keccak};

    struct Keccak256;

    impl Hasher for Keccak256 {
        type Hash = [u8; 32];

        fn hash_node(left: &Self::Hash, right: &Self::Hash) -> Self::Hash {
            let mut output = [0; 32];
            let mut hasher = Keccak::v256();
            hasher.update(left);
            hasher.update(right);
            hasher.finalize(&mut output);
            output
        }
    }

    #[test]
    fn test_index_calculus() {
        assert_eq!(parent(0), None);
        assert_eq!(parent(1), Some(0));
        assert_eq!(parent(2), Some(0));
        assert_eq!(parent(3), Some(1));
        assert_eq!(parent(4), Some(1));
        assert_eq!(parent(5), Some(2));
        assert_eq!(parent(6), Some(2));
        assert_eq!(first_child(0), 1);
        assert_eq!(first_child(2), 5);
        assert_eq!(levels(0), 0);
        assert_eq!(levels(1), 1);
        assert_eq!(levels(2), 1);
        assert_eq!(levels(3), 2);
        assert_eq!(levels(6), 2);
    }

    #[test]
    fn test_root() {
        let mut tree = MerkleTree::<Keccak256>::new(2, [0; 32]);
        assert_eq!(
            tree.root(),
            hex!("b4c11951957c6f8f642c4af61cd6b24640fec6dc7fc607ee8206a99e92410d30")
        );
        tree.set(
            0,
            hex!("0000000000000000000000000000000000000000000000000000000000000001"),
        );
        assert_eq!(
            tree.root(),
            hex!("c1ba1812ff680ce84c1d5b4f1087eeb08147a4d510f3496b2849df3a73f5af95")
        );
        tree.set(
            1,
            hex!("0000000000000000000000000000000000000000000000000000000000000002"),
        );
        assert_eq!(
            tree.root(),
            hex!("893760ec5b5bee236f29e85aef64f17139c3c1b7ff24ce64eb6315fca0f2485b")
        );
        tree.set(
            2,
            hex!("0000000000000000000000000000000000000000000000000000000000000003"),
        );
        assert_eq!(
            tree.root(),
            hex!("222ff5e0b5877792c2bc1670e2ccd0c2c97cd7bb1672a57d598db05092d3d72c")
        );
        tree.set(
            3,
            hex!("0000000000000000000000000000000000000000000000000000000000000004"),
        );
        assert_eq!(
            tree.root(),
            hex!("a9bb8c3f1f12e9aa903a50c47f314b57610a3ab32f2d463293f58836def38d36")
        );
    }

    #[test]
    fn test_proof() {
        let mut tree = MerkleTree::<Keccak256>::new(2, [0; 32]);
        tree.set(
            0,
            hex!("0000000000000000000000000000000000000000000000000000000000000001"),
        );
        tree.set(
            1,
            hex!("0000000000000000000000000000000000000000000000000000000000000002"),
        );
        tree.set(
            2,
            hex!("0000000000000000000000000000000000000000000000000000000000000003"),
        );
        tree.set(
            3,
            hex!("0000000000000000000000000000000000000000000000000000000000000004"),
        );

        let proof = tree.proof(2).expect("proof should exist");
        assert_eq!(proof.leaf_index(), 2);
        assert!(tree.verify(
            hex!("0000000000000000000000000000000000000000000000000000000000000003"),
            &proof
        ));
        assert!(!tree.verify(
            hex!("0000000000000000000000000000000000000000000000000000000000000001"),
            &proof
        ));
    }

    #[test]
    fn test_position() {
        let mut tree = MerkleTree::<Keccak256>::new(2, [0; 32]);
        tree.set(
            0,
            hex!("0000000000000000000000000000000000000000000000000000000000000001"),
        );
        tree.set(
            1,
            hex!("0000000000000000000000000000000000000000000000000000000000000002"),
        );
        tree.set(
            2,
            hex!("0000000000000000000000000000000000000000000000000000000000000003"),
        );
        tree.set(
            3,
            hex!("0000000000000000000000000000000000000000000000000000000000000004"),
        );
    }
}
