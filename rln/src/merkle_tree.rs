// Implementation adapted from https://github.com/kilic/rln/blob/master/src/merkle.rs
// and https://github.com/worldcoin/semaphore-rs/blob/d462a4372f1fd9c27610f2acfe4841fab1d396aa/src/merkle_tree.rs

use ark_std::str::FromStr;
use serde::{Deserialize, Serialize};
use std::cmp::max;
use std::fmt::Debug;
use std::io::{self, Error, ErrorKind};
use std::{collections::HashMap, hash::Hash};

/// Hash types, values and algorithms for a Merkle tree
pub trait Hasher {
    /// Type of the leaf and node hashes
    type Fr: Copy + Clone + Eq + Serialize;

    /// Return the default Fr element
    fn default_leaf() -> Self::Fr;

    /// Compute the hash of an intermediate node
    fn hash(input: &[Self::Fr]) -> Self::Fr;
}

/// The Merkle tree structure
pub struct MerkleTree<H>
where
    H: Hasher,
{
    pub depth: usize,
    cached_nodes: Vec<H::Fr>,
    nodes: HashMap<(usize, usize), H::Fr>,
    pub next_index: usize,
}

/// The Merkle proof
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct MerkleProof<H: Hasher>(pub Vec<(H::Fr, u8)>);

impl<H> MerkleTree<H>
where
    H: Hasher,
{
    pub fn new(depth: usize, default_leaf: H::Fr) -> Self {
        let mut cached_nodes: Vec<H::Fr> = Vec::with_capacity(depth + 1);
        cached_nodes.push(default_leaf);
        for i in 0..depth {
            cached_nodes.push(H::hash(&[cached_nodes[i]; 2]));
        }
        cached_nodes.reverse();
        MerkleTree {
            cached_nodes: cached_nodes.clone(),
            depth,
            nodes: HashMap::new(),
            next_index: 0,
        }
    }

    pub fn tree_size(&self) -> usize {
        1 << self.depth
    }

    pub fn root(&self) -> H::Fr {
        self.get_node(0, 0)
    }

    pub fn set(&mut self, index: usize, leaf: H::Fr) -> io::Result<()> {
        if index >= self.tree_size() {
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

    pub fn update_next(&mut self, leaf: H::Fr) -> io::Result<()> {
        self.set(self.next_index, leaf)?;
        Ok(())
    }

    pub fn delete(&mut self, index: usize) -> io::Result<()> {
        let leaf = H::default_leaf();
        self.set(index, leaf)?;
        Ok(())
    }

    pub fn proof(&self, index: usize) -> io::Result<MerkleProof<H>> {
        if index >= self.tree_size() {
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
        Ok(MerkleProof(witness))
    }

    pub fn verify(&self, leaf: &H::Fr, witness: &MerkleProof<H>) -> io::Result<bool> {
        if witness.length() != self.depth {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "witness length doesn't match tree depth",
            ));
        }
        let mut acc = *leaf;

        for w in witness.0.iter() {
            if w.1 == 0 {
                acc = H::hash(&[acc, w.0]);
            } else {
                acc = H::hash(&[w.0, acc]);
            }
        }
        Ok(acc.eq(&self.root()))
    }

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

impl<H: Hasher> MerkleProof<H> {
    #[must_use]
    pub fn length(&self) -> usize {
        self.0.len()
    }

    #[must_use]
    pub fn get_path_elements(&self) -> Vec<H::Fr> {
        self.0.iter().map(|x| x.0).collect()
    }

    /// Compute path index (TODO: do we want to keep this here?)
    #[must_use]
    pub fn get_path_index(&self) -> Vec<u8> {
        self.0.iter().map(|x| x.1).collect()
    }

    pub fn leaf_index(&self) -> usize {
        // In current implementation the path indexes in a proof correspond to the binary representation of the leaf index
        let mut binary_repr = self.get_path_index();
        binary_repr.reverse();
        binary_repr
            .into_iter()
            .fold(0, |acc, digit| (acc << 1) + usize::from(digit))
    }

    #[must_use]
    pub fn root(&self, leaf: &H::Fr) -> H::Fr {
        let mut acc: H::Fr = *leaf;
        for w in self.0.iter() {
            if w.1 == 1 {
                acc = H::hash(&[acc, w.0]);
            } else {
                acc = H::hash(&[w.0, acc]);
            }
        }
        acc
    }
}

impl<H> Debug for MerkleProof<H>
where
    H: Hasher,
    H::Fr: Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Proof").field(&self.0).finish()
    }
}

// Tests from https://github.com/worldcoin/semaphore-rs/blob/d462a4372f1fd9c27610f2acfe4841fab1d396aa/src/merkle_tree.rs
pub mod test {
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
        let mut tree = MerkleTree::<Keccak256>::new(2, [0; 32]);
        assert_eq!(
            tree.root(),
            hex!("b4c11951957c6f8f642c4af61cd6b24640fec6dc7fc607ee8206a99e92410d30")
        );
        tree.set(
            0,
            hex!("0000000000000000000000000000000000000000000000000000000000000001"),
        )
        .unwrap();
        assert_eq!(
            tree.root(),
            hex!("c1ba1812ff680ce84c1d5b4f1087eeb08147a4d510f3496b2849df3a73f5af95")
        );
        tree.set(
            1,
            hex!("0000000000000000000000000000000000000000000000000000000000000002"),
        )
        .unwrap();
        assert_eq!(
            tree.root(),
            hex!("893760ec5b5bee236f29e85aef64f17139c3c1b7ff24ce64eb6315fca0f2485b")
        );
        tree.set(
            2,
            hex!("0000000000000000000000000000000000000000000000000000000000000003"),
        )
        .unwrap();
        assert_eq!(
            tree.root(),
            hex!("222ff5e0b5877792c2bc1670e2ccd0c2c97cd7bb1672a57d598db05092d3d72c")
        );
        tree.set(
            3,
            hex!("0000000000000000000000000000000000000000000000000000000000000004"),
        )
        .unwrap();
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
        )
        .unwrap();
        tree.set(
            1,
            hex!("0000000000000000000000000000000000000000000000000000000000000002"),
        )
        .unwrap();
        tree.set(
            2,
            hex!("0000000000000000000000000000000000000000000000000000000000000003"),
        )
        .unwrap();
        tree.set(
            3,
            hex!("0000000000000000000000000000000000000000000000000000000000000004"),
        )
        .unwrap();

        let proof = tree.proof(2).expect("index should be set");
        println!("path {:#?}", proof.get_path_index());
        assert_eq!(proof.leaf_index(), 2);
        assert!(tree
            .verify(
                &hex!("0000000000000000000000000000000000000000000000000000000000000003"),
                &proof
            )
            .unwrap());
        assert!(!tree
            .verify(
                &hex!("0000000000000000000000000000000000000000000000000000000000000001"),
                &proof
            )
            .unwrap());
    }

    #[test]
    fn test_position() {
        let mut tree = MerkleTree::<Keccak256>::new(2, [0; 32]);
        tree.set(
            0,
            hex!("0000000000000000000000000000000000000000000000000000000000000001"),
        )
        .unwrap();
        tree.set(
            1,
            hex!("0000000000000000000000000000000000000000000000000000000000000002"),
        )
        .unwrap();
        tree.set(
            2,
            hex!("0000000000000000000000000000000000000000000000000000000000000003"),
        )
        .unwrap();
        tree.set(
            3,
            hex!("0000000000000000000000000000000000000000000000000000000000000004"),
        )
        .unwrap();
    }
}
