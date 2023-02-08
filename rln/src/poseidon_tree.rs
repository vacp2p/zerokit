// This crate defines the RLN module default Merkle tree implementation and its Hasher

// Implementation inspired by https://github.com/worldcoin/semaphore-rs/blob/d462a4372f1fd9c27610f2acfe4841fab1d396aa/src/poseidon_tree.rs (no differences)

use crate::circuit::Fr;
use crate::poseidon_hash::poseidon_hash;
use cfg_if::cfg_if;
use utils::merkle_tree::*;

// The zerokit RLN default Merkle tree implementation is the OptimalMerkleTree.
// To switch to FullMerkleTree implementation, it is enough to enable the fullmerkletree feature

cfg_if! {
    if #[cfg(feature = "fullmerkletree")] {
        pub type PoseidonTree = FullMerkleTree<PoseidonHash>;
        pub type MerkleProof = FullMerkleProof<PoseidonHash>;
    } else {
        pub type PoseidonTree = OptimalMerkleTree<PoseidonHash>;
        pub type MerkleProof = OptimalMerkleProof<PoseidonHash>;
    }
}

// The zerokit RLN Merkle tree Hasher
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PoseidonHash;

// The default Hasher trait used by Merkle tree implementation in utils
impl utils::merkle_tree::Hasher for PoseidonHash {
    type Fr = Fr;

    fn default_leaf() -> Self::Fr {
        Self::Fr::from(0)
    }

    fn hash(inputs: &[Self::Fr]) -> Self::Fr {
        poseidon_hash(inputs)
    }
}
