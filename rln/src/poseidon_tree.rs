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

// #[cfg(feature = "pmtree-ft")]
use pmtree::*;
use crate::utils::{bytes_le_to_fr, fr_to_bytes_le};
use utils::OptimalMerkleTree;

// #[cfg(feature = "pmtree-ft")]
// The pmtree Hasher trait used by pmtree Merkle tree
impl pmtree::Hasher for PoseidonHash {
    type Fr = Fr;

    fn default_leaf() -> Self::Fr {
        Fr::from(0)
    }

    fn serialize(value: Self::Fr) -> Value {
        fr_to_bytes_le(&value)
    }

    fn deserialize(value: Value) -> Self::Fr {
        let (fr, _) = bytes_le_to_fr(&value);
        fr
    }

    fn hash(inputs: &[Self::Fr]) -> Self::Fr {
        poseidon_hash(inputs)
    }
}

