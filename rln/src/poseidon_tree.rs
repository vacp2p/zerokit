// Implementation from https://github.com/worldcoin/semaphore-rs/blob/d462a4372f1fd9c27610f2acfe4841fab1d396aa/src/poseidon_tree.rs
use crate::merkle_tree::{self, Hasher, MerkleTree};
use semaphore::{Field, poseidon_hash};

use serde::{Deserialize, Serialize};


#[allow(dead_code)]
pub type PoseidonTree = MerkleTree<PoseidonHash>;
#[allow(dead_code)]
pub type Branch = merkle_tree::Branch<PoseidonHash>;
#[allow(dead_code)]
pub type Proof = merkle_tree::Proof<PoseidonHash>;

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PoseidonHash;

impl Hasher for PoseidonHash {
    type Hash = Field;

    fn hash_node(left: &Self::Hash, right: &Self::Hash) -> Self::Hash {
        poseidon_hash(&[*left, *right])
    }
}