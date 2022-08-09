// Implementation taken from https://github.com/worldcoin/semaphore-rs/blob/d462a4372f1fd9c27610f2acfe4841fab1d396aa/src/poseidon_tree.rs (no differences)
// Implements Merkle trees with Poseidon hash for the customized semaphore-rs merkle_tree implementation

use crate::merkle_tree::{self, Hasher, MerkleTree};
use semaphore::{poseidon_hash, Field};

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PoseidonHash;

// Incremental Merkle tree
#[allow(dead_code)]
pub type PoseidonTree = MerkleTree<PoseidonHash>;

impl Hasher for PoseidonHash {
    type Fr = Field;

    fn default_leaf() -> Self::Fr {
        Self::Fr::from(0)
    }

    fn hash(inputs: &[Self::Fr]) -> Self::Fr {
        poseidon_hash(inputs)
    }
}

#[test]
fn test_merkle_performance() {
    use std::time::{Duration, Instant};

    let tree_height = 20;
    let sample_size = 10000;

    let leaves: Vec<Field> = (0..sample_size).map(|s| Field::from(s)).collect();

    let mut gen_time: u128 = 0;
    let mut upd_time: u128 = 0;

    for _ in 0..sample_size.try_into().unwrap() {
        let now = Instant::now();
        PoseidonTree::new(tree_height, Field::from(0));
        gen_time += now.elapsed().as_nanos();
    }

    let mut tree = PoseidonTree::new(tree_height, Field::from(0));
    for i in 0..sample_size.try_into().unwrap() {
        let now = Instant::now();
        tree.set(i, leaves[i]).unwrap();
        upd_time += now.elapsed().as_nanos();
        let proof = tree.proof(i).expect("index should be set");
        assert_eq!(proof.leaf_index(), i);
    }

    println!(
        "Average tree generation time: {:?}",
        Duration::from_nanos((gen_time / u128::from(sample_size)).try_into().unwrap())
    );

    println!(
        "Average update_next time: {:?}",
        Duration::from_nanos((upd_time / u128::from(sample_size)).try_into().unwrap())
    );
}
