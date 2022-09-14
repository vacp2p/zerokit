// This crate defines the RLN module default Merkle tree implementation and its Hasher

// Implementation inspired by https://github.com/worldcoin/semaphore-rs/blob/d462a4372f1fd9c27610f2acfe4841fab1d396aa/src/poseidon_tree.rs (no differences)

use crate::circuit::Fr;
use crate::merkle_tree::*;
use crate::poseidon_hash::poseidon_hash;

// The zerokit RLN default Merkle tree implementation.
// To switch to FullMerkleTree implementation it is enough to redefine the following two types
pub type PoseidonTree = OptimalMerkleTree<PoseidonHash>;
pub type MerkleProof = OptimalMerkleProof<PoseidonHash>;
//pub type PoseidonTree = FullMerkleTree<PoseidonHash>;
//pub type MerkleProof = FullMerkleProof<PoseidonHash>;

// The zerokit RLN default Hasher
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PoseidonHash;

impl Hasher for PoseidonHash {
    type Fr = Fr;

    fn default_leaf() -> Self::Fr {
        Self::Fr::from(0)
    }

    fn hash(inputs: &[Self::Fr]) -> Self::Fr {
        poseidon_hash(inputs)
    }
}

// Poseidon Hash wrapper over poseidon-rs implementation. Adapted from semaphore-rs poseidon hash wrapper.
// TODO: integrate poseidon hash in zerokit
static POSEIDON: Lazy<Poseidon> = Lazy::new(Poseidon::new);

pub fn poseidon_hash(input: &[Fr]) -> Fr {
    let input = input
        .iter()
        .copied()
        .map(|x| fr_to_posfr(x))
        .collect::<Vec<_>>();

    POSEIDON
        .hash(input)
        .map(|x| posfr_to_fr(x))
        .expect("hash with fixed input size can't fail")
}

////////////////////////////////////////////////////////////
/// Tests
////////////////////////////////////////////////////////////

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    /// A basic performance comparison between the two supported Merkle Tree implementations
    fn test_merkle_implementations_performances() {
        use std::time::{Duration, Instant};

        let tree_height = 20;
        let sample_size = 100;

        let leaves: Vec<Fr> = (0..sample_size).map(|s| Fr::from(s)).collect();

        let mut gen_time_full: u128 = 0;
        let mut upd_time_full: u128 = 0;
        let mut gen_time_opt: u128 = 0;
        let mut upd_time_opt: u128 = 0;

        for _ in 0..sample_size.try_into().unwrap() {
            let now = Instant::now();
            FullMerkleTree::<PoseidonHash>::default(tree_height);
            gen_time_full += now.elapsed().as_nanos();

            let now = Instant::now();
            OptimalMerkleTree::<PoseidonHash>::default(tree_height);
            gen_time_opt += now.elapsed().as_nanos();
        }

        let mut tree_full = FullMerkleTree::<PoseidonHash>::default(tree_height);
        let mut tree_opt = OptimalMerkleTree::<PoseidonHash>::default(tree_height);
        for i in 0..sample_size.try_into().unwrap() {
            let now = Instant::now();
            tree_full.set(i, leaves[i]).unwrap();
            upd_time_full += now.elapsed().as_nanos();
            let proof = tree_full.proof(i).expect("index should be set");
            assert_eq!(proof.leaf_index(), i);

            let now = Instant::now();
            tree_opt.set(i, leaves[i]).unwrap();
            upd_time_opt += now.elapsed().as_nanos();
            let proof = tree_opt.proof(i).expect("index should be set");
            assert_eq!(proof.leaf_index(), i);
        }

        println!("Average tree generation time:");
        println!(
            "   - Full Merkle Tree:  {:?}",
            Duration::from_nanos((gen_time_full / sample_size).try_into().unwrap())
        );
        println!(
            "   - Optimal Merkle Tree: {:?}",
            Duration::from_nanos((gen_time_opt / sample_size).try_into().unwrap())
        );

        println!("Average update_next execution time:");
        println!(
            "   - Full Merkle Tree: {:?}",
            Duration::from_nanos((upd_time_full / sample_size).try_into().unwrap())
        );

        println!(
            "   - Optimal Merkle Tree: {:?}",
            Duration::from_nanos((upd_time_opt / sample_size).try_into().unwrap())
        );
    }
}
