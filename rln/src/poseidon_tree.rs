// This crate defines RLN module default Merkle tree implementation and Hasher
// Implementation inspired by https://github.com/worldcoin/semaphore-rs/blob/d462a4372f1fd9c27610f2acfe4841fab1d396aa/src/poseidon_tree.rs (no differences)

use semaphore::Field;
use serde::{Deserialize, Serialize};

use crate::merkle_tree::*;

////////////////////////////////////////////////////////////////////////////////////////////
// This is temporary to allow progressive switch to arkworks Fr only arithmetic
////////////////////////////////////////////////////////////////////////////////////////////
use crate::circuit::Fr;
use crate::utils::*;
use ark_ff::{BigInteger as _, PrimeField as _};
use ff::{PrimeField as _, PrimeFieldRepr as _};
use once_cell::sync::Lazy;
use poseidon_rs::{Fr as PosFr, Poseidon};

static POSEIDON: Lazy<Poseidon> = Lazy::new(Poseidon::new);

fn fr_to_posfr(value: Fr) -> PosFr {
    let mut bytes = [0_u8; 32];
    let byte_vec = value.into_repr().to_bytes_be();
    bytes.copy_from_slice(&byte_vec[..]);
    let mut repr = <PosFr as ff::PrimeField>::Repr::default();
    repr.read_be(&bytes[..])
        .expect("read from correctly sized slice always succeeds");
    PosFr::from_repr(repr).expect("value is always in range")
}

fn posfr_to_fr(value: PosFr) -> Fr {
    let mut bytes = [0u8; 32];
    value
        .into_repr()
        .write_be(&mut bytes[..])
        .expect("write to correctly sized slice always succeeds");
    Fr::from_be_bytes_mod_order(&bytes)
}

pub fn poseidon_hash(input: &[Field]) -> Field {
    let input = input
        .iter()
        .copied()
        .map(|x| fr_to_posfr(to_fr(&x)))
        .collect::<Vec<_>>();

    POSEIDON
        .hash(input)
        .map(|x| to_field(&posfr_to_fr(x)))
        .expect("hash with fixed input size can't fail")
}
////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////

// The zerokit RLN default Merkle tree implementation.
// To switch to FullMerkleTree implementation it is enough to redefine the following two types
pub type PoseidonTree = OptimalMerkleTree<PoseidonHash>;
pub type MerkleProof = OptimalMerkleProof<PoseidonHash>;
//pub type PoseidonTree = FullMerkleTree<PoseidonHash>;
//pub type MerkleProof = FullMerkleProof<PoseidonHash>;

// The zerokit RLN default Hasher
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PoseidonHash;

impl Hasher for PoseidonHash {
    type Fr = Field;

    fn default_leaf() -> Self::Fr {
        Self::Fr::from(0)
    }

    fn hash(inputs: &[Self::Fr]) -> Self::Fr {
        poseidon_hash(inputs)
    }
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

        let leaves: Vec<Field> = (0..sample_size).map(|s| Field::from(s)).collect();

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
            Duration::from_nanos(
                (gen_time_full / u128::from(sample_size))
                    .try_into()
                    .unwrap()
            )
        );
        println!(
            "   - Optimal Merkle Tree: {:?}",
            Duration::from_nanos((gen_time_opt / u128::from(sample_size)).try_into().unwrap())
        );

        println!("Average update_next execution time:");
        println!(
            "   - Full Merkle Tree: {:?}",
            Duration::from_nanos(
                (upd_time_full / u128::from(sample_size))
                    .try_into()
                    .unwrap()
            )
        );

        println!(
            "   - Optimal Merkle Tree: {:?}",
            Duration::from_nanos((upd_time_opt / u128::from(sample_size)).try_into().unwrap())
        );
    }
}
