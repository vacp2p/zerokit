// This crate instantiate the Poseidon hash algorithm

use crate::{circuit::Fr, utils::bytes_le_to_fr};
use once_cell::sync::Lazy;
use tiny_keccak::{Hasher, Keccak};
use utils::poseidon::Poseidon;

// These indexed constants hardcodes the supported round parameters tuples (t, RF, RN, SKIP_MATRICES) for the Bn254 scalar field
// SKIP_MATRICES is the index of the randomly generated secure MDS matrix. See security note in the zerokit_utils::poseidon::poseidon_constants crate on this.
// TODO: generate these parameters
pub const ROUND_PARAMS: [(usize, usize, usize, usize); 8] = [
    (2, 8, 56, 0),
    (3, 8, 57, 0),
    (4, 8, 56, 0),
    (5, 8, 60, 0),
    (6, 8, 60, 0),
    (7, 8, 63, 0),
    (8, 8, 64, 0),
    (9, 8, 63, 0),
];

// Poseidon Hash wrapper over above implementation. Adapted from semaphore-rs poseidon hash wrapper.
static POSEIDON: Lazy<Poseidon<Fr>> = Lazy::new(|| Poseidon::<Fr>::from(&ROUND_PARAMS));

pub fn poseidon_hash(input: &[Fr]) -> Fr {
    POSEIDON
        .hash(input.to_vec())
        .expect("hash with fixed input size can't fail")
}

// Hashes arbitrary signal to the underlying prime field
pub fn hash_to_field(signal: &[u8]) -> Fr {
    // We hash the input signal using Keccak256
    // (note that a bigger curve order might require a bigger hash blocksize)
    let mut hash = [0; 32];
    let mut hasher = Keccak::v256();
    hasher.update(signal);
    hasher.finalize(&mut hash);

    // We export the hash as a field element
    let (el, _) = bytes_le_to_fr(hash.as_ref());
    el
}
