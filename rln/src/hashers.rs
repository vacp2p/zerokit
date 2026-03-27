// This crate instantiates the Poseidon hash algorithm.

use std::sync::LazyLock;

use num_bigint::BigUint;
use tiny_keccak::{Hasher, Keccak};
use zerokit_utils::poseidon::{Poseidon, PoseidonError};

use crate::circuit::Fr;

/// These indexed constants hardcode the supported round parameters tuples (t, RF, RN, SKIP_MATRICES) for the Bn254 scalar field.
/// SKIP_MATRICES is the index of the randomly generated secure MDS matrix.
/// TODO: generate these parameters
const ROUND_PARAMS: [(usize, usize, usize, usize); 8] = [
    (2, 8, 56, 0),
    (3, 8, 57, 0),
    (4, 8, 56, 0),
    (5, 8, 60, 0),
    (6, 8, 60, 0),
    (7, 8, 63, 0),
    (8, 8, 64, 0),
    (9, 8, 63, 0),
];

/// Poseidon Hash wrapper over above implementation.
static POSEIDON: LazyLock<Poseidon<Fr>> = LazyLock::new(|| Poseidon::<Fr>::from(&ROUND_PARAMS));

/// Hashes a list of field elements using Poseidon.
///
///
/// Panics if the input length does not match any of the supported round parameters.
pub fn poseidon_hash(input: &[Fr]) -> Fr {
    POSEIDON
        .hash(input)
        .expect("Input length must be valid with supported round parameters")
}

/// Hashes a list of field elements using Poseidon.
///
/// Return an error if the input length does not match any of the supported round parameters.
pub fn poseidon_hash_try_from(frs: &[Fr]) -> Result<Fr, PoseidonError> {
    let hash = POSEIDON.hash(frs)?;
    Ok(hash)
}

/// Hashes a pair of field elements using Poseidon.
///
/// No panic or error is expected since the supported round parameters include the case of two elements.
pub fn poseidon_hash_pair(fr1: Fr, fr2: Fr) -> Fr {
    POSEIDON
        .hash(&[fr1, fr2])
        .expect("Two element input must be valid with supported round parameters")
}

/// The zerokit RLN Merkle tree Hasher.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PoseidonHash;

/// The default Hasher trait used by Merkle tree implementation in utils.
impl zerokit_utils::merkle_tree::Hasher for PoseidonHash {
    type Fr = Fr;

    fn default_leaf() -> Self::Fr {
        Self::Fr::from(0)
    }

    fn hash_pair(left: Self::Fr, right: Self::Fr) -> Self::Fr {
        poseidon_hash_pair(left, right)
    }
}

/// Hashes arbitrary signal to the underlying prime field.
pub fn hash_to_field_le(signal: &[u8]) -> Fr {
    // We hash the input signal using Keccak256
    let mut hash = [0; 32];
    let mut hasher = Keccak::v256();
    hasher.update(signal);
    hasher.finalize(&mut hash);

    Fr::from(BigUint::from_bytes_le(&hash))
}

/// Hashes arbitrary signal to the underlying prime field.
pub fn hash_to_field_be(signal: &[u8]) -> Fr {
    // We hash the input signal using Keccak256
    let mut hash = [0; 32];
    let mut hasher = Keccak::v256();
    hasher.update(signal);
    hasher.finalize(&mut hash);
    hash.reverse();

    Fr::from(BigUint::from_bytes_be(&hash))
}
