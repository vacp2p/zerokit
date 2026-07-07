// This module instantiates the Poseidon hash algorithm.

use std::sync::LazyLock;

use ark_ff::PrimeField;
use tiny_keccak::{Hasher, Keccak};
use zeroize::Zeroize;
use zerokit_utils::poseidon::{Poseidon, PoseidonError};

use crate::circuit::{Fr, SecretFr};

/// TODO(backlog): Generate these parameters
/// These indexed constants hardcode the supported round parameters tuples (t, RF, RN, SKIP_MATRICES) for the Bn254 scalar field.
/// SKIP_MATRICES is the index of the randomly generated secure MDS matrix.
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
/// Panics if the input length does not match any of the supported round parameters.
pub fn poseidon_hash(input: &[Fr]) -> Fr {
    POSEIDON
        .hash(input)
        .expect("Input length must be valid with supported round parameters")
}

/// Hashes a pair of field elements using Poseidon.
///
/// No panic or error is expected since the supported round parameters include the case of two elements.
pub fn poseidon_hash_pair(fr1: Fr, fr2: Fr) -> Fr {
    POSEIDON
        .hash(&[fr1, fr2])
        .expect("Two element input must be valid with supported round parameters")
}

/// Hashes a list of field elements using Poseidon.
///
/// Return an error if the input length does not match any of the supported round parameters.
pub fn poseidon_hash_list(frs: &[Fr]) -> Result<Fr, PoseidonError> {
    let hash = POSEIDON.hash(frs)?;
    Ok(hash)
}

/// Computes the Poseidon hash of identity secret into a identity commitment.
///
/// The internal copy of the secret is zeroized after hashing.
pub(crate) fn poseidon_hash_id_secret(secret: &SecretFr) -> Fr {
    let mut to_hash = [**secret];
    let id_commitment = poseidon_hash(&to_hash);
    to_hash[0].zeroize(); // wipe the secret copy from the stack buffer
    id_commitment
}

/// Computes the Poseidon hash of a pair of secret field elements into a new secret.
///
/// The internal copies of the secrets are zeroized after hashing.
pub(crate) fn poseidon_hash_secret_pair(secret1: &SecretFr, secret2: &SecretFr) -> SecretFr {
    let mut to_hash = [**secret1, **secret2];
    let mut hashed = poseidon_hash(&to_hash);
    to_hash.zeroize(); // wipe the secret copies from the stack buffer

    // SecretFr::from wipes the intermediate hash result after wrapping it
    SecretFr::from(&mut hashed)
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

    Fr::from_le_bytes_mod_order(&hash)
}

/// Hashes arbitrary signal to the underlying prime field.
pub fn hash_to_field_be(signal: &[u8]) -> Fr {
    // We hash the input signal using Keccak256
    let mut hash = [0; 32];
    let mut hasher = Keccak::v256();
    hasher.update(signal);
    hasher.finalize(&mut hash);

    Fr::from_be_bytes_mod_order(&hash)
}
