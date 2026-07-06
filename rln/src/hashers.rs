// This module defines the hashing facade for the RLN module.

use std::{marker::PhantomData, sync::LazyLock};

use ark_ff::PrimeField;
use tiny_keccak::{Hasher as _, Keccak};
use zeroize::Zeroizing;
use zerokit_utils::{hasher::ZerokitHasher, poseidon::Poseidon};

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

/// The Poseidon instance over the Bn254 scalar field, parameterized by [`rln::hashers::ROUND_PARAMS`].
static POSEIDON: LazyLock<Poseidon<Fr>> = LazyLock::new(|| Poseidon::<Fr>::from(&ROUND_PARAMS));

/// The Poseidon hash function over the Bn254 scalar field.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PoseidonHash;

impl ZerokitHasher for PoseidonHash {
    type Fr = Fr;

    fn hash(input: &[Fr]) -> Fr {
        POSEIDON
            .hash(input)
            .expect("Input length must be valid with supported round parameters")
    }
}

/// The RLN hashing facade. All hashing in the crate goes through this one type.
///
/// For example, `Hasher::<PoseidonHash>::hash_pair(left, right)`.
pub struct Hasher<H: ZerokitHasher<Fr = Fr>>(PhantomData<H>);

impl<H: ZerokitHasher<Fr = Fr>> Hasher<H> {
    /// Hashes a single field element.
    pub fn hash_single(input: Fr) -> Fr {
        H::hash(&[input])
    }

    /// Hashes two field elements.
    pub fn hash_pair(left: Fr, right: Fr) -> Fr {
        H::hash(&[left, right])
    }

    /// Hashes a list of field elements.
    pub fn hash_list(input: &[Fr]) -> Fr {
        H::hash(input)
    }

    /// Computes the identity commitment `H(identity_secret)` from the identity secret.
    pub fn compute_id_commitment(secret: &SecretFr) -> Fr {
        let to_hash = Zeroizing::new([**secret]);
        H::hash(&*to_hash)
    }

    /// Computes the Shamir share slope `a_1 = H(identity_secret, external_nullifier, message_id)`.
    pub fn compute_share_slope(secret: &SecretFr, second: Fr, third: Fr) -> Fr {
        let to_hash = Zeroizing::new([**secret, second, third]);
        H::hash(&*to_hash)
    }

    /// Computes the identity secret `H(identity_trapdoor, identity_nullifier)` from the two source secrets.
    pub fn compute_identity_secret(left: &SecretFr, right: &SecretFr) -> SecretFr {
        let to_hash = Zeroizing::new([**left, **right]);
        let mut hashed = H::hash(&*to_hash);

        // SecretFr::from wipes the intermediate hash result after wrapping it
        SecretFr::from(&mut hashed)
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

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_facade_arities_match_concrete_poseidon() {
        let first = Fr::from(1);
        let second = Fr::from(2);
        let third = Fr::from(3);
        assert_eq!(
            Hasher::<PoseidonHash>::hash_single(first),
            PoseidonHash::hash(&[first])
        );
        assert_eq!(
            Hasher::<PoseidonHash>::hash_pair(first, second),
            PoseidonHash::hash(&[first, second])
        );
        assert_eq!(
            Hasher::<PoseidonHash>::hash_list(&[first, second, third]),
            PoseidonHash::hash(&[first, second, third])
        );
    }

    #[test]
    fn test_facade_secret_methods_match_concrete_poseidon() {
        let secret = SecretFr::from(&mut Fr::from(42));
        let other = SecretFr::from(&mut Fr::from(43));
        assert_eq!(
            Hasher::<PoseidonHash>::compute_id_commitment(&secret),
            PoseidonHash::hash(&[*secret])
        );
        assert_eq!(
            *Hasher::<PoseidonHash>::compute_identity_secret(&secret, &other),
            PoseidonHash::hash(&[*secret, *other])
        );
        assert_eq!(
            Hasher::<PoseidonHash>::compute_share_slope(&secret, Fr::from(5), Fr::from(6)),
            PoseidonHash::hash(&[*secret, Fr::from(5), Fr::from(6)])
        );
    }
}
