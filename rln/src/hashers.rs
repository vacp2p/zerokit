// This module defines the hashing facade for the RLN module.

use std::{marker::PhantomData, sync::LazyLock};

use ark_ff::PrimeField;
use tiny_keccak::{Hasher as _, Keccak};
use zerokit_utils::{hasher::ZerokitHasher, poseidon::Poseidon};

use crate::circuit::Fr;

// TODO(backlog): Generate these parameters

/// These indexed constants hardcode the supported round parameters tuples
/// (t, RF, RN, SKIP_MATRICES) for the Bn254 scalar field.
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

/// The Poseidon instance over the Bn254 scalar field, parameterized by [`ROUND_PARAMS`].
static POSEIDON: LazyLock<Poseidon<Fr>> = LazyLock::new(|| Poseidon::from(&ROUND_PARAMS));

/// The Poseidon hash function over the Bn254 scalar field.
#[derive(Clone, Copy, PartialEq)]
pub struct PoseidonHash;

impl ZerokitHasher for PoseidonHash {
    type Scalar = Fr;

    fn hash(input: &[Fr]) -> Fr {
        POSEIDON
            .hash(input)
            .expect("Input length must be valid with supported round parameters")
    }
}

/// The RLN hashing facade. All hashing in the crate goes through this one type.
///
/// For example, `Hasher::<PoseidonHash>::hash_pair(left, right)`.
pub struct Hasher<H>(PhantomData<H>);

impl<H> Hasher<H>
where
    H: ZerokitHasher<Scalar = Fr>,
{
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
}

/// Hashes an arbitrary-length signal to the prime field.
/// Keccak-256 digest reduced little-endian modulo the field order.
///
/// Keccak-256 is used because this mapping runs outside the circuit: the circuit only
/// consumes the resulting field elements (signal `x`, `epoch`, `rln_identifier`).
pub fn hash_to_field_le(signal: &[u8]) -> Fr {
    let mut hash = [0; 32];
    let mut hasher = Keccak::v256();
    hasher.update(signal);
    hasher.finalize(&mut hash);

    Fr::from_le_bytes_mod_order(&hash)
}

/// Hashes an arbitrary-length signal to the prime field.
/// Keccak-256 digest reduced big-endian modulo the field order.
///
/// Keccak-256 is used because this mapping runs outside the circuit: the circuit only
/// consumes the resulting field elements (signal `x`, `epoch`, `rln_identifier`).
pub fn hash_to_field_be(signal: &[u8]) -> Fr {
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
}
