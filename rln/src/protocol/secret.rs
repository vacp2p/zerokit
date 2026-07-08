// This module defines the protocol computations that take secret inputs.
//
// They are free functions (not methods on the `Hasher` facade) so the hashing layer stays
// hash-only, and every stack copy of a secret is wiped in this one audited place.

use zeroize::Zeroizing;
use zerokit_utils::hasher::ZerokitHasher;

use crate::circuit::{Fr, SecretFr};

/// Computes the identity commitment `H(identity_secret)` from the identity secret.
pub(crate) fn compute_id_commitment<H: ZerokitHasher<Scalar = Fr>>(
    identity_secret: &SecretFr,
) -> Fr {
    let to_hash = Zeroizing::new([**identity_secret]);
    H::hash(&*to_hash)
}

/// Computes the Shamir share slope `a_1 = H(identity_secret, external_nullifier, message_id)`.
pub(crate) fn compute_share_slope<H: ZerokitHasher<Scalar = Fr>>(
    identity_secret: &SecretFr,
    external_nullifier: Fr,
    message_id: Fr,
) -> Fr {
    let to_hash = Zeroizing::new([**identity_secret, external_nullifier, message_id]);
    H::hash(&*to_hash)
}

/// Computes the identity secret `H(identity_trapdoor, identity_nullifier)` from the two source
/// secrets.
pub(crate) fn compute_identity_secret<H: ZerokitHasher<Scalar = Fr>>(
    identity_trapdoor: &SecretFr,
    identity_nullifier: &SecretFr,
) -> SecretFr {
    let to_hash = Zeroizing::new([**identity_trapdoor, **identity_nullifier]);
    let mut hashed = H::hash(&*to_hash);

    // SecretFr::from wipes the intermediate hash result after wrapping it
    SecretFr::from(&mut hashed)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::hashers::PoseidonHash;

    #[test]
    fn test_secret_computations_match_concrete_poseidon() {
        let secret = SecretFr::from(&mut Fr::from(42));
        let other = SecretFr::from(&mut Fr::from(43));
        assert_eq!(
            compute_id_commitment::<PoseidonHash>(&secret),
            PoseidonHash::hash(&[*secret])
        );
        assert_eq!(
            *compute_identity_secret::<PoseidonHash>(&secret, &other),
            PoseidonHash::hash(&[*secret, *other])
        );
        assert_eq!(
            compute_share_slope::<PoseidonHash>(&secret, Fr::from(5), Fr::from(6)),
            PoseidonHash::hash(&[*secret, Fr::from(5), Fr::from(6)])
        );
    }
}
