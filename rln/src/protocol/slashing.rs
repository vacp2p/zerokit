use ark_ff::AdditiveGroup;

use super::proof::RLNProofValues;
use crate::{circuit::Fr, error::ProtocolError, utils::IdSecret};

/// Computes identity secret from two (x, y) shares.
fn compute_id_secret(share1: (Fr, Fr), share2: (Fr, Fr)) -> Result<IdSecret, ProtocolError> {
    // Assuming a0 is the identity secret and a1 = poseidonHash([a0, external_nullifier]),
    // a (x,y) share satisfies the following relation
    // y = a_0 + x * a_1
    let (x1, y1) = share1;
    let (x2, y2) = share2;

    // If the two input shares were computed for the same external_nullifier and identity secret, we can recover the latter
    // y1 = a_0 + x1 * a_1
    // y2 = a_0 + x2 * a_1

    if (x1 - x2) != Fr::ZERO {
        let a_1 = (y1 - y2) / (x1 - x2);
        let mut a_0 = y1 - x1 * a_1;

        // If shares come from the same polynomial, a0 is correctly recovered and a1 = poseidonHash([a0, external_nullifier])
        let id_secret = IdSecret::from(&mut a_0);
        Ok(id_secret)
    } else {
        Err(ProtocolError::DivisionByZero)
    }
}

/// Recovers identity secret from two proof shares with the same external nullifier.
///
/// When a user violates rate limits by generating multiple proofs in the same epoch,
/// their shares can be used to recover their identity secret through polynomial interpolation.
pub fn recover_id_secret(
    rln_proof_values_1: &RLNProofValues,
    rln_proof_values_2: &RLNProofValues,
) -> Result<IdSecret, ProtocolError> {
    let external_nullifier_1 = rln_proof_values_1.external_nullifier;
    let external_nullifier_2 = rln_proof_values_2.external_nullifier;

    // We continue only if the proof values are for the same external nullifier
    if external_nullifier_1 != external_nullifier_2 {
        return Err(ProtocolError::ExternalNullifierMismatch(
            external_nullifier_1,
            external_nullifier_2,
        ));
    }

    // We extract the two shares
    let share1 = (rln_proof_values_1.x, rln_proof_values_1.y);
    let share2 = (rln_proof_values_2.x, rln_proof_values_2.y);

    // We recover the secret
    compute_id_secret(share1, share2)
}
