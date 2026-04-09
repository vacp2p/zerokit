use ark_ff::AdditiveGroup;

#[cfg(feature = "multi-message-id")]
use super::proof::RLNOutputs;
use super::proof::RLNProofValues;
use crate::{circuit::Fr, error::RecoverSecretError, utils::IdSecret};

/// Computes identity secret from two (x, y) shares.
///
/// This function is feature-agnostic: it operates on plain `(x, y)` share pairs
/// that can be extracted from any [`RLNProofValues`] variant (`SingleV1` or `MultiV1`).
/// By normalizing proof outputs into simple `(x, y)` pairs with a single nullifier,
/// slashing can be performed across different prover modes without compile-time feature constraints.
pub fn compute_id_secret(
    share1: (Fr, Fr),
    share2: (Fr, Fr),
) -> Result<IdSecret, RecoverSecretError> {
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
        Err(RecoverSecretError::DivisionByZero)
    }
}

/// Recovers identity secret from two [`RLNProofValues`] with the same external nullifier.
///
/// This is a convenience API that accepts two proof values of the **same** variant.
/// For cross-feature slashing (e.g. one share from `SingleV1` and another from `MultiV1`),
/// extract the `(x, y)` pair and nullifier from each proof value and call [`compute_id_secret`] directly.
pub fn recover_id_secret(
    rln_proof_values_1: &RLNProofValues,
    rln_proof_values_2: &RLNProofValues,
) -> Result<IdSecret, RecoverSecretError> {
    let external_nullifier_1 = rln_proof_values_1.external_nullifier();
    let external_nullifier_2 = rln_proof_values_2.external_nullifier();

    // We continue only if the proof values are for the same external nullifier
    if external_nullifier_1 != external_nullifier_2 {
        return Err(RecoverSecretError::ExternalNullifierMismatch(
            *external_nullifier_1,
            *external_nullifier_2,
        ));
    }

    match (rln_proof_values_1, rln_proof_values_2) {
        #[cfg(not(feature = "multi-message-id"))]
        (pv1, pv2) => {
            let share1 = (*pv1.x(), *pv1.y());
            let share2 = (*pv2.x(), *pv2.y());
            compute_id_secret(share1, share2)
        }
        #[cfg(feature = "multi-message-id")]
        (pv1, pv2) => {
            let RLNOutputs::MultiV1 {
                ys: ys1,
                nullifiers: nullifiers1,
                selector_used: selector_used1,
            } = &pv1.outputs;
            let RLNOutputs::MultiV1 {
                ys: ys2,
                nullifiers: nullifiers2,
                selector_used: selector_used2,
            } = &pv2.outputs;

            for (i, (nullifier_i, &used_i)) in
                nullifiers1.iter().zip(selector_used1.iter()).enumerate()
            {
                if !used_i {
                    continue;
                }
                for (j, (nullifier_j, &used_j)) in
                    nullifiers2.iter().zip(selector_used2.iter()).enumerate()
                {
                    if !used_j {
                        continue;
                    }
                    if nullifier_i == nullifier_j {
                        let share1 = (*pv1.x(), ys1[i]);
                        let share2 = (*pv2.x(), ys2[j]);
                        return compute_id_secret(share1, share2);
                    }
                }
            }
            Err(RecoverSecretError::NoMatchingNullifier)
        }
    }
}
