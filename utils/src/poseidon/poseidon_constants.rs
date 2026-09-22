// This module provides an implementation to compute the Poseidon hash round constants and MDS matrices.

// SECURITY NOTE: The MDS matrices are generated interatively using the Grain LFSR until certain criteria are met.
// According to the paper, such matrices have to respect some conditions which are checked by 3 different algorithms in the reference implementation.
// At the moment such algorithms are not implemented, however *for the hardcoded parameters* the first random matrix generated satisfy such conditions.
// If different parameters are implemented, it should be checked against the reference implementation how many matrices are generated before outputting
// the right one, and pass this number to the skip_matrices parameter of find_poseidon_ark_and_mds function in order to output the correct one.
// Poseidon reference implementation: https://extgit.iaik.tugraz.at/krypto/hadeshash/-/blob/master/code/generate_parameters_grain.sage (algorithm_1, algorithm_2, algorithm_3)

use ark_ff::PrimeField;

use super::poseidon_grain::PoseidonGrainLFSR;

/// The Poseidon round parameters tuples `(t, RF, RP, SKIP_MATRICES)` for the Bn254 scalar field,
/// matching circomlib for `1..=16` inputs (`t = inputs + 1`): `RF = 8` and `RP` per width taken
/// from `N_ROUNDS_P` in <https://github.com/iden3/circomlib/blob/master/circuits/poseidon.circom>.
pub const POSEIDON_ROUND_PARAMS: [(usize, usize, usize, usize); 16] = [
    (2, 8, 56, 0),
    (3, 8, 57, 0),
    (4, 8, 56, 0),
    (5, 8, 60, 0),
    (6, 8, 60, 0),
    (7, 8, 63, 0),
    (8, 8, 64, 0),
    (9, 8, 63, 0),
    (10, 8, 60, 0),
    (11, 8, 66, 0),
    (12, 8, 60, 0),
    (13, 8, 65, 0),
    (14, 8, 70, 0),
    (15, 8, 60, 0),
    (16, 8, 64, 0),
    (17, 8, 68, 0),
];

/// Derives the Poseidon round constants (ARK) and the MDS matrix for one state width from the
/// Grain LFSR.
///
/// Draws `(full_rounds + partial_rounds) * rate` constants by rejection sampling, then skips
/// `skip_matrices` candidate matrices before building the Cauchy MDS matrix
/// `m[i][j] = 1 / (x_i + y_j)` (see the security note at the top of this module).
pub fn find_poseidon_ark_and_mds<F: PrimeField>(
    is_field: u64,
    is_sbox_an_inverse: u64,
    prime_bits: u64,
    rate: usize,
    full_rounds: u64,
    partial_rounds: u64,
    skip_matrices: usize,
) -> (Vec<F>, Vec<Vec<F>>) {
    let mut lfsr = PoseidonGrainLFSR::new(
        is_field,
        is_sbox_an_inverse,
        prime_bits,
        rate as u64,
        full_rounds,
        partial_rounds,
    );

    let mut ark = Vec::<F>::with_capacity((full_rounds + partial_rounds) as usize);
    for _ in 0..(full_rounds + partial_rounds) {
        let values = lfsr.get_field_elements_rejection_sampling::<F>(rate);
        for el in values {
            ark.push(el);
        }
    }

    let mut mds = Vec::<Vec<F>>::with_capacity(rate);
    mds.resize(rate, vec![F::ZERO; rate]);

    // Note that we build the MDS matrix generating 2*rate elements. If the matrix built is not secure (see checks with algorithm 1, 2, 3 in reference implementation)
    // it has to be skipped. Since here we do not implement such algorithm we allow to pass a parameter to skip generations of elements giving unsecure matrixes.
    // At the moment, the skip_matrices parameter has to be generated from the reference implementation and passed to this function
    for _ in 0..skip_matrices {
        let _ = lfsr.get_field_elements_mod_p::<F>(2 * (rate));
    }

    // a qualifying matrix must satisfy the following requirements
    // - there is no duplication among the elements in x or y
    // - there is no i and j such that x[i] + y[j] = p
    // - the resultant MDS passes all the three tests

    let xs = lfsr.get_field_elements_mod_p::<F>(rate);
    let ys = lfsr.get_field_elements_mod_p::<F>(rate);

    for i in 0..(rate) {
        for (j, ys_item) in ys.iter().enumerate().take(rate) {
            // Poseidon algorithm guarantees xs[i] + ys[j] != 0
            mds[i][j] = (xs[i] + ys_item)
                .inverse()
                .expect("MDS matrix inverse must be valid");
        }
    }

    (ark, mds)
}

#[cfg(test)]
mod test {
    use ark_bn254::Fr;
    use ark_ff::AdditiveGroup;

    use super::*;

    #[test]
    fn test_find_poseidon_ark_and_mds_bn254_regression_no_inverse_panic() {
        let result = std::panic::catch_unwind(|| {
            // Parameters match the hardcoded BN254 Poseidon setup used by current tests.
            find_poseidon_ark_and_mds::<Fr>(1, 0, 254, 2, 8, 56, 0)
        });

        assert!(
            result.is_ok(),
            "find_poseidon_ark_and_mds unexpectedly panicked (possible MDS inverse invariant break)"
        );

        let (ark, mds) = result.unwrap();
        assert_eq!(ark.len(), (8 + 56) * 2);
        assert_eq!(mds.len(), 2);
        assert_eq!(mds[0].len(), 2);
        assert_eq!(mds[1].len(), 2);
        assert_ne!(mds[0][0], Fr::ZERO);
    }
}
