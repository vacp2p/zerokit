// This module provides the Poseidon2 round parameters and round-constant derivation.

// The Poseidon2 permutation (https://eprint.iacr.org/2023/323) reuses the Grain LFSR of the
// original Poseidon for its round constants (same seeding), while its matrices are structural:
// the external matrix `M_E` is fixed per width and the internal matrix `M_I` is the all-ones
// matrix plus a per-field diagonal. The diagonals below were generated with the HorizenLabs
// reference script (poseidon2_rust_params.sage) for the Bn254 scalar field; the `t = 3` set
// matches the published HorizenLabs instance bit-for-bit.
// Poseidon2 reference implementation: https://github.com/HorizenLabs/poseidon2

use ark_ff::PrimeField;

use super::poseidon_grain::PoseidonGrainLFSR;

/// One Poseidon2 width configuration for a concrete field: the state width `t`, the round
/// counts and the internal-matrix diagonal.
#[derive(Debug, Clone, PartialEq)]
pub struct Poseidon2WidthParams {
    /// State width (input length plus `1`).
    pub t: usize,
    /// Number of full (external) rounds `RF`.
    pub n_rounds_f: usize,
    /// Number of partial (internal) rounds `RP`.
    pub n_rounds_p: usize,
    /// Big-endian byte encoding of the internal-matrix diagonal minus one (`M_I = J + diag`).
    pub mat_internal_diag_m_1: &'static [[u8; 32]],
}

const fn u256_be(value: u8) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes[31] = value;
    bytes
}

const MAT_DIAG2_M_1: [[u8; 32]; 2] = [u256_be(1), u256_be(2)];

const MAT_DIAG3_M_1: [[u8; 32]; 3] = [u256_be(1), u256_be(1), u256_be(2)];

const MAT_DIAG4_M_1: [[u8; 32]; 4] = [
    [
        0x10, 0xdc, 0x6e, 0x9c, 0x00, 0x6e, 0xa3, 0x8b, 0x04, 0xb1, 0xe0, 0x3b, 0x4b, 0xd9, 0x49,
        0x0c, 0x0d, 0x03, 0xf9, 0x89, 0x29, 0xca, 0x1d, 0x7f, 0xb5, 0x68, 0x21, 0xfd, 0x19, 0xd3,
        0xb6, 0xe7,
    ],
    [
        0x0c, 0x28, 0x14, 0x5b, 0x6a, 0x44, 0xdf, 0x3e, 0x01, 0x49, 0xb3, 0xd0, 0xa3, 0x0b, 0x3b,
        0xb5, 0x99, 0xdf, 0x97, 0x56, 0xd4, 0xdd, 0x9b, 0x84, 0xa8, 0x6b, 0x38, 0xcf, 0xb4, 0x5a,
        0x74, 0x0b,
    ],
    [
        0x00, 0x54, 0x4b, 0x83, 0x38, 0x79, 0x15, 0x18, 0xb2, 0xc7, 0x64, 0x5a, 0x50, 0x39, 0x27,
        0x98, 0xb2, 0x1f, 0x75, 0xbb, 0x60, 0xe3, 0x59, 0x61, 0x70, 0x06, 0x7d, 0x00, 0x14, 0x1c,
        0xac, 0x15,
    ],
    [
        0x22, 0x2c, 0x01, 0x17, 0x57, 0x18, 0x38, 0x6f, 0x2e, 0x2e, 0x82, 0xeb, 0x12, 0x27, 0x89,
        0xe3, 0x52, 0xe1, 0x05, 0xa3, 0xb8, 0xfa, 0x85, 0x26, 0x13, 0xbc, 0x53, 0x44, 0x33, 0xee,
        0x42, 0x8b,
    ],
];

/// The Poseidon2 width configurations for the Bn254 scalar field, covering `1..=3` inputs
/// (`t = inputs + 1`): `RF = 8` and `RP = 56` for every width, generated with the HorizenLabs
/// reference script (the `t = 3` instance matches the published HorizenLabs one).
pub const POSEIDON2_ROUND_PARAMS: [Poseidon2WidthParams; 3] = [
    Poseidon2WidthParams {
        t: 2,
        n_rounds_f: 8,
        n_rounds_p: 56,
        mat_internal_diag_m_1: &MAT_DIAG2_M_1,
    },
    Poseidon2WidthParams {
        t: 3,
        n_rounds_f: 8,
        n_rounds_p: 56,
        mat_internal_diag_m_1: &MAT_DIAG3_M_1,
    },
    Poseidon2WidthParams {
        t: 4,
        n_rounds_f: 8,
        n_rounds_p: 56,
        mat_internal_diag_m_1: &MAT_DIAG4_M_1,
    },
];

/// Derives the Poseidon2 round constants for one state width from the Grain LFSR (same
/// seeding as the original Poseidon).
///
/// Returns `(rc_external, rc_internal)`: `RF` rows of `t` constants for the external rounds
/// and a single constant per internal round. The Grain stream is drawn in round order
/// (`RF / 2` external, `RP` internal, `RF / 2` external) with `t` constants per external
/// round but only ONE constant per internal round (`RF * t + RP` total), matching the
/// reference generation script.
pub fn find_poseidon2_round_constants<F: PrimeField>(
    t: usize,
    n_rounds_f: usize,
    n_rounds_p: usize,
) -> (Vec<Vec<F>>, Vec<F>) {
    let mut lfsr = PoseidonGrainLFSR::new(
        1, // is_field = 1
        0, // is_sbox_inverse = 0
        F::MODULUS_BIT_SIZE as u64,
        t as u64,
        n_rounds_f as u64,
        n_rounds_p as u64,
    );

    let half_f = n_rounds_f / 2;
    let mut rc_external = Vec::<Vec<F>>::with_capacity(n_rounds_f);
    let mut rc_internal = Vec::<F>::with_capacity(n_rounds_p);
    for round in 0..(n_rounds_f + n_rounds_p) {
        if round < half_f || round >= half_f + n_rounds_p {
            rc_external.push(lfsr.get_field_elements_rejection_sampling::<F>(t));
        } else {
            let values = lfsr.get_field_elements_rejection_sampling::<F>(1);
            rc_internal.push(values[0]);
        }
    }

    (rc_external, rc_internal)
}
