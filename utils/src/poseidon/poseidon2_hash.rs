// This module implements the Poseidon2 hash algorithm https://eprint.iacr.org/2023/323

// The permutation follows the HorizenLabs reference implementation
// https://github.com/HorizenLabs/poseidon2/blob/main/plain_implementations/src/poseidon2/poseidon2.rs
// Hashing uses the one-shot compression layout of the Logos ecosystem (the compress function
// of https://github.com/logos-storage/rust-poseidon-bn254-pure and the Nomos compression
// mode): state [x1, .., xN, 0] with t = N + 1, capacity zero last, output state[0].

use ark_ff::PrimeField;
use zeroize::Zeroizing;

use super::{
    error::Poseidon2Error,
    poseidon2_constants::{find_poseidon2_round_constants, Poseidon2WidthParams},
};

/// Derived round parameters for one Poseidon2 state width.
#[derive(Debug, Clone, PartialEq)]
pub struct Poseidon2RoundParameters<F: PrimeField> {
    /// State width (input length plus `1`).
    pub t: usize,
    /// Number of full (external) rounds `RF`.
    pub n_rounds_f: usize,
    /// Number of partial (internal) rounds `RP`.
    pub n_rounds_p: usize,
    /// Full-round constants, one row of `t` constants per external round.
    pub rc_external: Vec<Vec<F>>,
    /// Partial-round constants, a single constant per internal round (added to `state[0]`).
    pub rc_internal: Vec<F>,
    /// Diagonal of the internal matrix minus one (`M_I = J + diag`).
    pub mat_internal_diag_m_1: Vec<F>,
}

/// The Poseidon2 hash engine over a prime field: holds the derived round parameters for every
/// configured state width.
pub struct Poseidon2<F: PrimeField> {
    round_params: Vec<Poseidon2RoundParameters<F>>,
}

impl<F> Poseidon2<F>
where
    F: PrimeField,
{
    /// Loads the width configurations and derives the round constants for every entry in
    /// `width_params` via [`find_poseidon2_round_constants`]. For the Bn254 scalar field use
    /// [`POSEIDON2_ROUND_PARAMS`](crate::poseidon::POSEIDON2_ROUND_PARAMS).
    pub fn from(width_params: &[Poseidon2WidthParams]) -> Self {
        let mut read_params = Vec::<Poseidon2RoundParameters<F>>::with_capacity(width_params.len());

        for wp in width_params {
            let (rc_external, rc_internal) =
                find_poseidon2_round_constants::<F>(wp.t, wp.n_rounds_f, wp.n_rounds_p);
            let rp = Poseidon2RoundParameters {
                t: wp.t,
                n_rounds_f: wp.n_rounds_f,
                n_rounds_p: wp.n_rounds_p,
                rc_external,
                rc_internal,
                mat_internal_diag_m_1: wp
                    .mat_internal_diag_m_1
                    .iter()
                    .map(|bytes| F::from_be_bytes_mod_order(bytes))
                    .collect(),
            };
            read_params.push(rp);
        }

        Poseidon2 {
            round_params: read_params,
        }
    }

    /// Returns the derived round parameters, one entry per configured state width.
    pub fn get_parameters(&self) -> &Vec<Poseidon2RoundParameters<F>> {
        &self.round_params
    }

    /// Hashes `inp` in the one-shot compression layout: the input is placed in `state[..N]`
    /// with the capacity zero last (`state[N] = 0`), permutation runs once and returns `state[0]`.
    pub fn hash(&self, inp: &[F]) -> Result<F, Poseidon2Error> {
        // Note that the state width t becomes input length + 1; hence for length N we pick
        // parameters with T = N + 1
        let t = inp.len() + 1;

        if inp.is_empty() {
            return Err(Poseidon2Error::EmptyInput);
        }

        let params = self
            .round_params
            .iter()
            .find(|el| el.t == t)
            .ok_or(Poseidon2Error::NoParametersForInputLength(inp.len()))?;

        // The external matrix M_E is only defined here for the widths the protocol uses; a
        // custom parameter set with any other width is rejected instead of hashing wrongly.
        // Extending this range requires a matching M_E branch in matmul_external and the
        // range in the Poseidon2Error::UnsupportedStateWidth message.
        if !matches!(t, 2..=4) {
            return Err(Poseidon2Error::UnsupportedStateWidth(t));
        }

        // The state vector holds a copy of the input, which may be secret material (identity
        // secrets), Zeroizing wipes it on drop so no secret bytes remain in memory after the
        // hash is computed.
        let mut state = Zeroizing::new(vec![F::ZERO; t]);
        state[..inp.len()].clone_from_slice(inp);

        // Initial linear layer: Poseidon2 multiplies the state by M_E once before any round.
        Self::matmul_external(&mut state);

        let half_f = params.n_rounds_f / 2;
        for round in 0..half_f {
            Self::add_rc(&mut state, &params.rc_external[round]);
            Self::sbox_full(&mut state);
            Self::matmul_external(&mut state);
        }
        for round in 0..params.n_rounds_p {
            state[0] += params.rc_internal[round];
            Self::sbox_single(&mut state[0]);
            Self::matmul_internal(&mut state, &params.mat_internal_diag_m_1);
        }
        for round in half_f..params.n_rounds_f {
            Self::add_rc(&mut state, &params.rc_external[round]);
            Self::sbox_full(&mut state);
            Self::matmul_external(&mut state);
        }

        Ok(state[0])
    }

    fn add_rc(state: &mut [F], rc: &[F]) {
        for (elem, c) in state.iter_mut().zip(rc) {
            *elem += *c;
        }
    }

    fn sbox_full(state: &mut [F]) {
        for elem in state.iter_mut() {
            Self::sbox_single(elem);
        }
    }

    fn sbox_single(elem: &mut F) {
        let aux = *elem;
        *elem *= *elem;
        *elem *= *elem;
        *elem *= aux;
    }

    /// Multiplies the state by the external matrix `M_E`: `circ(2, 1)` for `t = 2`, the
    /// all-ones matrix plus the identity for `t = 3` and the fixed `M4` matrix of the paper
    /// for `t = 4`, evaluated with the addition chain of the reference implementation.
    fn matmul_external(state: &mut [F]) {
        match state.len() {
            2 => {
                let sum = state[0] + state[1];
                state[0] += sum;
                state[1] += sum;
            }
            3 => {
                let sum = state[0] + state[1] + state[2];
                state[0] += sum;
                state[1] += sum;
                state[2] += sum;
            }
            4 => {
                let t_0 = state[0] + state[1];
                let t_1 = state[2] + state[3];
                let t_2 = state[1].double() + t_1;
                let t_3 = state[3].double() + t_0;
                let t_4 = t_1.double().double() + t_3;
                let t_5 = t_0.double().double() + t_2;
                let t_6 = t_3 + t_5;
                let t_7 = t_2 + t_4;
                state[0] = t_6;
                state[1] = t_5;
                state[2] = t_7;
                state[3] = t_4;
            }
            _ => (),
        }
    }

    /// Multiplies the state by the internal matrix `M_I = J + diag`: every cell becomes the
    /// state sum plus its own value scaled by the diagonal entry minus one.
    fn matmul_internal(state: &mut [F], mat_internal_diag_m_1: &[F]) {
        let mut sum = F::ZERO;
        for elem in state.iter() {
            sum += *elem;
        }
        for (elem, diag) in state.iter_mut().zip(mat_internal_diag_m_1) {
            *elem *= *diag;
            *elem += sum;
        }
    }
}
