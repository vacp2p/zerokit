// This module implements the Poseidon hash algorithm https://eprint.iacr.org/2019/458.pdf

// Implementation partially taken from https://github.com/arnaucube/poseidon-rs/blob/233027d6075a637c29ad84a8a44f5653b81f0410/src/lib.rs
// and adapted to work over arkworks field traits and custom data structures

use ark_ff::PrimeField;
use zeroize::Zeroizing;

use super::{error::PoseidonError, poseidon_constants::find_poseidon_ark_and_mds};

/// Derived round parameters for one Poseidon state width.
#[derive(Debug, Clone, PartialEq)]
pub struct RoundParameters<F: PrimeField> {
    /// State width (input length plus `1`).
    pub t: usize,
    /// Number of full rounds `RF`.
    pub n_rounds_f: usize,
    /// Number of partial rounds `RP`.
    pub n_rounds_p: usize,
    /// Number of candidate MDS matrices discarded before a secure one is found (see
    /// [`find_poseidon_ark_and_mds`]).
    pub skip_matrices: usize,
    /// Round constants (ARK), one row of `t` constants per round in round order, flattened.
    pub c: Vec<F>,
    /// The `t x t` MDS matrix applied in the mixing step of every round.
    pub m: Vec<Vec<F>>,
}

/// The Poseidon hash engine over a prime field: holds the derived round parameters for every
/// configured state width.
pub struct Poseidon<F: PrimeField> {
    round_params: Vec<RoundParameters<F>>,
}

impl<F> Poseidon<F>
where
    F: PrimeField,
{
    /// Loads the round parameters and derives the round constants for every tuple in
    /// `poseidon_params`.
    ///
    /// Each tuple is `(t, RF, RP, skip_matrices)` where `t` is the state width (input length
    /// plus `1`), `RF` is the number of full rounds, `RP` is the number of partial rounds and
    /// `skip_matrices` is the number of candidate MDS matrices to discard before a secure one
    /// is found (see [`find_poseidon_ark_and_mds`]). For the Bn254 scalar field use
    /// [`POSEIDON_ROUND_PARAMS`](crate::poseidon::POSEIDON_ROUND_PARAMS).
    pub fn from(poseidon_params: &[(usize, usize, usize, usize)]) -> Self {
        let mut read_params = Vec::<RoundParameters<F>>::with_capacity(poseidon_params.len());

        for &(t, n_rounds_f, n_rounds_p, skip_matrices) in poseidon_params {
            let (ark, mds) = find_poseidon_ark_and_mds::<F>(
                1, // is_field = 1
                0, // is_sbox_inverse = 0
                F::MODULUS_BIT_SIZE as u64,
                t,
                n_rounds_f as u64,
                n_rounds_p as u64,
                skip_matrices,
            );
            let rp = RoundParameters {
                t,
                n_rounds_p,
                n_rounds_f,
                skip_matrices,
                c: ark,
                m: mds,
            };
            read_params.push(rp);
        }

        Poseidon {
            round_params: read_params,
        }
    }

    /// Returns the derived round parameters, one entry per configured state width.
    pub fn get_parameters(&self) -> &Vec<RoundParameters<F>> {
        &self.round_params
    }

    /// Adds the round constants to the state: cell `i` receives `c[it + i]`, where `it` is the
    /// offset of the current round into the flattened constant vector.
    pub fn ark(&self, state: &mut [F], c: &[F], it: usize) {
        state.iter_mut().enumerate().for_each(|(i, elem)| {
            *elem += c[it + i];
        });
    }

    /// Applies the S-box `x^5` for round `i`: to every cell in a full round, to `state[0]`
    /// only in a partial round (rounds `RF / 2 .. RF / 2 + RP`).
    pub fn sbox(&self, n_rounds_f: usize, n_rounds_p: usize, state: &mut [F], i: usize) {
        if (i < n_rounds_f / 2) || (i >= n_rounds_f / 2 + n_rounds_p) {
            state.iter_mut().for_each(|current_state| {
                let aux = *current_state;
                *current_state *= *current_state;
                *current_state *= *current_state;
                *current_state *= aux;
            })
        } else {
            let aux = state[0];
            state[0] *= state[0];
            state[0] *= state[0];
            state[0] *= aux;
        }
    }

    /// Multiplies the state by the MDS matrix `m`, writing the result into `state_2` (the
    /// caller swaps the two buffers afterwards).
    pub fn mix_2(&self, state: &[F], m: &[Vec<F>], state_2: &mut [F]) {
        for i in 0..state.len() {
            // Cache the row reference
            let row = &m[i];
            let mut acc = F::ZERO;
            for j in 0..state.len() {
                acc += row[j] * state[j];
            }
            state_2[i] = acc;
        }
    }

    /// Hashes `inp` in the one-shot layout: the input is placed in `state[1..]` with
    /// `state[0] = 0`, the permutation runs once and `state[0]` is returned.
    pub fn hash(&self, inp: &[F]) -> Result<F, PoseidonError> {
        // Note that the rate t becomes input length + 1; hence for length N we pick parameters
        // with T = N + 1
        let t = inp.len() + 1;

        if inp.is_empty() {
            return Err(PoseidonError::EmptyInput);
        }

        // We seek the index (Poseidon's round_params is an ordered vector) for the parameters
        // corresponding to t
        let param_index = self
            .round_params
            .iter()
            .position(|el| el.t == t)
            .ok_or(PoseidonError::NoParametersForInputLength(inp.len()))?;

        // The state vectors hold a copy of the input, which may be secret material (identity
        // secrets), Zeroizing wipes them on drop so no secret bytes remain in memory after the
        // hash is computed.
        let mut state = Zeroizing::new(vec![F::ZERO; t]);
        let mut state_2 = state.clone();
        state[1..].clone_from_slice(inp);

        for i in 0..(self.round_params[param_index].n_rounds_f
            + self.round_params[param_index].n_rounds_p)
        {
            self.ark(
                &mut state,
                &self.round_params[param_index].c,
                i * self.round_params[param_index].t,
            );
            self.sbox(
                self.round_params[param_index].n_rounds_f,
                self.round_params[param_index].n_rounds_p,
                &mut state,
                i,
            );
            self.mix_2(&state, &self.round_params[param_index].m, &mut state_2);
            std::mem::swap(&mut state, &mut state_2);
        }

        Ok(state[0])
    }
}

impl<F> Default for Poseidon<F>
where
    F: PrimeField,
{
    // Default instantiation has no round constants set. Will return an error when hashing is
    // attempted.
    fn default() -> Self {
        Self::from(&[])
    }
}
