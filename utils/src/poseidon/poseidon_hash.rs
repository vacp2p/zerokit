// This crate implements the Poseidon hash algorithm https://eprint.iacr.org/2019/458.pdf

// Implementation partially taken from https://github.com/arnaucube/poseidon-rs/blob/233027d6075a637c29ad84a8a44f5653b81f0410/src/lib.rs
// and adapted to work over arkworks field traits and custom data structures

use crate::poseidon_constants::find_poseidon_ark_and_mds;
use ark_ff::PrimeField;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoundParameters<F: PrimeField> {
    // confirm: Is this "rate"? does this correlate with light-poseidon "width" parameter?
    pub t: usize,
    pub n_rounds_full: usize,
    pub n_rounds_partial: usize,
    pub skip_matrices: usize,
    pub ark_consts: Vec<F>,
    pub mds: Vec<Vec<F>>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoundParameVec<F: PrimeField> {
    pub inner: Vec<RoundParameters<F>>,
}

// Dev artifact: helps grok internal params against light-poseidon approach to params
// /// Parameters for the Poseidon hash algorithm.
// pub struct PoseidonParameters<F: PrimeField> {
//     /// Round constants.
//     pub ark: Vec<F>,
//     /// MDS matrix.
//     pub mds: Vec<Vec<F>>,
//     /// Number of full rounds (where S-box is applied to all elements of the
//     /// state).
//     pub full_rounds: usize,
//     /// Number of partial rounds (where S-box is applied only to the first
//     /// element of the state).
//     pub partial_rounds: usize,
//     /// Number of prime fields in the state.
//     pub width: usize,
//     /// Exponential used in S-box to power elements of the state.
//     pub alpha: u64,
// }

pub struct Poseidon<F: PrimeField> {
    round_params: Vec<RoundParameters<F>>,
}

impl<F: PrimeField> RoundParameVec<F> {
    fn make_param_vec(poseidon_params: &[(usize, usize, usize, usize)]) -> Self {
        let mut read_params = Vec::<RoundParameters<F>>::with_capacity(poseidon_params.len());

        for &(t, n_rounds_full, n_rounds_partial, skip_matrices) in poseidon_params {
            let (ark, mds) = find_poseidon_ark_and_mds::<F>(
                1, // is_field = 1
                0, // is_sbox_inverse = 0
                F::MODULUS_BIT_SIZE as u64,
                t,
                n_rounds_full as u64,
                n_rounds_partial as u64,
                skip_matrices,
            );
            let rp = RoundParameters {
                t,
                n_rounds_partial,
                n_rounds_full,
                skip_matrices,
                ark_consts: ark,
                mds,
            };
            read_params.push(rp);
        }
        Self { inner: read_params }
    }
}
impl<F: PrimeField> Poseidon<F> {
    // Loads round parameters and generates round constants
    // poseidon_params is a vector containing tuples (t, n_rounds_full, n_rounds_partial, skip_matrices)
    // where t is the rate (input length + 1)
    // and skip_matrices is a (temporary) parameter used to generate secure MDS matrices (see comments in the description of find_poseidon_ark_and_mds)
    // TODO: implement automatic generation of round parameters
    pub fn from(poseidon_params: &[(usize, usize, usize, usize)]) -> Self {
        let param_vec = RoundParameVec::make_param_vec(poseidon_params);
        // dbg!(&param_vec.inner);
        Poseidon {
            round_params: param_vec.inner,
        }
    }

    pub fn get_parameters(&self) -> &Vec<RoundParameters<F>> {
        &self.round_params
    }

    pub fn ark(&self, state: &mut [F], c: &[F], it: usize) {
        state.iter_mut().enumerate().for_each(|(i, elem)| {
            *elem += c[it + i];
        });
    }

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

    pub fn select_params(&self, inp: &[F]) -> Result<&RoundParameters<F>, String> {
        if inp.is_empty() {
            return Err("Attempt to hash empty data input".to_string());
        }
        // Note that the rate t becomes input length + 1; hence for length N we pick parameters with T = N + 1
        let t = inp.len() + 1;
        self.round_params
            .iter()
            .find(|el| el.t == t)
            .ok_or("No parameters found for inputs length".to_string())
    }

    pub fn hash(&self, inp: &[F]) -> Result<F, String> {
        let params = self.select_params(inp)?;
        let mut state = Vec::with_capacity(inp.len() + 1);
        state.push(F::ZERO);
        state.extend_from_slice(inp);
        let mut state_2 = vec![F::ZERO; inp.len() + 1];

        for i in 0..(params.n_rounds_full + params.n_rounds_partial) {
            self.ark(&mut state, &params.ark_consts, i * params.t);
            self.sbox(params.n_rounds_full, params.n_rounds_partial, &mut state, i);
            self.mix_2(&state, &params.mds, &mut state_2);
            std::mem::swap(&mut state, &mut state_2);
        }

        Ok(state[0])
    }
}

impl<F> Default for Poseidon<F>
where
    F: PrimeField,
{
    // Default instantiation has no round constants set. Will return an error when hashing is attempted.
    fn default() -> Self {
        Self::from(&[])
    }
}

// WIP artifact
#[cfg(test)]
mod test {
    use ark_bn254::Fr;

    use super::*;
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
    // #[test]
    // fn see_params() {
    //     let mut param_vec = RoundParameVec::<Fr>::make_param_vec(&ROUND_PARAMS);
    //     let stats /* (rate, fulls, partual, sm, ark_n, mds_n) */ = param_vec.inner.into_iter().map(|RoundParameters { rate, n_rounds_full, n_rounds_partial, skip_matrices, ark_consts, mds }| (rate, n_rounds_full, n_rounds_partial, skip_matrices, ark_consts.len(), mds.len())).collect::<Vec<_>>();
    //     println!("r  f  p   s  cl   ml");
    //     for s in stats.iter() {
    //         println!("{:?}", s);
    //     }
    //     panic!();
    // }
    // #[test]
    // fn see_data() {
    //     let size = 10;
    //     let mut param_vec = RoundParameVec::<Fr>::make_param_vec(&ROUND_PARAMS);
    //     let mut values = Vec::with_capacity(size as usize);
    //     for i in 0..size {
    //         values.push([Fr::from(u128::MAX - i)]);
    //     }
    //     panic!("{:?}", values);
    // }
}
