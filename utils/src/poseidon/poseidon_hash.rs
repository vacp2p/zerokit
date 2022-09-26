// This crate implements the Poseidon hash algorithm https://eprint.iacr.org/2019/458.pdf

// Implementation partially taken from https://github.com/arnaucube/poseidon-rs/blob/233027d6075a637c29ad84a8a44f5653b81f0410/src/lib.rs
// and adapted to work over arkworks field traits and custom data structures

use crate::poseidon_constants::find_poseidon_ark_and_mds;
use ark_ff::{FpParameters, PrimeField};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoundParamenters<F: PrimeField> {
    pub t: usize,
    pub n_rounds_f: usize,
    pub n_rounds_p: usize,
    pub skip_matrices: usize,
    pub c: Vec<F>,
    pub m: Vec<Vec<F>>,
}

pub struct Poseidon<F: PrimeField> {
    round_params: Vec<RoundParamenters<F>>,
}
impl<F: PrimeField> Poseidon<F> {
    // Loads round parameters and generates round constants
    // poseidon_params is a vector containing tuples (t, RF, RP, skip_matrices)
    // where: t is the rate (input lenght + 1), RF is the number of full rounds, RP is the number of partial rounds
    // and skip_matrices is a (temporary) parameter used to generate secure MDS matrices (see comments in the description of find_poseidon_ark_and_mds)
    // TODO: implement automatic generation of round parameters
    pub fn from(poseidon_params: &[(usize, usize, usize, usize)]) -> Self {
        let mut read_params = Vec::<RoundParamenters<F>>::new();

        for i in 0..poseidon_params.len() {
            let (t, n_rounds_f, n_rounds_p, skip_matrices) = poseidon_params[i];
            let (ark, mds) = find_poseidon_ark_and_mds::<F>(
                1, // is_field = 1
                0, // is_sbox_inverse = 0
                F::Params::MODULUS_BITS as u64,
                t,
                n_rounds_f as u64,
                n_rounds_p as u64,
                skip_matrices,
            );
            let rp = RoundParamenters {
                t: t,
                n_rounds_p: n_rounds_p,
                n_rounds_f: n_rounds_f,
                skip_matrices: skip_matrices,
                c: ark,
                m: mds,
            };
            read_params.push(rp);
        }

        Poseidon {
            round_params: read_params,
        }
    }

    pub fn get_parameters(&self) -> Vec<RoundParamenters<F>> {
        self.round_params.clone()
    }

    pub fn ark(&self, state: &mut [F], c: &[F], it: usize) {
        for i in 0..state.len() {
            state[i] += c[it + i];
        }
    }

    pub fn sbox(&self, n_rounds_f: usize, n_rounds_p: usize, state: &mut [F], i: usize) {
        if (i < n_rounds_f / 2) || (i >= n_rounds_f / 2 + n_rounds_p) {
            for j in 0..state.len() {
                let aux = state[j];
                state[j] *= state[j];
                state[j] *= state[j];
                state[j] *= aux;
            }
        } else {
            let aux = state[0];
            state[0] *= state[0];
            state[0] *= state[0];
            state[0] *= aux;
        }
    }

    pub fn mix(&self, state: &[F], m: &[Vec<F>]) -> Vec<F> {
        let mut new_state: Vec<F> = Vec::new();
        for i in 0..state.len() {
            new_state.push(F::zero());
            for j in 0..state.len() {
                let mut mij = m[i][j];
                mij *= state[j];
                new_state[i] += mij;
            }
        }
        new_state.clone()
    }

    pub fn hash(&self, inp: Vec<F>) -> Result<F, String> {
        // Note that the rate t becomes input lenght + 1, hence for lenght N we pick parameters with T = N + 1
        let t = inp.len() + 1;

        // We seek the index (Poseidon's round_params is an ordered vector) for the parameters corresponding to t
        let param_index = self.round_params.iter().position(|el| el.t == t);

        if inp.is_empty() || param_index.is_none() {
            return Err("No parameters found for inputs length".to_string());
        }

        let param_index = param_index.unwrap();

        let mut state = vec![F::zero(); t];
        state[1..].clone_from_slice(&inp);

        for i in 0..(self.round_params[param_index].n_rounds_f
            + self.round_params[param_index].n_rounds_p)
        {
            self.ark(
                &mut state,
                &self.round_params[param_index].c,
                (i as usize) * self.round_params[param_index].t,
            );
            self.sbox(
                self.round_params[param_index].n_rounds_f,
                self.round_params[param_index].n_rounds_p,
                &mut state,
                i,
            );
            state = self.mix(&state, &self.round_params[param_index].m);
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
