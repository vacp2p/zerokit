// This crate implements the Poseidon hash algorithm https://eprint.iacr.org/2019/458.pdf

// The implementation is taken from https://github.com/arnaucube/poseidon-rs/blob/233027d6075a637c29ad84a8a44f5653b81f0410/src/lib.rs
// and slightly adapted to work over arkworks field data type

use crate::circuit::Fr;
use crate::poseidon_constants::find_poseidon_ark_and_mds;
use ark_ff::{FpParameters, PrimeField};
use ark_std::Zero;
use once_cell::sync::Lazy;

// These indexed constants hardcodes the round parameters triple (t, RF, RN) from the paper
// SKIP_MATRICES is the index of the randomly generated secure MDS matrix. See security note in the poseidon_constants crate on this.
// TODO: generate in-code such parameters
pub const INPUT_LENGTH: &[usize] = &[1, 2, 3, 4, 5, 6, 7, 8];
pub const N_ROUNDS_F: &[usize] = &[8, 8, 8, 8, 8, 8, 8, 8];
pub const N_ROUNDS_P: &[usize] = &[56, 57, 56, 60, 60, 63, 64, 63];
pub const SKIP_MATRICES: &[u64] = &[0, 0, 0, 0, 0, 0, 0, 0];

#[derive(Debug, PartialEq, Eq)]
pub struct Constants<'a> {
    pub c: Vec<Vec<Fr>>,
    pub m: Vec<Vec<Vec<Fr>>>,
    pub n_rounds_f: &'a [usize],
    pub n_rounds_p: &'a [usize],
}

pub fn gen_constants() -> Constants<'static> {
    let mut c: Vec<Vec<Fr>> = Vec::new();
    let mut m: Vec<Vec<Vec<Fr>>> = Vec::new();

    for i in 0..INPUT_LENGTH.len() {
        let (ark, mds) = find_poseidon_ark_and_mds::<Fr>(
            1,
            0,
            <Fr as PrimeField>::Params::MODULUS_BITS as u64,
            INPUT_LENGTH[i],
            N_ROUNDS_F[i] as u64,
            N_ROUNDS_P[i] as u64,
            SKIP_MATRICES[i],
        );
        c.push(ark);
        m.push(mds);
    }

    Constants {
        c: c,
        m: m,
        n_rounds_f: N_ROUNDS_F,
        n_rounds_p: N_ROUNDS_P,
    }
}

pub struct Poseidon<'a> {
    constants: Constants<'a>,
}
impl Poseidon<'_> {
    pub fn new() -> Poseidon<'static> {
        Poseidon {
            constants: gen_constants(),
        }
    }
    pub fn ark(&self, state: &mut [Fr], c: &[Fr], it: usize) {
        for i in 0..state.len() {
            state[i] += c[it + i];
        }
    }

    pub fn sbox(&self, n_rounds_f: usize, n_rounds_p: usize, state: &mut [Fr], i: usize) {
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

    pub fn mix(&self, state: &[Fr], m: &[Vec<Fr>]) -> Vec<Fr> {
        let mut new_state: Vec<Fr> = Vec::new();
        for i in 0..state.len() {
            new_state.push(Fr::zero());
            for j in 0..state.len() {
                let mut mij = m[i][j];
                mij *= state[j];
                new_state[i] += mij;
            }
        }
        new_state.clone()
    }

    pub fn hash(&self, inp: Vec<Fr>) -> Result<Fr, String> {
        // Note that T becomes input lenght + 1, hence for lenght N we pick parameters with T = N + 1
        let t = inp.len() + 1;
        if inp.is_empty() || (inp.len() >= self.constants.n_rounds_p.len() - 1) {
            return Err("Wrong inputs length".to_string());
        }
        let n_rounds_f = self.constants.n_rounds_f[t - 2];
        let n_rounds_p = self.constants.n_rounds_p[t - 2];

        let mut state = vec![Fr::zero(); t];
        state[1..].clone_from_slice(&inp);

        for i in 0..(n_rounds_f + n_rounds_p) {
            self.ark(&mut state, &self.constants.c[t - 2], (i as usize) * t);
            self.sbox(n_rounds_f, n_rounds_p, &mut state, i);
            state = self.mix(&state, &self.constants.m[t - 2]);
        }

        Ok(state[0])
    }
}

impl Default for Poseidon<'_> {
    fn default() -> Self {
        Self::new()
    }
}

// Poseidon Hash wrapper over above implementation. Adapted from semaphore-rs poseidon hash wrapper.
static POSEIDON: Lazy<Poseidon> = Lazy::new(Poseidon::new);

pub fn poseidon_hash(input: &[Fr]) -> Fr {
    POSEIDON
        .hash(input.to_vec())
        .expect("hash with fixed input size can't fail")
}
