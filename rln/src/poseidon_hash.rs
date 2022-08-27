// This crate implements the Poseidon hash algorithm https://eprint.iacr.org/2019/458.pdf

// The implementation is taken from https://github.com/arnaucube/poseidon-rs/blob/233027d6075a637c29ad84a8a44f5653b81f0410/src/lib.rs
// and slightly adapted to work over arkworks field data type

use crate::circuit::Fr;
use crate::poseidon_constants::constants;
use crate::utils::*;
use ark_std::Zero;
use once_cell::sync::Lazy;

#[derive(Debug)]
pub struct Constants {
    pub c: Vec<Vec<Fr>>,
    pub m: Vec<Vec<Vec<Fr>>>,
    pub n_rounds_f: usize,
    pub n_rounds_p: Vec<usize>,
}
pub fn load_constants() -> Constants {
    let (c_str, m_str) = constants();
    let mut c: Vec<Vec<Fr>> = Vec::new();
    for i in 0..c_str.len() {
        let mut cci: Vec<Fr> = Vec::new();
        for j in 0..c_str[i].len() {
            let b: Fr = str_to_fr(c_str[i][j], 10);
            cci.push(b);
        }
        c.push(cci);
    }
    let mut m: Vec<Vec<Vec<Fr>>> = Vec::new();
    for i in 0..m_str.len() {
        let mut mi: Vec<Vec<Fr>> = Vec::new();
        for j in 0..m_str[i].len() {
            let mut mij: Vec<Fr> = Vec::new();
            for k in 0..m_str[i][j].len() {
                let b: Fr = str_to_fr(m_str[i][j][k], 10);
                mij.push(b);
            }
            mi.push(mij);
        }
        m.push(mi);
    }
    Constants {
        c: c,
        m: m,
        n_rounds_f: 8,
        n_rounds_p: vec![56, 57, 56, 60, 60, 63, 64, 63],
    }
}

pub struct Poseidon {
    constants: Constants,
}
impl Poseidon {
    pub fn new() -> Poseidon {
        Poseidon {
            constants: load_constants(),
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
        let t = inp.len() + 1;
        if inp.is_empty() || (inp.len() >= self.constants.n_rounds_p.len() - 1) {
            return Err("Wrong inputs length".to_string());
        }
        let n_rounds_f = self.constants.n_rounds_f;
        let n_rounds_p = self.constants.n_rounds_p[t - 2];

        let mut state = vec![Fr::zero(); t];
        state[1..].clone_from_slice(&inp);

        for i in 0..(n_rounds_f + n_rounds_p) {
            self.ark(&mut state, &self.constants.c[t - 2], i * t);
            self.sbox(n_rounds_f, n_rounds_p, &mut state, i);
            state = self.mix(&state, &self.constants.m[t - 2]);
        }

        Ok(state[0])
    }
}

impl Default for Poseidon {
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
