// Measures light-poseidon (circomlib-compatible Poseidon with hardcoded constants, the
// crate LEZ's PR #304 benchmarked): init = constructing the hasher for the requested
// arity, steady = `iters` chained hashes. Outputs must equal the p1-zerokit guest.

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use light_poseidon::{Poseidon, PoseidonHasher};
use risc0_zkvm::guest::env;

fn main() {
    let arity: u32 = env::read();
    let iters: u32 = env::read();
    let y = Fr::from(2u64);
    let z = Fr::from(3u64);

    let c0 = env::cycle_count();
    let mut hasher = Poseidon::<Fr>::new_circom(arity as usize).unwrap();
    let c1 = env::cycle_count();

    let mut x = Fr::from(1u64);
    for _ in 0..iters {
        x = match arity {
            1 => hasher.hash(&[x]).unwrap(),
            2 => hasher.hash(&[x, y]).unwrap(),
            _ => hasher.hash(&[x, y, z]).unwrap(),
        };
    }
    let c2 = env::cycle_count();

    let out = x.into_bigint().to_bytes_be();
    env::commit(&(c1 - c0, c2 - c1, out));
}
