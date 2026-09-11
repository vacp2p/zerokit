// Measures zerokit's Poseidon2 (HorizenLabs constant set, runtime Grain constant
// derivation, zero-last compression layout): init = constructing the hasher from
// POSEIDON2_ROUND_PARAMS (derives the 3 widths), steady = `iters` chained hashes.

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use risc0_zkvm::guest::env;
use zerokit_utils::poseidon::{Poseidon2, POSEIDON2_ROUND_PARAMS};

fn main() {
    let arity: u32 = env::read();
    let iters: u32 = env::read();
    let y = Fr::from(2u64);
    let z = Fr::from(3u64);

    let c0 = env::cycle_count();
    let hasher = Poseidon2::<Fr>::from(&POSEIDON2_ROUND_PARAMS);
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
