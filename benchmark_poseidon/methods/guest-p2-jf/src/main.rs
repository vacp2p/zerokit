// Measures jf-poseidon2 (HorizenLabs t = 3 instance with hardcoded constants, the crate
// Nomos wraps) as an arity-2 compression: state [x, y, 0], one raw permutation, state[0].
// Outputs must equal the p2-zerokit guest at arity 2 (same zero-last layout).

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField, Zero};
use jf_poseidon2::{constants::bn254::Poseidon2ParamsBn3, Poseidon2};
use risc0_zkvm::guest::env;

fn main() {
    let arity: u32 = env::read();
    let iters: u32 = env::read();
    assert_eq!(arity, 2, "jf-poseidon2 ships only the t = 3 Bn254 instance");
    let y = Fr::from(2u64);

    let c0 = env::cycle_count();
    // Constants are compile-time consts; there is nothing to initialize.
    let c1 = env::cycle_count();

    let mut x = Fr::from(1u64);
    for _ in 0..iters {
        let mut state = [x, y, Fr::zero()];
        Poseidon2::<Fr>::permute_mut::<Poseidon2ParamsBn3, 3>(&mut state);
        x = state[0];
    }
    let c2 = env::cycle_count();

    let out = x.into_bigint().to_bytes_be();
    env::commit(&(c1 - c0, c2 - c1, out));
}
