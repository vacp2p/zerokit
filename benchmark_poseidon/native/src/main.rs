// Native counterpart of the RISC0 guest benchmarks: the same five hash implementations,
// the same chained arity-2 workload, measured in wall time on the host CPU. Init is the
// constant setup (runtime Grain derivation for the zerokit hashers, ~nothing for the
// hardcoded-constant crates); marginal is the steady-state cost per hash.

use std::hint::black_box;
use std::time::Instant;

use ark_bn254::Fr;
use ark_ff::Zero;
use jf_poseidon2::{constants::bn254::Poseidon2ParamsBn3, Poseidon2 as JfPoseidon2};
use light_poseidon::{Poseidon as LightPoseidon, PoseidonHasher};
use rust_poseidon_bn254_pure::bn254::field::Felt;
use rust_poseidon_bn254_pure::poseidon2::permutation::permute_felt;
use zerokit_utils::poseidon::{
    Poseidon, Poseidon2, POSEIDON2_ROUND_PARAMS, POSEIDON_ROUND_PARAMS,
};

const ITERS: u32 = 200_000;

fn bench<F: FnMut(Fr) -> Fr>(name: &str, mut f: F) {
    let mut x = Fr::from(1u64);
    for _ in 0..1000 {
        x = f(x);
    }
    let t = Instant::now();
    for _ in 0..ITERS {
        x = f(x);
    }
    let ns = t.elapsed().as_nanos() as f64 / ITERS as f64;
    black_box(x);
    println!("| {name} | {ns:.0} ns |");
}

fn main() {
    let y = Fr::from(2u64);

    println!("| init | time |");
    println!("|---|---|");
    let t = Instant::now();
    let p1 = Poseidon::<Fr>::from(&POSEIDON_ROUND_PARAMS);
    println!("| zerokit Poseidon | {:.2} ms |", t.elapsed().as_secs_f64() * 1e3);
    let t = Instant::now();
    let p2 = Poseidon2::<Fr>::from(&POSEIDON2_ROUND_PARAMS);
    println!("| zerokit Poseidon2 | {:.2} ms |", t.elapsed().as_secs_f64() * 1e3);
    let t = Instant::now();
    let mut light = LightPoseidon::<Fr>::new_circom(2).unwrap();
    println!("| light-poseidon | {:.2} ms |", t.elapsed().as_secs_f64() * 1e3);
    println!();

    println!("| impl | marginal/hash (pair) |");
    println!("|---|---|");
    bench("zerokit Poseidon", |x| p1.hash(&[x, y]).unwrap());
    bench("light-poseidon", |x| light.hash(&[x, y]).unwrap());
    bench("zerokit Poseidon2", |x| p2.hash(&[x, y]).unwrap());
    bench("jf-poseidon2", |x| {
        let mut state = [x, y, Fr::zero()];
        JfPoseidon2::<Fr>::permute_mut::<Poseidon2ParamsBn3, 3>(&mut state);
        state[0]
    });

    // The pure crate uses its own field type; run the same chained workload on Felt and
    // time it with the same harness shape.
    let fy = Felt::from_u32(2);
    let fzero = Felt::from_u32(0);
    let mut fx = Felt::from_u32(1);
    for _ in 0..1000 {
        fx = permute_felt(&(fx, fy, fzero)).0;
    }
    let t = Instant::now();
    for _ in 0..ITERS {
        fx = permute_felt(&(fx, fy, fzero)).0;
    }
    let ns = t.elapsed().as_nanos() as f64 / ITERS as f64;
    black_box(format!("{fx}"));
    println!("| rust-poseidon-bn254-pure | {ns:.0} ns |");
}
