// Measures logos-storage/rust-poseidon-bn254-pure (Poseidon2 permutation with a
// self-contained 32-bit-limb field stack written for rv32 targets), pinned at the same
// revision LEZ PR #304 benchmarks, as an arity-2 compression: (x, y, 0) -> out.0.
// That revision predates the crate's "new"-constant tables, so its outputs are not
// cross-checked against the other guests; the per-hash work is identical either way.

use risc0_zkvm::guest::env;
use rust_poseidon_bn254_pure::bn254::field::Felt;
use rust_poseidon_bn254_pure::poseidon2::permutation::permute_felt;

fn main() {
    let arity: u32 = env::read();
    let iters: u32 = env::read();
    assert_eq!(arity, 2, "the pure crate is benchmarked as an arity-2 compression");
    let y = Felt::from_u32(2);
    let zero = Felt::from_u32(0);

    let c0 = env::cycle_count();
    // Constants are compile-time consts; there is nothing to initialize.
    let c1 = env::cycle_count();

    let mut x = Felt::from_u32(1);
    for _ in 0..iters {
        let out = permute_felt(&(x, y, zero));
        x = out.0;
    }
    let c2 = env::cycle_count();

    let out = format!("{x}").into_bytes();
    env::commit(&(c1 - c0, c2 - c1, out));
}
