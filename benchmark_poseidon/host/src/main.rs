// Runs every guest through the RISC0 executor (no proving) and reports RISC-V cycle
// counts per hash implementation: init cost (constant setup) and marginal cost per hash,
// from two sources that must agree - the in-guest cycle_count() brackets and the
// difference between the 1-iteration and 101-iteration sessions.

use methods::{P1_LIGHT_ELF, P1_ZEROKIT_ELF, P2_JF_ELF, P2_PURE_ELF, P2_ZEROKIT_ELF};
use risc0_zkvm::{ExecutorEnv, ExecutorImpl};

const ITERS_SHORT: u32 = 1;
const ITERS_LONG: u32 = 101;

struct Run {
    init_cycles: u64,
    loop_cycles: u64,
    user_cycles: u64,
    segments: usize,
    out: Vec<u8>,
}

fn run(elf: &[u8], arity: u32, iters: u32) -> Run {
    let env = ExecutorEnv::builder()
        .write(&arity)
        .unwrap()
        .write(&iters)
        .unwrap()
        .build()
        .unwrap();
    let mut exec = ExecutorImpl::from_elf(env, elf).unwrap();
    let session = exec.run().unwrap();
    let (init_cycles, loop_cycles, out): (u64, u64, Vec<u8>) =
        session.journal.as_ref().unwrap().decode().unwrap();
    Run {
        init_cycles,
        loop_cycles,
        user_cycles: session.user_cycles,
        segments: session.segments.len(),
        out,
    }
}

fn main() {
    // (display name, guest ELF, arities). rust-poseidon-bn254-pure is pinned at the
    // revision LEZ PR #304 benchmarks, which predates its "new"-constant tables, so it
    // is excluded from the correctness gates; the per-hash work is identical.
    let subjects: [(&str, &[u8], &[u32]); 5] = [
        ("zerokit Poseidon", P1_ZEROKIT_ELF, &[1, 2, 3]),
        ("light-poseidon", P1_LIGHT_ELF, &[1, 2, 3]),
        ("zerokit Poseidon2", P2_ZEROKIT_ELF, &[1, 2, 3]),
        ("jf-poseidon2", P2_JF_ELF, &[2]),
        ("rust-poseidon-bn254-pure", P2_PURE_ELF, &[2]),
    ];

    println!("| impl | arity | init cycles | marginal cycles/hash | user cycles (init + 1 hash) | segments |");
    println!("|---|---|---|---|---|---|");

    let mut outputs: Vec<(String, u32, Vec<u8>)> = Vec::new();
    for (name, elf, arities) in subjects {
        for &arity in arities {
            let short = run(elf, arity, ITERS_SHORT);
            let long = run(elf, arity, ITERS_LONG);
            let guest_marginal = long.loop_cycles / ITERS_LONG as u64;
            let session_marginal =
                (long.user_cycles - short.user_cycles) / (ITERS_LONG - ITERS_SHORT) as u64;
            // The two measurements come from independent counters; a large disagreement
            // means the harness is broken.
            assert!(
                session_marginal.abs_diff(guest_marginal) < guest_marginal / 10,
                "cycle counters disagree for {name} arity {arity}"
            );
            println!(
                "| {name} | {arity} | {} | {} | {} | {} |",
                short.init_cycles, guest_marginal, short.user_cycles, short.segments,
            );
            outputs.push((name.to_string(), arity, long.out));
        }
    }

    // Correctness gates: the circomlib-compatible Poseidon implementations must agree,
    // and the two zero-last Poseidon2 implementations must agree at arity 2.
    for arity in [1u32, 2, 3] {
        let a = &outputs
            .iter()
            .find(|o| o.0 == "zerokit Poseidon" && o.1 == arity)
            .unwrap()
            .2;
        let b = &outputs
            .iter()
            .find(|o| o.0 == "light-poseidon" && o.1 == arity)
            .unwrap()
            .2;
        assert_eq!(a, b, "zerokit Poseidon and light-poseidon disagree at arity {arity}");
    }
    let a = &outputs
        .iter()
        .find(|o| o.0 == "zerokit Poseidon2" && o.1 == 2)
        .unwrap()
        .2;
    let b = &outputs
        .iter()
        .find(|o| o.0 == "jf-poseidon2" && o.1 == 2)
        .unwrap()
        .2;
    assert_eq!(a, b, "zerokit Poseidon2 and jf-poseidon2 disagree at arity 2");
    println!("\ncorrectness gates passed");
}
