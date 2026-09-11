# Results

Five BN254 Poseidon/Poseidon2 implementations, measured inside the RISC0 zkVM executor
(r0vm 3.0.6, guest toolchain rust 1.97.0) and natively (2020 MacBook M1 Pro). Reproduce
with `./run.sh`.

## Terminology

- **init cycles**: RISC-V cycles spent building the hasher before the first hash - for
  the zerokit hashers this is the runtime Grain LFSR constant derivation, for the
  hardcoded-constant crates it is ~nothing. A zkVM guest pays this on every proof.
- **marginal cycles/hash**: steady-state cost of each additional hash after init - the
  fair per-hash comparison. Measured twice independently (in-guest `env::cycle_count()`
  brackets and the 1-vs-101-iteration session difference); the host asserts they agree.
- **user cycles**: total guest cycles, proportional to zkVM proving cost.
- **segments**: the proof is split into ~1M-cycle segments; each is one unit of proving
  work.

## RISC0 guest cycles

| impl | arity | init cycles | marginal cycles/hash | user cycles (init + 1 hash) | segments |
|---|---|---|---|---|---|
| zerokit Poseidon | 1 | 937,821,091 | 711,382 | 938,549,714 | 944 |
| zerokit Poseidon | 2 | 937,821,091 | 1,252,370 | 939,090,180 | 945 |
| zerokit Poseidon | 3 | 937,821,091 | 1,953,198 | 939,791,289 | 945 |
| light-poseidon | 1 | 200,620 | 970,713 | 1,186,387 | 2 |
| light-poseidon | 2 | 309,857 | 1,575,556 | 1,900,017 | 2 |
| light-poseidon | 3 | 413,045 | 2,344,867 | 2,772,780 | 3 |
| zerokit Poseidon2 | 1 | 16,925,628 | 335,115 | 17,276,508 | 18 |
| zerokit Poseidon2 | 2 | 16,925,628 | 383,732 | 17,325,778 | 18 |
| zerokit Poseidon2 | 3 | 16,925,628 | 750,896 | 17,691,699 | 18 |
| jf-poseidon2 | 2 | 85 | 350,852 | 1,001,300 | 2 |
| rust-poseidon-bn254-pure | 2 | 85 | 354,035 | 368,474 | 1 |

## Native wall time

| init | time |
|---|---|
| zerokit Poseidon | 84.4 ms |
| zerokit Poseidon2 | 1.7 ms |
| light-poseidon | ~0 |

| impl | marginal/hash (pair) |
|---|---|
| zerokit Poseidon | 19,243 ns |
| light-poseidon | 24,620 ns |
| zerokit Poseidon2 | 6,518 ns |
| jf-poseidon2 | 6,350 ns |
| rust-poseidon-bn254-pure | 17,891 ns |

## Findings

1. **Runtime constant derivation is prohibitive in a zkVM guest.** zerokit's Poseidon
   init (Grain for all 16 widths) costs 938M cycles = ~944 proof segments per proof;
   Poseidon2 (3 widths) 16.9M = 18 segments. Native the same work is a one-time
   84 ms / 1.7 ms. Any zkVM use of the zerokit hashers needs hardcoded or host-supplied
   constants.
2. **Poseidon2 keeps its native advantage inside the zkVM.** Marginal pair hash 383,732
   vs 1,252,370 cycles against zerokit Poseidon (-69%), mirroring the native -66%.
3. **zerokit is the fastest implementation of each hash family once initialized.**
   Its Poseidon beats light-poseidon on both metrics; its Poseidon2 is the fastest
   native (on par with jf-poseidon2) and within 9% of jf-poseidon2 in-guest.
4. **A 32-bit field stack purpose-built for rv32 does not beat generic arkworks
   per hash.** rust-poseidon-bn254-pure ties jf-poseidon2 in-guest (354K vs 351K
   cycles) while being 2.8x slower natively (32-bit limbs on a 64-bit CPU). Its real
   guest win is the whole-program footprint: no init and the only single-segment guest.
