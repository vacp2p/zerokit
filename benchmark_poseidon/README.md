# benchmark_poseidon

Benchmarks five BN254 Poseidon/Poseidon2 implementations twice over: RISC-V cycle counts
inside the RISC0 zkVM executor (proportional to zkVM proving cost) and native wall time
on the host CPU. Results and terminology: [RESULTS.md](RESULTS.md).

| subject | hash | constants |
|---|---|---|
| zerokit `Poseidon` (circomlib-compatible) | Poseidon | derived at runtime (Grain LFSR) |
| [light-poseidon](https://github.com/Lightprotocol/light-poseidon) | Poseidon | hardcoded |
| zerokit `Poseidon2` (HorizenLabs set, zero-last layout) | Poseidon2 | derived at runtime (Grain LFSR) |
| [jf-poseidon2](https://github.com/EspressoSystems/jellyfish) | Poseidon2 | hardcoded |
| [rust-poseidon-bn254-pure](https://github.com/logos-storage/rust-poseidon-bn254-pure) (self-contained 32-bit-limb field stack written for rv32; vendored in `vendor/`, pinned at the revision LEZ PR #304 benchmarks) | Poseidon2 | hardcoded |

## Run

Requires a [rzup-installed](https://dev.risczero.com/api/zkvm/install) RISC0 toolchain.

```bash
./run.sh
```
