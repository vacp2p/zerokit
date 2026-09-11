#!/bin/bash
# Runs both benchmark suites: RISC-V cycle counts inside the RISC0 executor, then the
# native wall-time counterpart. Requirements: a rzup-installed RISC0 toolchain
# (https://dev.risczero.com/api/zkvm/install).
#
# RISC0_SKIP_BUILD_KERNELS: the executor is pure CPU and never uses the GPU prover
# kernels; skipping them lets the host build on a CommandLineTools-only mac.
# RUSTC_BOOTSTRAP: rust-poseidon-bn254-pure uses nightly feature gates; this lets the
# pinned stable toolchain accept them, matching how the RISC0 guest toolchain builds it.
set -e
cd "$(dirname "$0")"

export RISC0_SKIP_BUILD_KERNELS=1
export RUSTC_BOOTSTRAP=1

echo "== RISC0 guest cycles =="
cargo run --release -p host

echo
echo "== native wall time =="
cargo run --release -p native
