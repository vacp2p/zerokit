# Zerokit Utils Crate

[![Crates.io](https://img.shields.io/crates/v/zerokit_utils.svg)](https://crates.io/crates/zerokit_utils)

Cryptographic primitives for zero-knowledge applications, featuring efficient Merkle tree implementations and a Poseidon hash function.

## Overview

This crate provides core cryptographic components optimized for zero-knowledge proof systems:

1. Multiple Merkle tree implementations with different space/time tradeoffs
2. A Poseidon hash implementation

## Merkle Tree Implementations

The crate supports two interchangeable Merkle tree implementations:

- **FullMerkleTree**
  - Stores each tree node in memory
- **OptimalMerkleTree**
  - Only stores nodes used to prove accumulation of set leaves

Both OptimalMerkleTree and FullMerkleTree use [Rayon](https://crates.io/crates/rayon) internally to speed up computation through data parallelism. This provides significant performance improvements, especially during large Merkle tree updates.

### Implementation notes

Glossary:

- depth: level of leaves if we count from levels from 0
- number of levels: depth + 1
- capacity (number of leaves): 1 << depth
- total number of nodes: 1 << (depth + 1) - 1

So for instance:

- depth: 3
- number of levels: 4
- capacity (number of leaves): 8
- total number of nodes: 15

```mermaid
flowchart TD
    A[Root] --> N1
    A[Root] --> N2
    N1 --> N3
    N1 --> N4
    N2 --> N5
    N2 --> N6
    N3 -->|Leaf| L1
    N3 -->|Leaf| L2
    N4 -->|Leaf| L3
    N4 -->|Leaf| L4
    N5 -->|Leaf| L5
    N5 -->|Leaf| L6
    N6 -->|Leaf| L7
    N6 -->|Leaf| L8
```

## Poseidon Hash Implementation

This crate provides an implementation to compute the Poseidon hash round constants and MDS matrices:

- **Customizable parameters**: Supports different security levels and input sizes
- **Arkworks-friendly**: Adapted to work over arkworks field traits and custom data structures

### Security Note

The MDS matrices are generated iteratively using the Grain LFSR until certain criteria are met.
According to the paper, such matrices must respect specific conditions which are checked by 3 different algorithms in the reference implementation.

These validation algorithms are not currently implemented in this crate.
For the hardcoded parameters, the first random matrix generated satisfies these conditions.
If using different parameters, you should check against the reference implementation how many matrices are generated before outputting the correct one,
and pass this number to the `skip_matrices` parameter of the `find_poseidon_ark_and_mds` function.

## Installation

Add Zerokit Utils to your Rust project:

```toml
[dependencies]
zerokit-utils = "0.5.1"
```

## Performance Considerations

- **FullMerkleTree**: Use when memory is abundant and operation speed is critical
- **OptimalMerkleTree**: Use when memory efficiency is more important than raw speed
- **Poseidon**: Offers a good balance between security and performance for ZK applications

## Building and Testing

```bash
# Build the crate
cargo make build

# Run tests
cargo make test

# Run benchmarks
cargo make bench
```

To view the results of the benchmark, open the `target/criterion/report/index.html` file generated after the bench

## Acknowledgements

- The Merkle tree implementations are adapted from:
  - [kilic/rln](https://github.com/kilic/rln/blob/master/src/merkle.rs)
  - [worldcoin/semaphore-rs](https://github.com/worldcoin/semaphore-rs/blob/d462a4372f1fd9c27610f2acfe4841fab1d396aa/src/merkle_tree.rs)

- The Poseidon implementation references:
  - [Poseidon reference implementation](https://extgit.iaik.tugraz.at/krypto/hadeshash/-/blob/master/code/generate_parameters_grain.sage)
