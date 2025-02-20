# Zerokit

[![Crates.io](https://img.shields.io/crates/v/rln.svg)](https://crates.io/crates/rln)
[![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/vacp2p/zerokit/ci.yml?branch=master&label=CI)](https://github.com/vacp2p/zerokit/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

A collection of Zero Knowledge modules written in Rust and designed to be used in other system programming environments.

## Overview

Zerokit provides zero-knowledge cryptographic primitives with a focus on performance, security, and usability. The current focus is on Rate-Limiting Nullifier (RLN) implementation.

## Features

- **RLN Implementation**: Efficient Rate-Limiting Nullifier using zkSNARKs
- **Circom Compatibility**: Uses Circom-based circuits for RLN
- **Cross-Platform**: Support for multiple architectures (see compatibility note below)
- **FFI-Friendly**: Easy to integrate with other languages

## Architecture

Zerokit currently focuses on RLN (Rate-Limiting Nullifier) implementation using [Circom](https://iden3.io/circom) circuits through ark-circom, providing an alternative to existing native Rust implementations.

## Build and Test

> [!IMPORTANT]
> For WASM support or x32 architecture builds, use version `0.6.1`. Current version has dependency issues for these platforms. WASM support will return in a future release.

### Install Dependencies

```bash
make installdeps
```

### Build and Test All Crates

```bash
make build
make test
```

## Release Assets

We use [`cross-rs`](https://github.com/cross-rs/cross) to cross-compile and generate release assets:

```bash
# Example: Build for specific target
cross build --target x86_64-unknown-linux-gnu --release -p rln
```

## Used By

Zerokit powers zero-knowledge functionality in:

- [**nwaku**](https://github.com/waku-org/nwaku) - Nim implementation of the Waku v2 protocol
- [**js-rln**](https://github.com/waku-org/js-rln) - JavaScript bindings for RLN

## Acknowledgements

- Inspired by [Applied ZKP](https://zkp.science/) group work, including [zk-kit](https://github.com/appliedzkp/zk-kit)
- Uses [ark-circom](https://github.com/gakonst/ark-circom) for zkey and Groth16 proof generation
- Witness calculation based on [circom-witnesscalc](https://github.com/iden3/circom-witnesscalc) by iden3. The execution graph file used by this code has been generated by means of the same iden3 software.

> [!IMPORTANT]
> The circom-witnesscalc code fragments have been borrowed instead of depending on this crate, because its types of input and output data were incompatible with the corresponding zerokit code fragments, and circom-witnesscalc has some dependencies, which are redundant for our purpose.

## Documentation

For detailed documentation on each module:

```bash
cargo doc --open
```
