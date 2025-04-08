# RLN for WASM

This library is used in [waku-org/js-rln](https://github.com/waku-org/js-rln/)

> **Note**: This project requires `wasm-pack` for compiling Rust to WebAssembly and `cargo-make` for running the build commands. Make sure both are installed before proceeding.

Install `wasm-pack`:

```bash
curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh
```

Install `cargo-make`

```bash
cargo install cargo-make
```

Or install everything needed for `zerokit` at the root of the repository:

```bash
make installdeps
```

## Building the library

First, navigate to the rln-wasm directory:

```bash
cd rln-wasm
```

Compile zerokit for `wasm32-unknown-unknown`:

```bash
cargo make build
```

Or compile with the **arkzkey** feature enabled

```bash
cargo make build_arkzkey
```

## Running tests and benchmarks

```bash
cargo make test
```

Or test with the **arkzkey** feature enabled

```bash
cargo make test_arkzkey
```
