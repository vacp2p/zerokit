# RLN for WASM

This library is used in [waku-org/js-rln](https://github.com/waku-org/js-rln/)

> **Note**: This project requires `wasm-pack` for compiling Rust to WebAssembly and `cargo-make` for running the build commands. Make sure both are installed before proceeding.

Install `wasm-pack`

```bash
curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh
```

Install `cargo-make`

```bash
cargo install cargo-make
```

OR

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

Compile a slimmer version of zerokit for `wasm32-unknown-unknown`:

```bash
cargo make post-build
```

## Running tests and benchmarks

```bash
cargo make test
```

## Publishing a npm package

```bash
cargo make login
cargo make publish
```
