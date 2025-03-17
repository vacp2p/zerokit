# RLN for WASM

This library is used in [waku-org/js-rln](https://github.com/waku-org/js-rln/)

## Building the library

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

Compile zerokit for `wasm32-unknown-unknown`:

```bash
cd rln-wasm
cargo make build
```

Compile a slimmer version of zerokit for `wasm32-unknown-unknown`:

```bash
cd rln-wasm
cargo make post-build
```

## Running tests

```bash
cd rln-wasm
cargo make test
```

## Publishing a npm package

```bash
cd rln-wasm
cargo make login
cargo make publish
```
