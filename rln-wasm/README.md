# RLN for WASM
This library is used in [waku-org/js-rln](https://github.com/waku-org/js-rln/)

## Building the library
1. Install `wasm-pack`
```
curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh
```
2. Install `cargo-make`
```
cargo install cargo-make
```
3. Compile zerokit for `wasm32-unknown-unknown`:
```
cd rln-wasm
cargo make build
```

## Running tests
```
cd rln-wasm
cargo make test
```

## Publishing a npm package
```
cd rln-wasm
cargo make login
cargo make publish
```