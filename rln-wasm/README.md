# RLN for WASM
This library is used in [waku-org/js-rln](https://github.com/waku-org/js-rln/)

## Building the library
1. Make sure you have nodejs installed and the `build-essential` package if using ubuntu.
2. Install wasm-pack
```
curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh
```
3. Compile zerokit for `wasm32-unknown-unknown`:
```
cd rln-wasm
wasm-pack build --release
```

## Running tests
```
cd rln-wasm
wasm-pack test --node --release
```