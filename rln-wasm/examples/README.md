# RLN WASM Node Examples

This example demonstrates how to use the RLN WASM package in a Node.js environment.

## Build the @waku/zerokit-rln-wasm package at the root of rln-wasm module

```bash
cargo make build
```

## Running the examples

**Note:** Set `MULTI_MESSAGE_ID` constant in [index.js](../examples/index.js) to `true` when testing with multi-message-id mode.

After building the package in any mode, install dependencies and run:

```bash
cd examples
npm install
npm start
```
