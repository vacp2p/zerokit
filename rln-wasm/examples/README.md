# RLN WASM Node Examples

This example demonstrates how to use the RLN WASM package in a Node.js environment.

## Build the @waku/zerokit-rln-wasm package at the root of rln-wasm module

### Standard mode

```bash
cargo make build
```

### Multi-message-id mode

```bash
cargo make build_multi_message_id
```

## Running the examples

After building the package in any mode, install dependencies and run:

```bash
cd examples
npm install
npm start
```

**Note:** Set `MULTI_MESSAGE_ID` constant in [index.js](../examples/index.js) to `true` when testing with multi-message-id features.
