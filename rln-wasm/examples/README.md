# RLN WASM Node Examples

These examples demonstrate how to use the RLN WASM package in a Node.js environment.

| File | Description |
| --- | --- |
| [0_common.js](0_common.js) | Shared helpers used by all examples |
| [1_basic_proof.js](1_basic_proof.js) | Creates a witness, generates a proof, reads the proof values, and verifies the proof |
| [2_serialization.js](2_serialization.js) | Serializes and deserializes every exposed type to and from bytes |
| [3_slashing.js](3_slashing.js) | Sends two messages with the same message id, then recovers the identity secret from the two proofs |
| [4_partial_proof.js](4_partial_proof.js) | Generates a partial proof ahead of time, finishes it with the full witness, and verifies the result |
| [5_multi_message_id.js](5_multi_message_id.js) | Runs the proof and slashing flows in Multi message-id mode, where one proof covers several message ids |

## Build the @waku/zerokit-rln-wasm package at the root of rln-wasm module

```bash
cargo make build
```

## Running the examples

After building the package, install dependencies and run any example:

```bash
cd examples
npm install
npm run basic
npm run serialization
npm run slashing
npm run partial
npm run multi
```

Or run everything in order:

```bash
npm run all
```
