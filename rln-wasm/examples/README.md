# RLN WASM Node Examples

These examples demonstrate how to use the RLN WASM package in a Node.js environment.

| File | Description |
| --- | --- |
| [common.js](common.js) | Shared helpers used by all examples |
| [basic_proof.js](basic_proof.js) | Creates a witness, generates a proof, reads the proof values, and verifies the proof |
| [type_serialization.js](type_serialization.js) | Serializes a witness and a proof to bytes and back, then verifies the deserialized proof |
| [recover_secret.js](recover_secret.js) | Sends two messages with the same message id, then recovers the identity secret from the two proofs |
| [partial_proof.js](partial_proof.js) | Generates a partial proof ahead of time, finishes it with the full witness, and verifies the result |
| [multi_message_id.js](multi_message_id.js) | Runs the proof and recover secret flows in Multi message-id mode, where one proof covers several message ids |

## Build the package

At the root of the rln-wasm module:

```bash
cargo make build
```

## Run the examples

```bash
cd examples
npm install
npm run basic_proof
npm run type_serialization
npm run recover_secret
npm run partial_proof
npm run multi_message_id
```

Or run everything in order:

```bash
npm run all
```
