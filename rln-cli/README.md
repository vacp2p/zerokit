# Zerokit RLN-CLI

The Zerokit RLN-CLI provides a command-line interface examples on how to use public API of the [Zerokit RLN Module](../rln/README.md).

## Relay Example

The following [Relay Example](src/examples/relay.rs) demonstrates how RLN enables spam prevention in anonymous environments for multple users.

You can run the example using the following command:

```bash
cargo run --example relay
```

You can also change **MESSAGE_LIMIT** and **TREE_DEPTH** in the [relay.rs](src/examples/relay.rs) file to see how the RLN instance behaves with different parameters.

The customize **TREE_DEPTH** constant differs from the default value of `20` should follow [Custom Circuit Compilation](../rln/README.md#advanced-custom-circuit-compilation) instructions.

## Stateless Example

The following [Stateless Example](src/examples/stateless.rs) demonstrates how RLN can be used for stateless features by creating the Merkle tree outside of RLN instance.

This example function similarly to the [Relay Example](#relay-example) but uses a stateless RLN and seperate Merkle tree.

You can run the example using the following command:

```bash
cargo run --example stateless --no-default-features --features stateless
```
