# Zerokit RLN-CLI

The Zerokit RLN-CLI provides a command-line interface for interacting with the public API of the [Zerokit RLN Module](../rln/README.md).

It also contain:

+ [Relay Example](#relay-example) to demonstrate the use of the RLN module for spam prevention.
+ [Stateless Example](#stateless-example) to demonstrate the use of the RLN module for stateless features.

## Configuration

The CLI can be configured using a JSON configuration file (see the [example](example.config.json)).

You can specify the configuration file path using the `RLN_CONFIG_PATH` environment variable:

```bash
export RLN_CONFIG_PATH=example.config.json
```

Alternatively, you can provide the configuration file path as an argument for each command:

```bash
RLN_CONFIG_PATH=example.config.json cargo run -- <SUBCOMMAND> [OPTIONS]
```

If the configuration file is empty, default settings will be used, but the tree data folder will be temporary and not saved to the preconfigured path.

We recommend using the example config, as all commands (except `new` and `create-with-params`) require an initialized RLN instance.

## Feature Flags

The CLI supports optional features. To enable the **arkzkey** feature, run:

```bash
cargo run --features arkzkey -- <SUBCOMMAND> [OPTIONS]
```

For more details, refer to the [Zerokit RLN Module](../rln/README.md) documentation.

## Relay Example

The following [Example](src/examples/relay.rs) demonstrates how RLN enables spam prevention in anonymous environments for multple users.

You can run the example using the following command:

```bash
cargo run --example relay
```

or with the **arkzkey** feature flag:

```bash
cargo run --example relay --features arkzkey
```

You can also change **MESSAGE_LIMIT** and **TREEE_HEIGHT** in the [relay.rs](src/examples/relay.rs) file to see how the RLN instance behaves with different parameters.

The customize **TREEE_HEIGHT** constant differs from the default value of `10` and `20` should follow [Custom Circuit Compilation](../rln/README.md#custom-circuit-compilation) instructions.

## Stateless Example

The following [Example](src/examples/stateless.rs) demonstrates how RLN can be used for stateless features by creating the Merkle tree outside of RLN instance.

This example function similarly to the [Relay Example](#relay-example) but uses a stateless RLN and seperate Merkle tree.

You can run the example using the following command:

```bash
cargo run --example stateless --features stateless
```

or with the **arkzkey** feature flag:

```bash
cargo run --example stateless --features stateless,arkzkey
```

## CLI Commands

### Instance Management

To initialize a new RLN instance:

```bash
cargo run new --tree-height <HEIGHT>
```

To initialize an RLN instance with custom parameters:

```bash
cargo run new-with-params --resources-path <PATH> --tree-height <HEIGHT>
```

To update the Merkle tree height:

```bash
cargo run set-tree --tree-height <HEIGHT>
```

### Leaf Operations

To set a single leaf:

```bash
cargo run set-leaf --index <INDEX> --input <INPUT_PATH>
```

To set multiple leaves:

```bash
cargo run set-multiple-leaves --index <START_INDEX> --input <INPUT_PATH>
```

To reset multiple leaves:

```bash
cargo run reset-multiple-leaves --input <INPUT_PATH>
```

To set the next available leaf:

```bash
cargo run set-next-leaf --input <INPUT_PATH>
```

To delete a specific leaf:

```bash
cargo run delete-leaf --index <INDEX>
```

### Proof Operations

To generate a proof:

```bash
cargo run prove --input <INPUT_PATH>
```

To generate an RLN proof:

```bash
cargo run generate-proof --input <INPUT_PATH>
```

To verify a proof:

```bash
cargo run verify --input <PROOF_PATH>
```

To verify a proof with multiple Merkle roots:

```bash
cargo run verify-with-roots --input <INPUT_PATH> --roots <ROOTS_PATH>
```

### Tree Information

To retrieve the current Merkle root:

```bash
cargo run get-root
```

To obtain a Merkle proof for a specific index:

```bash
cargo run get-proof --index <INDEX>
```
