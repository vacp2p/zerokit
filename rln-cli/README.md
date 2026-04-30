# Zerokit RLN-CLI

The Zerokit RLN-CLI provides command-line interface examples
on how to use the public API of the
[Zerokit RLN Module](../rln/README.md).

## Relay Example

The following [Relay Example](src/examples/relay.rs) demonstrates
how RLN enables spam prevention in anonymous environments for multiple users.

You can run the example using the following command:

```bash
cargo run --example relay
```

You can also change **MESSAGE_LIMIT** and **TREE_DEPTH**
in the [relay.rs](src/examples/relay.rs) file
to see how the RLN instance behaves with different parameters.

To customize the **TREE_DEPTH** constant to differ from the default value of `20`,
follow the [Custom Circuit Compilation](../rln/README.md#advanced-custom-circuit-compilation) instructions.

## Stateless Example

The following [Stateless Example](src/examples/stateless.rs) demonstrates
how RLN can be used for stateless features
by creating the Merkle tree outside of the RLN instance.

This example functions similarly to the [Relay Example](#relay-example)
but uses a stateless RLN and separate Merkle tree.

You can run the example using the following command:

```bash
cargo run --example stateless --no-default-features --features stateless
```

## Multi Message ID Example

The following [Multi Message ID Example](src/examples/multi_message_id.rs) demonstrates
how RLN supports consuming multiple message_id units in a single proof.

This example functions similarly to the [Relay Example](#relay-example)
but uses the [multi-message-id resource files](../rln/resources/tree_depth_20/multi_message_id).

You can run the example using the following command:

```bash
cargo run --example multi_message_id
```

## Partial Proof Example

The following [Partial Proof Example](src/examples/partial.rs) demonstrates
how RLN supports accelerated proof generation
by pre-computing and caching the static witness portion,
then quickly finishing proofs for new messages.

This example functions similarly to the [Relay Example](#relay-example)
but demonstrates the partial proof optimization technique
for improved proof generation performance.

Cached partial proofs remain usable across tree changes within a small window -
verify against a bounded set of recent roots
(e.g. via [`verify_with_roots`](../rln/src/public.rs))
instead of regenerating immediately.
Once the root falls outside the allowed window,
reset by generating a new partial proof with the latest Merkle path.
See the [Partial Proof Generation](../rln/README.md#partial-proof-generation) section for details.

You can run the example using the following command:

```bash
cargo run --example partial
```
