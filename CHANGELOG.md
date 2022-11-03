## Upcoming release

Release highlights:
- Allows consumers of zerokit RLN to set leaves to the Merkle Tree from an arbitrary index. Useful for batching updates to the Merkle Tree.

The full list of changes is below.

### Features
- Creation of `set_leaves_from`, which allows consumers to add leaves to a tree from a given starting index. `init_tree_with_leaves` internally uses `set_leaves_from`, with index 0.

### Changes
- Renaming of `set_leaves` to `init_tree_with_leaves`, which is a more accurate representation of the function's utility.

### Fixes
- None

## 2022-09-19 v0.1

Initial beta release.

This release contains:

- RLN Module with API to manage, compute and verify [RLN](https://rfc.vac.dev/spec/32/) zkSNARK proofs and RLN primitives.
- This can be consumed either as a Rust API or as a C FFI. The latter means it can be easily consumed through other environments, such as [Go](https://github.com/status-im/go-zerokit-rln/blob/master/rln/librln.h) or [Nim](https://github.com/status-im/nwaku/blob/4745c7872c69b5fd5c6ddab36df9c5c3d55f57c3/waku/v2/protocol/waku_rln_relay/waku_rln_relay_types.nim).

It also contains the following examples and experiments:

- Basic [example wrapper](https://github.com/vacp2p/zerokit/tree/master/multiplier) around a simple Circom circuit to show Circom integration through ark-circom and FFI.
- Experimental [Semaphore wrapper](https://github.com/vacp2p/zerokit/tree/master/semaphore).

Feedback welcome! You can either [open an issue](https://github.com/vacp2p/zerokit/issues) or come talk to us in our [Vac Discord](https://discord.gg/PQFdubGt6d) #zerokit channel.
