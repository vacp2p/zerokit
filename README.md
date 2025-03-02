# Zerokit

A set of Zero Knowledge modules, written in Rust and designed to be used in other system programming environments.

## Initial scope

Focus on RLN and being able to use [Circom](https://iden3.io/circom) based
version through ark-circom, as opposed to the native one that currently exists
in Rust.

## Acknowledgements

- Uses [ark-circom](https://github.com/gakonst/ark-circom), Rust wrapper around Circom.

- Inspired by Applied ZKP group work, e.g. [zk-kit](https://github.com/appliedzkp/zk-kit).

- [RLN library](https://github.com/kilic/rln) written in Rust based on Bellman.

- [semaphore-rs](https://github.com/worldcoin/semaphore-rs) written in Rust based on ark-circom.

- The circom witness calculation code of the rln crate is based on [circom-witnesscalc](https://github.com/iden3/circom-witnesscalc) by iden3. The execution graph file used by this code has been generated by means of the same iden3 software. The circom-witnesscalc code fragments have been borrowed instead of depending on this crate, because its types of input and output data were incompatible with the corresponding zerokit code fragments, and circom-witnesscalc has some dependencies, which are redundant for our purpose.

## Users

Zerokit is used by -

- [nwaku](https://github.com/waku-org/nwaku)
- [js-rln](https://github.com/waku-org/js-rln)

## Build and Test

To install missing dependencies, run the following commands from the root folder

```bash
make installdeps
```

To build and test all crates, run the following commands from the root folder

```bash
make build
make test
```

## Release assets

We use [`cross-rs`](https://github.com/cross-rs/cross) to cross-compile and generate release assets for rln.
