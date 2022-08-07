# Zerokit RLN Module

This module provides APIs to manage, compute and verify [RLN](https://rfc.vac.dev/spec/32/) zkSNARK proofs and RLN primitives.

Currently, this module comes with three [pre-compiled](https://github.com/vacp2p/zerokit/tree/master/rln/resources) RLN circuits having Merkle tree of height `15`, `19` and `20`, respectively.

Implemented tests can be executed by running within the module folder

`cargo test --release`

## Compiling circuits

`rln` (https://github.com/privacy-scaling-explorations/rln) repo with Circuits is contained as a submodule. 

``` sh
# Update submodules
git submodule update --init --recursive

# Install rln dependencies
cd vendor/rln/ && npm install

# Build circuits
./scripts/build-circuits.sh rln

# Copy over assets
cp build/zkeyFiles/rln-final.zkey ../../resources/tree_height_15
cp build/zkeyFiles/rln.wasm ../../resources/tree_height_15
```

Note that the above code snippet will compile a RLN circuit with a Merkle tree of height equal `15` based on the default value set in `rln/circuit/rln.circom`.

To compile a RLN circuit with Merkle tree height `N`, it suffices to change `rln/circuit/rln.circom` to

```
pragma circom 2.0.0;

include "./rln-base.circom";

component main {public [x, epoch, rln_identifier ]} = RLN(N);
```

However, if `N` is too big, this might require a bigger Powers of Tau ceremony than the one hardcoded in `./scripts/build-circuits.sh`, which is `2^14`. 
In such case we refer to the official [Circom documentation](https://docs.circom.io/getting-started/proving-circuits/#powers-of-tau) for instructions on how to run an appropriate Powers of Tau ceremony and Phase 2 in order to compile the desired circuit.