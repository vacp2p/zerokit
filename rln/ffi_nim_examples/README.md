# RLN FFI Nim example

This example demonstrates how to use the RLN C FFI from Nim in both stateless and non-stateless modes. It covers:

- Creating an RLN handle (stateless or with Merkle tree backend)
- Generating identity keys and commitments
- Building a witness (mock Merkle path in stateless mode, real Merkle proof in non-stateless mode)
- Generating and verifying a proof
- Serializing/deserializing FFI objects (CFr, Vec\<CFr>, RLNWitnessInput, RLNProof, RLNProofValues)
- Simulating a double-signaling attack and recovering the identity secret

## Build the RLN library

From the repository root:

```bash
# Stateless build (no tree APIs)
cargo build -p rln --release --no-default-features --features stateless

# Non-stateless build (with tree APIs)
cargo build -p rln --release
```

This produces the shared library in `target/release`:

- macOS: `librln.dylib`
- Linux: `librln.so`
- Windows: `rln.dll`

## Build the Nim example (two modes)

From this directory:

```bash
# Stateless mode (no tree APIs, uses mock Merkle path)
nim c -d:release -d:ffiStateless main.nim

# Non-stateless mode (uses exported tree APIs to insert leaf and fetch proof)
nim c -d:release main.nim
```

Notes:

- The example links dynamically. If your OS linker cannot find the library at runtime,
  set an rpath or environment variable as shown below.
- The example auto-picks a platform-specific default library name.
  You can override it with `-d:RLN_LIB:"/absolute/path/to/lib"` if needed.

## Run the example

Ensure the dynamic loader can find the RLN library, then run the binary.

macOS:

```bash
DYLD_LIBRARY_PATH=../../target/release ./main
```

Linux:

```bash
LD_LIBRARY_PATH=../../target/release ./main
```

Windows (PowerShell):

```powershell
$env:PATH = "$PWD\..\..\target\release;$env:PATH"
./main.exe
```

You should see detailed output showing each step, for example:

```text
Creating RLN instance
RLN instance created successfully

Generating identity keys
Identity generated
  - identity_secret = ...
  - id_commitment = ...

Creating message limit
  - user_message_limit = ...

Computing rate commitment
  - rate_commitment = ...

CFr serialization: CFr <-> bytes
  - serialized rate_commitment = ...
  - deserialized rate_commitment = ...

Vec<CFr> serialization: Vec<CFr> <-> bytes
  - serialized keys = ...
  - deserialized keys = ...

... (Merkle path, hashing, witness, proof, verification, and slashing steps) ...

Proof verified successfully
Slashing successful: Identity is recovered!
```

## What the example does

### Stateless mode

1. Creates an RLN handle via the stateless constructor.
2. Generates identity keys, sets a `user_message_limit` and `message_id`.
3. Hashes a signal, epoch, and RLN identifier to field elements.
4. Computes `rateCommitment = Poseidon(id_commitment, user_message_limit)`.
5. Builds a mock Merkle path for an empty depth-20 tree at index 0 (no exported tree APIs):
    - Path siblings: level 0 sibling is `0`, then each level uses precomputed default hashes `H(0,0)`, `H(H(0,0),H(0,0))`, ...
    - Path indices: all zeros (left at every level)
    - Root: folds the path upwards with `rateCommitment` at index 0
6. Builds the witness, generates the proof, and verifies it with `ffi_verify_with_roots`, passing a one-element roots vector containing the computed root.
7. Simulates a double-signaling attack and recovers the identity secret from two proofs.

### Non-stateless mode

1. Creates an RLN handle with a Merkle tree backend and configuration.
2. Generates identity keys and computes `rateCommitment = Poseidon(id_commitment, user_message_limit)`.
3. Inserts the leaf with `ffi_set_next_leaf` and fetches a real Merkle path for index 0 via `ffi_get_merkle_proof`.
4. Builds the witness from the exported proof, generates the proof, and verifies with `ffi_verify_rln_proof` using the current tree root.
5. Simulates a double-signaling attack and recovers the identity secret from two proofs.
