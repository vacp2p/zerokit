# RLN FFI Nim example

This example demonstrates how to use the RLN C FFI from Nim in stateful, stateless, and multi-message-id modes.

## Build the RLN library

From the repository root:

```bash
# Stateful build (with tree APIs)
cargo build -p rln --release

# Stateless build (no tree APIs)
cargo build -p rln --release --no-default-features --features stateless

# Multi-message-id build
cargo build -p rln --release --features multi-message-id
```

This produces the shared library in `target/release`:

- macOS: `librln.dylib`
- Linux: `librln.so`
- Windows: `rln.dll`

## Build the Nim example

From this directory:

```bash
# Stateful mode (uses exported tree APIs to insert leaf and fetch proof)
nim c -d:release main.nim

# Stateless mode (no tree APIs, uses mock Merkle path)
nim c -d:release -d:ffiStateless main.nim

# Multi-message-id mode (with rate limiting using multiple message slots)
nim c -d:release -d:ffiMultiMessageId main.nim
```

Notes:

- The example links dynamically. If your OS linker cannot find the library at runtime,
  set an rpath or environment variable as shown below.
- The example auto-picks a platform-specific default library name.
  You can override it with `-d:RLN_LIB:"/absolute/path/to/lib"` if needed.
- **Important**: Ensure the RLN library is compiled with the same feature flags as the Nim example.
  For example, if you compile the Nim example with `-d:ffiMultiMessageId`, the library must be built
  with `--features multi-message-id`.

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

### Stateful mode (default)

1. Creates an RLN handle with a Merkle tree backend and configuration.
2. Generates identity keys and computes `rateCommitment = Poseidon(id_commitment, user_message_limit)`.
3. Inserts the leaf with `ffi_set_next_leaf` and fetches a real Merkle path for index 0 via `ffi_get_merkle_proof`.
4. Builds the witness from the exported proof, generates the proof, and verifies with `ffi_verify_rln_proof` using the current tree root.
5. Simulates a double-signaling attack and recovers the identity secret from two proofs.

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

### Multi-message-id mode

1. Creates an RLN handle with the multi-message-id configuration.
2. Generates identity keys and computes `rateCommitment = Poseidon(id_commitment, user_message_limit)`.
3. Creates a message_ids vector with 4 slots and a selector indicating which 2 slots are used (e.g., slots 0 and 1).
4. Builds the witness with the additional message_ids and selector_used parameters.
5. Generates and verifies the proof, which includes multiple `ys` and `nullifiers` values (one per slot).
6. Simulates a double-signaling attack by reusing one of the message slots (slot 1) in a second message, allowing the identity secret to be recovered via slashing.
