# RLN Nim FFI example

This example shows how to use the RLN C FFI from Nim in stateless mode. It demonstrates:

- Creating an RLN handle using the stateless constructor
- Building a witness for a mock Merkle path (no exported tree APIs)
- Generating a proof and verifying it

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
# Stateless (uses local mock path, no tree exports)
nim c -d:release -d:ffiStateless main.nim

# Non-stateless (uses exported tree APIs to insert leaf and fetch proof)
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

You should see output similar to:

```powershell
RLN created
Witness built
Proof generated
Verify: OK
```

## What the example does (stateless mode)

1) Creates an RLN handle via the stateless constructor.

2) Generates identity keys and sets a `user_message_limit` and `message_id`.

3) Hashes a signal and external nullifier (`ffi_hash`).

4) Computes `rateCommitment = Poseidon(id_commitment, user_message_limit)` using `ffi_poseidon_hash`.

5) Builds a mock Merkle path for an empty depth-20 tree at index 0 (no exported tree APIs):

   - Path siblings: level 0 sibling is `0`,
    then each level uses precomputed default hashes `H(0,0)`, `H(H(0,0),H(0,0))`, ...
   - Path indices: all zeros (left at every level)
   - Root: folds the path upwards with `rateCommitment` at index 0

6) Builds the witness, generates the proof, and verifies it with `ffi_verify_with_roots`,
   passing a one-element roots vector containing the computed root (length must be 1).

## What the example does (non-stateless mode)

1) Creates an RLN handle with a Merkle tree backend and configuration.

2) Generates identity keys and computes `rateCommitment = Poseidon(id_commitment, user_message_limit)`.

3) Inserts the leaf with `ffi_set_next_leaf` and fetches a real Merkle path for index 0 via `ffi_get_proof`.

4) Builds the witness from the exported proof, generates the proof, and verifies with `ffi_verify_rln_proof` using the current tree root.
