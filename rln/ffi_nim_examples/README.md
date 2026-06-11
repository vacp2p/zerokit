# RLN FFI Nim Examples

These examples demonstrate how to use the RLN C FFI from Nim. Most examples run in stateful mode with a persistent Merkle tree; `stateless.nim` shows the stateless mode where the Merkle proof is computed on the caller side.

| File | Description |
| --- | --- |
| [rln.nim](rln.nim) | FFI bindings: types, imported functions, and byte helpers for the RLN shared library |
| [common.nim](common.nim) | Shared helpers included directly by all examples |
| [basic_proof.nim](basic_proof.nim) | Creates a witness, generates a proof, reads the proof values, and verifies the proof |
| [type_serialization.nim](type_serialization.nim) | Serializes a witness and a proof to bytes and back, then verifies the deserialized proof |
| [recover_secret.nim](recover_secret.nim) | Sends two messages with the same message id, then recovers the identity secret from the two proofs |
| [partial_proof.nim](partial_proof.nim) | Generates a partial proof ahead of time, finishes it with the full witness, and verifies the result |
| [multi_message_id.nim](multi_message_id.nim) | Runs the proof and recover secret flows in Multi message-id mode, where one proof covers several message ids |
| [stateless.nim](stateless.nim) | Stateless mode: computes the Merkle proof manually and verifies with an explicit root list |

## Build the RLN library

From the repository root:

```bash
cargo build -p rln --release
```

This produces the shared library in `target/release`:

- macOS: `librln.dylib`
- Linux: `librln.so`
- Windows: `rln.dll`

## Build and run the examples

From this directory:

```bash
nim c -d:release basic_proof.nim
nim c -d:release type_serialization.nim
nim c -d:release recover_secret.nim
nim c -d:release partial_proof.nim
nim c -d:release multi_message_id.nim
nim c -d:release stateless.nim
./basic_proof
./type_serialization
./recover_secret
./partial_proof
./multi_message_id
./stateless
```

Notes:

- The examples link dynamically and embed an rpath pointing at `../../target/release`,
  so they normally run without extra setup.
- The examples auto-pick a platform-specific default library name.
  You can override it with `-d:RLN_LIB:"/absolute/path/to/lib"` if needed.
- If your OS linker cannot find the library at runtime, set an environment variable:

macOS:

```bash
DYLD_LIBRARY_PATH=../../target/release ./basic_proof
```

Linux:

```bash
LD_LIBRARY_PATH=../../target/release ./basic_proof
```

Windows (PowerShell):

```powershell
$env:PATH = "$PWD\..\..\target\release;$env:PATH"
./basic_proof.exe
```
