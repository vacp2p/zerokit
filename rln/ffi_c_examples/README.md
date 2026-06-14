# RLN FFI C Examples

These examples demonstrate how to use the RLN C FFI. Most examples run in stateful mode with a persistent Merkle tree; `stateless.c` shows the stateless mode where the Merkle proof is computed on the caller side.

| File | Description |
| --- | --- |
| [rln.h](rln.h) | Generated C header for the RLN FFI, produced by the `generate_headers` step below |
| [common.c](common.c) | Shared helpers included directly by all examples |
| [basic_proof.c](basic_proof.c) | Creates a witness, generates a proof, reads the proof values, and verifies the proof |
| [type_serialization.c](type_serialization.c) | Serializes a witness and a proof to bytes and back, then verifies the deserialized proof |
| [recover_secret.c](recover_secret.c) | Sends two messages with the same message id, then recovers the identity secret from the two proofs |
| [partial_proof.c](partial_proof.c) | Generates a partial proof ahead of time, finishes it with the full witness, and verifies the result |
| [multi_message_id.c](multi_message_id.c) | Runs the proof and recover secret flows in Multi message-id mode, where one proof covers several message ids |
| [stateless.c](stateless.c) | Stateless mode: computes the Merkle proof manually and verifies with an explicit root list |

## Compile the library and generate the header

```bash
cargo build -p rln --release
cargo run --features headers --bin generate_headers
mv -v rln.h rln/ffi_c_examples/
```

## Compile and run the examples

```bash
cd rln/ffi_c_examples/
gcc -Wall basic_proof.c -o basic_proof -lrln -L../../target/release
gcc -Wall type_serialization.c -o type_serialization -lrln -L../../target/release
gcc -Wall recover_secret.c -o recover_secret -lrln -L../../target/release
gcc -Wall partial_proof.c -o partial_proof -lrln -L../../target/release
gcc -Wall multi_message_id.c -o multi_message_id -lrln -L../../target/release
gcc -Wall stateless.c -o stateless -lrln -L../../target/release
./basic_proof
./type_serialization
./recover_secret
./partial_proof
./multi_message_id
./stateless
```

## Memory ownership

- Every pointer returned by the FFI is owned by the caller and must be released with its matching `ffi_*_free` function (`ffi_cfr_free`, `ffi_rln_proof_free`, `ffi_rln_witness_input_free`, ...).
- Debug and error strings are Rust `Vec<u8>`; release them with `ffi_c_string_free`.
- `ffi_vec_cfr_get` returns a borrowed pointer into the vector: do not free it, and do not use it after the vector itself is freed.
- The examples free everything explicitly to document this contract.

## Notes

The examples link against the shared library (`-lrln`). If you instead link the static library (`librln.a`), you must also link the native system libraries that the Rust runtime depends on. Print that list with:

```bash
cargo +nightly rustc --release -p rln -- -Z unstable-options --print native-static-libs
```
