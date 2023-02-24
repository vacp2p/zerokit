# Multiplier example

Example wrapper around a basic Circom circuit to test Circom 2 integration
through ark-circom and FFI.

## Build and Test

To build and test, run the following commands within the module folder
```bash
cargo make build
cargo make test
```

## FFI

To generate C or Nim bindings from Rust FFI, use `cbindgen` or `nbindgen`:

```
cbindgen . -o target/multiplier.h
nbindgen . -o target/multiplier.nim
```
