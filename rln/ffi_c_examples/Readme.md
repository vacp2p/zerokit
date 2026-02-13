# RLN FFI C example

This example demonstrates how to use the RLN C FFI in stateful, stateless, and multi-message-id modes.

## Stateful mode

### Compile lib stateful

```bash
cargo build -p rln --release
cargo run --features headers --bin generate-headers
mv -v rln.h rln/ffi_c_examples/
```

### Compile and run example stateful

```bash
cd rln/ffi_c_examples/
gcc -Wall main.c -o main -lrln -L../../target/release
./main
```

## Stateless mode

### Compile lib stateless

```bash
cargo build -p rln --release --no-default-features --features stateless
cargo run --no-default-features --features stateless,headers --bin generate-headers
mv -v rln.h rln/ffi_c_examples/
```

### Compile example stateless

```bash
cd rln/ffi_c_examples/
gcc -Wall -DSTATELESS main.c -o main -lrln -L../../target/release
./main
```

## Multi-message-id mode

### Compile lib multi-message-id

```bash
cargo build -p rln --release --features multi-message-id
cargo run --features multi-message-id,headers --bin generate-headers
mv -v rln.h rln/ffi_c_examples/
```

### Compile example multi-message-id

```bash
cd rln/ffi_c_examples/
gcc -Wall -DMULTI_MESSAGE_ID main.c -o main -lrln -L../../target/release
./main
```

## Note

### Find C lib used by Rust

```bash
cargo +nightly rustc --release -p rln -- -Z unstable-options --print native-static-libs
```
