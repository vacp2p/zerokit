# Compile and Run

## Non-stateless mode

### Compile lib non-stateless

```bash
cargo build -p rln
cargo run --features headers --bin generate-headers
mv -v rln.h rln/ffi_c_examples/
```

### Compile and run example non-stateless

```bash
cd rln/ffi_c_examples/
gcc -Wall main.c -o main -lrln -L../../target/debug
./main
```

## Stateless mode

### Compile lib stateless

```bash
cargo build -p rln --no-default-features --features stateless
cargo run  --no-default-features --features stateless,headers --bin generate-headers
mv -v rln.h rln/ffi_c_examples/
```

### Compile example stateless

```bash
cd rln/ffi_c_examples/
gcc -Wall -DSTATELESS main.c -o main -lrln -L../../target/debug
./main
```

## Note

### Find C lib used by Rust

```bash
cargo +nightly rustc --release -p rln -- -Z unstable-options --print native-static-libs
```
