## Compile lib

* cargo build -p rln && cargo run --features headers --bin generate-headers && mv -v rln.h rln/ffi_c_examples/

## Compile example

* cd rln/ffi_c_examples/
* gcc -Wall main.c -o main -l:librln.a -lm -L../../target/debug

## Note

### Find C lib used by Rust

cargo +nightly rustc --release -p rln -- -Z unstable-options --print native-static-libs