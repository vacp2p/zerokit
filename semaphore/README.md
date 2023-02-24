# Semaphore example package

This is basically a wrapper around/copy of
https://github.com/worldcoin/semaphore-rs to illustrate how e.g. RLN package
can be structured like.

Goal is also to provide a basic FFI around protocol.rs, which is currently not
in scope for that project.

See that project for more information.

## Build and Test

To build and test, run the following commands within the module folder
```bash
cargo make build
cargo make test
```
