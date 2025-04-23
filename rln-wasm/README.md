# RLN for WASM

This library is used in [waku-org/js-rln](https://github.com/waku-org/js-rln/)

> [!NOTE]
> This poject requires `wasm-pack` for compiling Rust to WebAssembly and `cargo-make` for running the build commands. \
> Make sure both are installed before proceeding.

Install `wasm-pack`:

```bash
curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh
```

Install `cargo-make`

```bash
cargo install cargo-make
```

Or install everything needed for `zerokit` at the root of the repository:

```bash
make installdeps
```

## Building the library

First, navigate to the rln-wasm directory:

```bash
cd rln-wasm
```

Compile zerokit for `wasm32-unknown-unknown`:

```bash
cargo make build
```

Or compile with the **arkzkey** feature enabled

```bash
cargo make build_arkzkey
```

## Running tests and benchmarks

```bash
cargo make test
```

Or test with the **arkzkey** feature enabled

```bash
cargo make test_arkzkey
```

If you want to run the tests in browser headless mode, you can use the following command:

```bash
cargo make test_browser
cargo make test_browser_arkzkey
```

## Parallel computation

The library supports parallel computation using the `wasm-bindgen-rayon` crate, enabling multi-threaded execution in the browser.

> [!NOTE]
> Parallel support is not enabled by default due to WebAssembly and browser limitations. \
> Compiling this feature requires `nightly` Rust.

To enable parallel computation for WebAssembly threads, you can use the following command:

```bash
cargo make build_multithread
```

Or with the **arkzkey** feature enabled:

```bash
cargo make build_multithread_arkzkey
```

### WebAssembly Threading Support

Most modern browsers support WebAssembly threads, but they require the following headers to enable `SharedArrayBuffer` and multithreading:

- Cross-Origin-Opener-Policy: same-origin
- Cross-Origin-Embedder-Policy: require-corp

Without these, the application will fall back to single-threaded mode.

## Feature detection

If you're targeting [older browser versions that didn't support WebAssembly threads yet](https://webassembly.org/roadmap/), you'll likely want to make two builds - one with threads support and one without - and use feature detection to choose the right one on the JavaScript side.

You can use [wasm-feature-detect](https://github.com/GoogleChromeLabs/wasm-feature-detect) library for this purpose. The code will look roughly like this:

```js
import { threads } from 'wasm-feature-detect';

let wasmPkg;

if (await threads()) {
  wasmPkg = await import('./pkg-with-threads/index.js');
  await wasmPkg.default();
  await wasmPkg.initThreadPool(navigator.hardwareConcurrency);
} else {
  wasmPkg = await import('./pkg-without-threads/index.js');
  await wasmPkg.default();
}

wasmPkg.nowCallAnyExportedFuncs();
```
