# RLN for WASM

[![npm version](https://badge.fury.io/js/@waku%2Fzerokit-rln-wasm.svg)](https://badge.fury.io/js/@waku%2Fzerokit-rln-wasm)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

The Zerokit RLN WASM Module provides WebAssembly bindings for working with
Rate-Limiting Nullifier [RLN](https://rfc.vac.dev/spec/32/) zkSNARK proofs and primitives.
This module is used by [waku-org/js-rln](https://github.com/waku-org/js-rln/) to enable
RLN functionality in JavaScript/TypeScript applications.

## Install Dependencies

> [!NOTE]
> This project requires the following tools:
>
> - `wasm-pack` - for compiling Rust to WebAssembly
> - `cargo-make` - for running build commands
> - `nvm` - to install and manage Node.js
>
> Ensure all dependencies are installed before proceeding.

### Manually

#### Install `wasm-pack`

```bash
cargo install wasm-pack --version=0.13.1
```

#### Install `cargo-make`

```bash
cargo install cargo-make
```

#### Install `Node.js`

If you don't have `nvm` (Node Version Manager), install it by following
the [installation instructions](https://github.com/nvm-sh/nvm?tab=readme-ov-file#install--update-script).

After installing `nvm`, install and use Node.js `v22.14.0`:

```bash
nvm install 22.14.0
nvm use 22.14.0
nvm alias default 22.14.0
```

If you already have Node.js installed,
check your version with `node -v` command — the version must be strictly greater than 22.

### Or install everything

You can run the following command from the root of the repository to install all required dependencies for `zerokit`

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

The library supports parallel computation using the `wasm-bindgen-rayon` crate,
enabling multi-threaded execution in the browser.

> [!NOTE]
> Parallel support is not enabled by default due to WebAssembly and browser limitations. \
> Compiling this feature requires `nightly` Rust and the `wasm-bindgen-cli` tool.

### Build Setup

#### Install `nightly` Rust

```bash
rustup install nightly
```

#### Install `wasm-bindgen-cli`

```bash
cargo install wasm-bindgen-cli --version=0.2.100
```

### Build Commands

To enable parallel computation for WebAssembly threads, you can use the following command:

```bash
cargo make build_multithread
```

Or with the **arkzkey** feature enabled:

```bash
cargo make build_multithread_arkzkey
```

### WebAssembly Threading Support

Most modern browsers support WebAssembly threads,
but they require the following headers to enable `SharedArrayBuffer`, which is necessary for multithreading:

- Cross-Origin-Opener-Policy: same-origin
- Cross-Origin-Embedder-Policy: require-corp

Without these, the application will fall back to single-threaded mode.

## Feature detection

If you're targeting [older browser versions that didn't support WebAssembly threads yet](https://webassembly.org/roadmap/),
you'll likely want to create two builds - one with thread support and one without -
and use feature detection to choose the right one on the JavaScript side.

You can use [wasm-feature-detect](https://github.com/GoogleChromeLabs/wasm-feature-detect)library for this purpose.
For example, your code might look like this:

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
