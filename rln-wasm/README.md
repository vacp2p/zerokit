# RLN for WASM

[![npm version](https://badge.fury.io/js/@waku%2Fzerokit-rln-wasm.svg)](https://badge.fury.io/js/@waku%2Fzerokit-rln-wasm)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

The Zerokit RLN WASM Module provides WebAssembly bindings for working with
Rate-Limiting Nullifier [RLN](https://rfc.vac.dev/vac/raw/rln-v2) zkSNARK proofs and primitives.
This module is used by [waku-org/js-rln](https://github.com/waku-org/js-rln/) to enable
RLN functionality in JavaScript/TypeScript applications.

## Install Dependencies

> [!NOTE]
> This project requires the following tools:
>
> - `wasm-pack` (v0.13.1) - for compiling Rust to WebAssembly
> - `cargo-make` - for running build commands
> - `nvm` - to install and manage Node.js (v22.14.0+)

### Quick Install

```bash
make installdeps
```

### Manual Installation

```bash
# Install wasm-pack
cargo install wasm-pack --version=0.13.1

# Install cargo-make
cargo install cargo-make

# Install Node.js via nvm
nvm install 22.14.0
nvm use 22.14.0
nvm alias default 22.14.0
```

## Building the Library

Navigate to the rln-wasm directory:

```bash
cd rln-wasm
```

Build commands:

```bash
cargo make build          # Default → @waku/zerokit-rln-wasm
cargo make build_parallel # Parallel → @waku/zerokit-rln-wasm-parallel (requires nightly Rust)
cargo make build_utils    # Utils only → @waku/zerokit-rln-wasm-utils
```

All packages output to `pkg/` directory.

## Running Tests and Benchmarks

```bash
cargo make test           # Standard tests
cargo make test_browser   # Browser headless mode
cargo make test_utils     # Utils-only tests
cargo make test_parallel  # Parallel tests
```

## Examples

See [Node example](./examples/index.js) and [README](./examples/Readme.md) for proof generation, verification, and slashing.

## Parallel Computation

Enables multi-threaded browser execution using `wasm-bindgen-rayon`.

> [!NOTE]
>
> - Parallel support is not enabled by default due to WebAssembly and browser limitations.
> - Requires `nightly` Rust: `rustup install nightly`
> - Browser-only (not compatible with Node.js)
> - Requires HTTP headers for `SharedArrayBuffer`:
>   - `Cross-Origin-Opener-Policy: same-origin`
>   - `Cross-Origin-Embedder-Policy: require-corp`

### Usage

Direct usage (modern browsers with WebAssembly threads support):

```js
import * as wasmPkg from '@waku/zerokit-rln-wasm-parallel';

await wasmPkg.default();
await wasmPkg.initThreadPool(navigator.hardwareConcurrency);
wasmPkg.nowCallAnyExportedFuncs();
```

### Feature Detection for Older Browsers

If you're targeting [older browser versions that didn't support WebAssembly threads yet](https://webassembly.org/roadmap/), you'll want to use both builds - the parallel version for modern browsers and the default version as a fallback. Use feature detection to choose the appropriate build on the JavaScript side.

You can use the [wasm-feature-detect](https://github.com/GoogleChromeLabs/wasm-feature-detect) library for this purpose:

```js
import { threads } from 'wasm-feature-detect';

let wasmPkg;

if (await threads()) {
  wasmPkg = await import('@waku/zerokit-rln-wasm-parallel');
  await wasmPkg.default();
  await wasmPkg.initThreadPool(navigator.hardwareConcurrency);
} else {
  wasmPkg = await import('@waku/zerokit-rln-wasm');
  await wasmPkg.default();
}

wasmPkg.nowCallAnyExportedFuncs();
```
