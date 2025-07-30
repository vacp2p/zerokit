# RLN WASM Utils

[![npm version](https://badge.fury.io/js/@waku%2Fzerokit-rln-wasm.svg)](https://badge.fury.io/js/@waku%2Fzerokit-rln-wasm-utils)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

The Zerokit RLN WASM Utils Module provides WebAssembly bindings for Rate-Limiting Nullifier [RLN](https://rfc.vac.dev/spec/32/) cryptographic primitives.
This module offers comprehensive functionality for identity generation and hashing needed for RLN applications.

## Features

### Identity Generation

- **Random Identity Generation**: Generate cryptographically secure random identities
- **Seeded Identity Generation**: Generate deterministic identities from seeds
- **Extended Identity Generation**: Generate extended identities with additional parameters
- **Seeded Extended Identity Generation**: Generate deterministic extended identities from seeds

### Hashing

- **Standard Hashing**: Hash arbitrary data to field elements
- **Poseidon Hashing**: Advanced cryptographic hashing using Poseidon hash function
- **Endianness Support**: Both little-endian and big-endian serialization support

## API Reference

### Identity Generation Functions

#### `generateMembershipKey(isLittleEndian: boolean): Uint8Array`

Generates a random membership key pair (identity secret and commitment).

**Parameters:**

- `isLittleEndian`: Boolean indicating endianness for serialization

**Returns:** Serialized identity pair as `Uint8Array`

#### `generateExtendedMembershipKey(isLittleEndian: boolean): Uint8Array`

Generates an extended membership key with additional parameters.

**Parameters:**

- `isLittleEndian`: Boolean indicating endianness for serialization

**Returns:** Serialized extended identity tuple as `Uint8Array`

#### `generateSeededMembershipKey(seed: Uint8Array, isLittleEndian: boolean): Uint8Array`

Generates a deterministic membership key from a seed.

**Parameters:**

- `seed`: Seed data as `Uint8Array`
- `isLittleEndian`: Boolean indicating endianness for serialization

**Returns:** Serialized identity pair as `Uint8Array`

#### `generateSeededExtendedMembershipKey(seed: Uint8Array, isLittleEndian: boolean): Uint8Array`

Generates a deterministic extended membership key from a seed.

**Parameters:**

- `seed`: Seed data as `Uint8Array`
- `isLittleEndian`: Boolean indicating endianness for serialization

**Returns:** Serialized extended identity tuple as `Uint8Array`

### Hashing Functions

#### `hash(input: Uint8Array, isLittleEndian: boolean): Uint8Array`

Hashes input data to a field element.

**Parameters:**

- `input`: Input data as `Uint8Array`
- `isLittleEndian`: Boolean indicating endianness for serialization

**Returns:** Serialized hash result as `Uint8Array`

#### `poseidonHash(input: Uint8Array, isLittleEndian: boolean): Uint8Array`

Computes Poseidon hash of input field elements.

**Parameters:**

- `input`: Serialized field elements as `Uint8Array` (format: length + field elements)
- `isLittleEndian`: Boolean indicating endianness for serialization

**Returns:** Serialized hash result as `Uint8Array`

## Usage Examples

### JavaScript/TypeScript

```javascript
import init, { 
  generateMembershipKey, 
  generateSeededMembershipKey,
  hash,
  poseidonHash 
} from '@waku/zerokit-rln-wasm';

// Initialize the WASM module
await init();

// Generate a random membership key
const membershipKey = generateMembershipKey(true); // little-endian
console.log('Membership key:', membershipKey);

// Generate a deterministic membership key from seed
const seed = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
const seededKey = generateSeededMembershipKey(seed, true);
console.log('Seeded key:', seededKey);

// Hash some data
const input = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
const hashResult = hash(input, true);
console.log('Hash result:', hashResult);

// Poseidon hash with field elements
const fieldElements = new Uint8Array([
  // Length (8 bytes) + field elements (32 bytes each)
  1, 0, 0, 0, 0, 0, 0, 0, // length = 1
  // field element data...
]);
const poseidonResult = poseidonHash(fieldElements, true);
console.log('Poseidon hash:', poseidonResult);
```

### Node.js

```javascript
const { 
  generateMembershipKey, 
  generateSeededMembershipKey,
  hash 
} = require('@waku/zerokit-rln-wasm');

// Generate random membership key
const membershipKey = generateMembershipKey(false); // big-endian
console.log('Membership key:', membershipKey);

// Generate seeded membership key
const seed = Buffer.from([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
const seededKey = generateSeededMembershipKey(seed, false);
console.log('Seeded key:', seededKey);

// Hash data
const input = Buffer.from([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
const hashResult = hash(input, false);
console.log('Hash result:', hashResult);
```

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

First, navigate to the rln-wasm-utils directory:

```bash
cd rln-wasm-utils
```

Compile zerokit for `wasm32-unknown-unknown`:

```bash
cargo make build
```

## Running tests

```bash
cargo make test
```

## License

This project is licensed under both MIT and Apache 2.0 licenses. See the LICENSE files for details.
