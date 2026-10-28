<!-- markdownlint-configure-file {
  "MD013": { "line_length": 100, "tables": false, "code_blocks": false }
} -->
# Zerokit: rules for coding agents

This file is the repository policy for any coding agent (Claude Code, Codex, Cursor,
Gemini CLI, Copilot, others). It holds conventions, invariants and settled decisions only.
It holds no work state: what is in progress, who reviews what, backlog and local setup live
in each developer's own tool file, never here.

## 0. Scope, precedence, maintenance

- Precedence on conflict: the code and its tests > this file > anything the agent remembers.
  `CONTRIBUTING.md` governs commits and PRs (signed, Conventional Commits, squash merge); this
  file does not repeat it.
- Personal preferences (reply language, whether the agent may commit, verbosity) belong in a
  gitignored file your tool loads (Claude Code `CLAUDE.md`, Cursor `.cursor/rules/`, Gemini
  `GEMINI.md`, Codex `~/.codex/AGENTS.md`). If none exists, ask the developer once before the
  first task and write the answers there, never into this file.
- Each developer customizes their own agent setup and tracks their own work (what is open,
  notes, scratch context) in those gitignored files. Nothing personal or in-progress is
  committed: this file changes only for a repo-wide rule, so it rarely changes and never
  becomes a merge-conflict magnet.
- Change this file rarely: every edit is a reviewed PR. Add a rule only when it is general,
  stable and not derivable from the code. Size: target 20 KB, hard ceiling 32 KiB (Codex
  truncates larger instruction files by default; every tool pays the size in context on every
  session). Above the target, tighten an existing rule before adding one.
- Keep it true: a PR that changes a convention, an invariant, a command, a feature flag, a
  dependency pin, a boundary name or a release step updates the matching section in the same
  PR (one commit `docs(agents): ...` is fine). A rule that no longer matches the code is a
  bug in this file, not a license to ignore it: fix the file.
- Before every release, review this file against the codebase as a release-checklist step
  (section 3) and land the corrections before tagging. The tag never ships a stale policy.
- The same rules apply whatever model or tool runs. Nothing here depends on a vendor feature.

## 1. Session protocol (every agent, every task)

- Never commit, push, tag, publish, post a review comment or open a PR unless the developer
  explicitly asks in that message. A sentence ending in a question mark is a question, not
  an order: prepare the command, show it, wait.
- No destructive git (`reset --hard`, force push, branch deletion) without an explicit ask.
- Before reporting a change as done: `cargo make fmt` (nightly rustfmt), `cargo clippy
  --all-targets --tests -- -D warnings`, the relevant tests, and the audit one-liners of
  section 8. Report failures with their output; never describe skipped steps as done.
- Dev builds are debug. Never pass `--release` locally except where section 3 allows it.
- Keep tracked files free of em-dashes (`U+2014`): use a comma, colon, parentheses or a
  period. Gate: `git grep -nP '\x{2014}'` must print nothing (the pattern is spelled as a
  code point so this file passes its own gate).
- Read the ledger (section 12) before proposing a design change; do not re-propose a row.
- Clean up what you create: scratch files and temporary caches. Build artifacts go through
  `cargo clean`; removing a directory is the developer's call, hand them the command.

## 2. What Zerokit is

RLN (Rate-Limiting Nullifiers): a zero-knowledge protocol for anonymous rate limiting. BN254,
Groth16 (arkworks + circom), Poseidon or Poseidon2 for arithmetic hashing, Keccak-256 to map a
signal to a field element. A Merkle tree holds rate commitments; Shamir secret sharing makes
two proofs with the same `external_nullifier` and different `message_id` reveal the secret
(slashing). Consumers: native Rust (full API), WASM (stateless only), FFI (C ABI). Every
protocol hash goes through the `Hasher<H>` facade (arity 1, 2, 3):

```text
id_commitment      = Poseidon(id_secret)
rate_commitment    = Poseidon(id_commitment, user_message_limit)      # Merkle leaf
external_nullifier = Poseidon(epoch, rln_identifier)
a_1                = Poseidon(id_secret, external_nullifier, message_id)
y                  = id_secret + x * a_1        ;  nullifier = Poseidon(a_1)
slash: id_secret   = (y2 * x1 - y1 * x2) / (x1 - x2)
```

## 3. Workspace and commands

- Four crates at one unified version (inter-crate path deps pin the same version): `rln`
  (core), `utils` (`zerokit_utils`), `rln-wasm`, `rln-cli` (`publish = false`). All four are
  workspace members; `default-members = ["rln", "utils"]`, so plain root `cargo` commands hit
  the core crates and `-p` reaches the others. Root `cargo make build/test/bench` iterates all
  four, including rln-wasm's wasm-pack tasks; `make installdeps` is native-only by decision,
  `make installdeps-wasm` adds wasm-pack and node. One root `Cargo.lock`; per-crate lock files
  are banned.
- Commands: `make installdeps | build | test | bench`; `cargo check -p rln`;
  `cd rln-wasm && cargo make test` (Node; `test_browser` Chrome; `test_parallel` nightly);
  `cargo make fmt | fmt_check` (nightly); `cargo run --bin generate_headers --features=headers`
  writes `rln.h` to the current directory. Run workspace commands from the repo root.
- `--release` locally is allowed only for the FFI C/Nim examples (their build files pin
  `target/release/librln`) and for CI, benches and wasm-pack.
- Feature flags: only `parallel` (rln, utils) and `headers` (rln). No tree feature flags: tree
  selection is type-level (`Stateless` / `Stateful<T>`).
- `doctest = false` in every lib crate (required for rln-wasm: wasm-pack would run doctests on
  wasm32 and fail). Examples in docs are illustrative.
- Release checklist, nix: `nix/default.nix` (called from `flake.nix`) pins a manual
  `cargoHash` that goes stale on every `Cargo.lock` change. Any PR touching the lock updates
  it and verifies `nix build .#rln`.
- Release checklist, crates.io size: the `rln` package sits just under the 10 MiB limit
  (the embedded depth-20 `.arkzkey` files are most of it). Before publishing run
  `cargo package -p rln` and check the `.crate` size. Any new embedded resource exceeds the
  limit: request a per-crate raise or split resources into their own crate. Embedded
  resources cannot be `exclude`d (`include_bytes!` needs them at compile time).
- Release checklist, policy: review this file against the code (commands, flags, pins,
  names, ledger) and merge the fixes before tagging.
- Release checklist, order: `cargo package -p rln` verifies against the crates.io
  `zerokit_utils`, so an unpublished utils change fails it. Verify locally with
  `cargo package -p rln --config 'patch.crates-io.zerokit_utils.path="<abs>/utils"'`.
  Release: bump utils and rln together, bump the pin in `rln/Cargo.toml`, publish utils, then
  rln.

## 4. Dependencies and manifests

- `ark-*` pinned to 0.5. Do not bump: `ark-ec` 0.6.0 builds a local rayon pool that panics
  on wasm32. Unpin only to a release that contains arkworks-rs/algebra#1112, then run the
  browser tests with `parallel` first. No vendoring, no `[patch.crates-io]`.
- `[workspace.dependencies]` holds deps shared by two or more members, plus two family
  exceptions: the whole `ark-*` family and `serde` (its `features = ["derive"]` lives at the
  root). Members use `{ workspace = true }` plus local `features` / `optional` additions.
  Single-member deps stay in their own manifest.
- Manifest sort: keep the cluster comments (`# ZKP Generation`, `# Error Handling`,
  `# Utilities`, `# Serialization`, `# Benchmarking`); within a cluster `workspace = true`
  entries first, then direct versions; each group sorted by crate-name length, ties
  alphabetical. The root table uses the same cluster comments.
- In `rln/Cargo.toml`, native-only deps (`sled`, prost, safer-ffi, ...) live under
  `[target.'cfg(not(target_arch = "wasm32"))'.dependencies]`. Never append a plain
  dependency below that header: it would silently become native-only. New shared deps go in
  `[dependencies]` above it.

## 5. Architecture invariants

- Groth16 proving uses `CircomReduction` (`create_proof_with_reduction_and_matrices`); the
  arkworks default reduction produces proofs that fail against snarkjs zkeys.
- Construction: `RLN.state` / `RLN.zkp` are `pub(crate)`; `RLNBuilder` is the only public
  construction path; tree access goes through `RLN` wrapper methods only. The stateful builder
  bounds `State: ZerokitMerkleTree<Hasher = PoseidonHash>`, so a tree/backend hash mismatch is
  a compile error. Per-hash constructors are suffixed functions on separate impl blocks
  (`stateless_poseidon2`, `stateful_poseidon2`). On native targets every constructor defaults
  `graph` / `zkey` to the embedded resources of its own hash; on wasm32 both are supplied.
- Hash layers (adding a hash is additive, mirror the Poseidon2 rollout: utils math, rln
  marker, circuit resources, builder constructors, FFI, WASM):
  `utils::Poseidon<F>` (math) > `utils::hasher::ZerokitHasher` (one trait, one method
  `hash(&[Scalar]) -> Scalar`, assoc type `Scalar` has no bounds on the trait; every tree
  consumer restates `where H::Scalar: Debug + Copy + PartialEq + Default + Send + Sync`) >
  `rln::PoseidonHash` / `Poseidon2Hash` (marker structs, private statics) > `rln::Hasher<H>`
  (facade, bound on the impl only, `hash_single` / `hash_pair` / `hash_list`) >
  `ArkGroth16Backend<H>` (no bound on the decl, no default type param). No alias over the
  assoc type: spell `H::Scalar`, `<Self::Hasher as ZerokitHasher>::Scalar` in trait defs,
  `<H as ZerokitHasher>::Scalar` where pmtree's `Hasher` is also in scope. `default_leaf` is
  not on the trait; trees store it as a field. Arity capability is a documented `# Panics`
  contract on `ZerokitHasher::hash`.
- Round parameters: `POSEIDON_ROUND_PARAMS` (t = 2..17, circomlib parity) and
  `POSEIDON2_ROUND_PARAMS` (t = 2..4, RF 8, RP 56, HorizenLabs "new" set) in utils; golden
  tests against circomlibjs, the Nomos vectors and rust-poseidon-bn254-pure pin them. Any
  parameter change must keep those tests green. Poseidon2 is one-shot per arity with the zero
  LAST (`[inputs.., 0]`); Poseidon1 stays circomlib zero-first. Do not reopen.
- Circuit gating: a hash without a matching circuit compiles but cannot produce valid proofs;
  mixing hash and resources yields `Ok(false)`, pinned by a test. Four depth-20 circuits are
  embedded (`rln_single`, `rln_multi`, `rln_poseidon2_single`, `rln_poseidon2_multi`).
  pmtree adapters keep the provided `default_leaf`; in `pm_tree.rs` import pmtree's trait as
  `PmTreeHasher` so bare `Hasher` is the facade.
- `RLNMerkleProof` is the canonical data type `{path_elements, identity_path_index}`;
  witness builders take it through a `#[builder(into)]` setter; a blanket
  `From<&P> where P: ZerokitMerkleProof<Index = u8>` bridges every tree proof. Witness fields
  stay flat (wire format unchanged). The type must survive any builder redesign.
- Keygen: `IdentityKeys` / `ExtendedIdentityKeys` with generic constructors only,
  `generate::<H, R>(rng)` and `generate_seeded::<H, R>(signal)`; call sites spell both type
  parameters. Secret accessors return owned `SecretFr`; `id_commitment() -> Fr`. Serde like
  every protocol type: LE derived arkworks, BE manual in `protocol/serialize.rs`, no inherent
  `to_bytes_*` / `from_bytes_*`. Wire = fields in order, no length prefix.
- Graph validation lives only in `generate_proof`; builders check structural invariants only.
- `override_range`: one shared provided `validate_override_range`; backends override only the
  apply step. `PmTreeError::Backend(_)` is for genuine storage or hasher faults, never
  validation.

## 6. Validation, errors, wire format

- No `.unwrap()`, `panic!()`, `unreachable!()` in library code (tests may). Sanctioned
  `.expect("message")` sites: `impl Default for PmTreeSledConfig`, embedded Poseidon constant
  init, and the documented `# Panics` arity contract in the facade. Do not re-flag them.
- Narrowest error per method, no top-level union error. Validation function is named
  `validate` everywhere; it runs at `build()` and at deserialize. Proof-values validation
  error is `ProofValuesMultiError`; `SerializationError` wraps typed validation errors with
  `#[from]` so BE deserialize propagates them through `?`. The LE path stays arkworks
  `InvalidData` (its `Valid` trait pins the type).
- Verify semantics: all verify methods return `Result<bool>`; `Ok(false)` is the zkSNARK
  verdict, `Err` is caller-input mismatch or backend fault. An invalid proof is never an
  error, at every boundary (`FFI_BoolResult { ok: false, err: null }`, WASM returns `false`).
- Fr malleability: every untrusted BE input rejects values `>= Fr::MODULUS` with a limb-wise
  check into `NonCanonicalFieldElement`, no BigUint detour.
- A forged length prefix panics on purpose (`Vec::with_capacity` from the prefix, LE and BE),
  matching arkworks; callers bound input size. No streaming workaround.
- `Proof` / `PartialProof` are LE-only. All BE impls live in `protocol/serialize.rs`;
  endianness is chosen by `_le` / `_be` suffixes, never an enum. Enum wire = one tag byte
  (`0` Single, `1` Multi) then the inner struct. Hand-written deserialize reads with
  `Validate::No` and checks at the end.
- Size constants are private to `protocol/serialize.rs` and never in the prelude; sizes
  delegate to arkworks `serialized_size`. Tests pin wire widths and tags as literals and never
  import source constants. The prelude re-exports the arkworks serialize traits.
- WASM/FFI boundary errors: `.map_err(|err| err.to_string())` only, no `catch_unwind`.

## 7. Secret handling

- `SecretFr` zeroizes on drop and has a hand-written redacted `Debug` (`SecretFr(********)`),
  locked by a regression test; containers derive `Debug` and inherit the redaction. `!Copy` is
  enforced by `ZeroizeOnDrop`. Extended keygen returns trapdoor, nullifier and secret as
  `SecretFr`.
- Any raw `Fr` copy of a secret is wiped after use with a `// wipe ...` comment. The audited
  copies live in the `pub(crate)` functions of `rln/src/protocol/secret.rs`, which hash on
  `Zeroizing` buffers directly (the only non-facade hash call sites). Secret clones need no
  comment. BE serialization of a secret uses a `Zeroizing` stack buffer and wipes the limbs.
- FFI: opaque `FFI_SecretFr`; keygen returns boxed secrets; `ffi_rln_recover_id_secret`
  returns a plain `CFr` on purpose (slashing reveal); `ffi_secret_fr_eq` compares without
  revealing. WASM: opaque `WasmSecretFr` exposes only `debug()` (redacted) and `equals()`;
  secrets persist only through `WasmIdentityKeys.toBytesLE/BE`. WASM memory is host-readable:
  hygiene, not isolation.

## 8. Code conventions

| Concern | Use | Avoid |
| --- | --- | --- |
| count vs length | `_count`, `LEAF_COUNT`; `_len` only for a real `.len()` | `_size`, `num_*`, `n_*` |
| index, config | `index`, `config` | `idx` (except vendored `iden3calc/*`), `cfg` outside attributes |
| common vars | `buf`, `len`, `message`, `signal`, `err` | `buffer`, `length`, `msg`, `sig`, `e` |
| predicates | `is_*`, `use_*` | `has_*`, `can_*`, `should_*` |
| prefixes | `ffi_*`, `default_*` (embedded resources), `get_*` / `set_*` | dropping them |
| hash types | marker `*Hash`, facade `Hasher<H>`, trait `ZerokitHasher` | `*Hasher` markers, gate traits |
| arity vs input length | `arity` = capability; `input length` = the concrete call | mixing both in one sentence |

- Assoc error type is `Error` (`Err` only for std `FromStr`). Write `Self::AssocType` in impls.
- Trait order in `#[derive]` lists and bounds: core std (`Debug, Clone, Copy, PartialEq,
  Hash, PartialOrd, Ord, Default`), then serialization (`CanonicalSerialize,
  CanonicalDeserialize, CanonicalSerializeBE, CanonicalDeserializeBE, Serialize, Deserialize,
  prost::*`), then domain (`Zeroize, ZeroizeOnDrop`, clap, `FromStr`, ...), error traits last,
  `Send + Sync` at the very end of bounds. `PartialEq` only, never `Eq`.
- Bounds: `impl` blocks carry no inline bounds, all go in `where` clauses (tests and benches
  included). Declarations keep inline bounds only where required; `PhantomData`-only generics
  carry none. No redundant generic annotations: no turbofish where inference works, no
  qualified-self brackets, no local aliases over assoc types.
- Method order follows the trait declaration order in every tree impl, the `RLN<Stateful>`
  wrapper and bench arms.
- Ownership: parameters the callee stores are owned; read-only parameters are references;
  accessors borrow existing fields and return owned values assembled on demand; secret
  accessors return owned `SecretFr`. FFI methods borrow handles and clone inside; only `free`
  consumes.
- Mode names: "Single message-id mode" / "Multi message-id mode". Log strings are plain
  English; variable names follow the target language (JS camelCase, C snake_case, Nim
  camelCase); C and Nim examples mirror the JS structure and output.
- `#[cfg(not(target_arch = "wasm32"))]` marks native-only items with the narrowest gate.
- Formatting: `rustfmt.toml` (edition 2021, `imports_granularity = "Crate"`,
  `group_imports = "StdExternalCrate"`, nightly fmt). Clippy `-D warnings` everywhere; for
  wasm `--target wasm32-unknown-unknown --tests`. Makefile lines over ~80 chars wrap with a
  trailing backslash; long URLs and quoted shell one-liners stay on one line.
- Docs: `///` on every `pub` and `pub(crate)` item, full sentences ending with a period,
  backticks around every type, method, parameter and expression, lines wrapped by hand to
  100 chars (rustfmt does not wrap comments). Module headers use `//!`. Intra-doc links: a
  type in scope is linked bare, a type out of scope by explicit path, a private target is a
  plain backtick. Gate: `cargo doc -p rln --no-deps` with zero warnings. Vendored
  `iden3calc/*` comments stay as they are.
- Audit one-liners (all must print nothing, the last must warn nothing):

```bash
git grep -nP '\x{2014}' -- '*.rs' '*.toml' '*.md'                                   # em-dash
rg -n 'derive\([^)]*\bEq\b' --type rust                                             # Eq derives
rg -n 'impl<[^>]*:[^>]*>' --type rust | grep -vE 'where|const [A-Z_]+:'             # inline impl bounds
rg -n 'mod tests\b' --type rust                                                     # plural test module
rg -n '#\[error\("[a-z]' --type rust                                                # lowercase error messages
rg -U --pcre2 -n '#\[(test|wasm_bindgen_test)\]\s+(pub )?fn (?!test_)' --type rust  # test_ prefix
cargo doc -p rln --no-deps
```

## 9. Tests and benches

- Unit tests: inline `#[cfg(test)] mod test` (singular). Integration tests: `<crate>/tests/`,
  layout mirrors `src/`. Every test function is prefixed `test_`. Tests may `.unwrap()`.
- A behavior tested for both endiannesses lives in one test body, never twin `_le` / `_be`
  tests; endianness-exclusive surfaces keep their suffix.
- The WASM suite stays lean: add a wasm test only for logic not yet covered; fold assertions
  into an existing test when the shape matches.
- Raw wire bytes in tests pin tags and widths as literals.
- Memory checks (Linux `cargo valgrind test`, macOS `leaks --atExit`): reports from statics
  (the graph cache, Poseidon constants) and sled/rayon pools alive at exit are known false
  positives (fixed one-time init, does not grow per proof). Only use-after-free, double-free
  and overflow in FFI code are real findings. No suppression file is tracked; do not drop the
  static caches to silence the reports.
- Benches (Criterion): one file per grouping, suffix `_benchmark.rs`, `[[bench]]` name
  matches, bench id exactly `<RustType>::<method>`, arm order = trait order, depth 20,
  `LEAF_COUNT = 8192`, cache `(leaf, proof)` outside `b.iter`. Never call
  `group.throughput(...)` (breaks the CI comparison action). PRs that would break the
  comparison carry the `skip-benchmark` label.
- Coverage CI: `cargo tarpaulin --engine llvm --timeout 300` (ptrace hangs on sled threads).

## 10. FFI and WASM boundaries

- Hash naming: unsuffixed means Poseidon (`generate`, `WasmRLN`, `ffi_rln_new_*`); every
  other hash carries its name as a suffix (`ffi_poseidon2_hash_pair`, `WasmRLNPoseidon2`).
  Never rename the unsuffixed defaults.
- FFI names: `ffi_<type>_<action>_<variant>`, type = the wrapper type in full, action in
  `new / get_* / to_bytes / from_bytes / free`, variant `_le / _be / _mixed` or none. Getters
  wrapping a native method mirror its name (`ffi_rln_leaves_set` is a count getter).
  Protocol-fixed names (`ffi_uint_to_fr`, `ffi_hash_to_field_*`) are exempt.
- Pointer discipline: C sees one `X *` per type. Receivers take `&FFI_X` / `&mut FFI_X`,
  constructors return `FFI_Result<repr_c::Box<FFI_X>, String>`, free functions consume the
  box. Result types: `FFI_Result<T, Err>` for pointers and vectors, `FFI_BoolResult` /
  `FFI_UsizeResult` where `Option<T>` has no niche. No function swallows errors.
- Cross-type conversions are target-side `from` at every layer (Rust `From`, FFI
  `ffi_<target>_from_<source>`, WASM `Wasm<Target>.from<Source>()`); no source-side
  `to_<target>`. Every accessor on a core type exists on its FFI (`get_*`) and WASM (`get*`)
  wrapper. Every owned `repr_c::Vec<T>` return has a matching `ffi_vec_<t>_free`; borrowed
  vectors are never freed.
- `FFI_RLN` is an enum with static dispatch; tree operations on the stateless variant return
  `Err`. The generated `rln.h` is alphabetical; `rln/ffi_c_examples/rln.h` is regenerated after
  an ABI change and `rln/ffi_nim_examples/rln.nim` is synced by hand (re-diff export names).
  C examples print repr_c buffers with `%.*s` and an `(int)` length, never `%s`.
- WASM: `Fr`, arkworks and tree types never cross the boundary (only `Wasm*` wrappers,
  `Uint8Array`, primitives). No tree methods, ever: bytes in, bytes out; JS supplies path
  data as a `WasmRLNMerkleProof`. Hashing surface = free functions (`poseidonHashPair`,
  `poseidon2HashPair`, `hashToFieldLE/BE`); per-hash RLN classes are fine, per-hash hasher
  classes are not. Wrapper types carry Rust-side `From` impls from their core types. All
  wasm_utils types are re-exported at the crate root. The browser bench keeps `iterations`
  small (ChromeDriver kills a renderer that stays busy for 30 s).

## 11. Circuits and embedded resources

- Circuits come from the `vacp2p/circom-rln` fork of Rate-Limiting-Nullifier/circom-rln
  v1.0.0. Externally audited at v1.0.0: `rln_single`, `withdraw`,
  `MerkleTreeInclusionProof`, `RangeCheck`. Everything post-fork (`rln_multi`,
  `ConditionalRangeCheck`, the Poseidon2 circuits) is not externally audited; say so in docs.
- Poseidon2 decisions are closed: HorizenLabs "new" constants, zero-last one-shot, t = 2..4.
  `poseidon2_constants.circom` keeps its `if / else if / else` shape with no `assert` and no
  fall-through array return (static-analysis tools misread anything else).
- Resource regeneration: build the circuits in circom-rln, convert zkeys with
  `rln/convert_zkey.sh`, build the witness graph with circom-witnesscalc `build-circuit` at the
  pinned revision with `--locked` (newer revisions write a graph format the vendored parser
  does not read). Golden vectors come from rust-poseidon-bn254-pure. Static-analysis runners
  (circomspect, Picus, zkFuzz) live under `scripts/` in circom-rln; verdicts are recorded in
  that repo's PR descriptions, not here.

## 12. Decision ledger (do not re-propose)

| Proposal | Verdict |
| --- | --- |
| Bump `ark-*` to 0.6 | No: breaks the browser thread pool (`parallel`) |
| Rename `validate` | Reverted; keep `validate` |
| Marker or gate trait over `ZerokitHasher` | No: `# Panics` contract instead |
| Type aliases `StatefulRLN<T>` / `StatelessRLN<H>` | Reverted; spell full types |
| GAT tree-kind redesign; `<T, H>` two-param tree | No (inference cost; T is hasher-determined) |
| Generic witness builder over `ZerokitMerkleProof`, or a trait impl for `RLNMerkleProof` | Rejected twice: pins a hasher into hash-agnostic data; `WasmRLNMerkleProof` solves parity |
| Enum of concrete tree proofs in the witness | No: wire break, per-hash explosion |
| Build-time `.graph()` check on builders | Removed; graph consistency belongs to `generate_proof` |
| Third keygen convenience constructor | No: two constructors only |
| `static_assertions` guard on `SecretFr` `Display` | Declined |
| `VerifyProofError::InvalidProof` variant | No: an invalid proof is `Ok(false)` |
| `COMPRESS_PROOF_SIZE` const; `UnexpectedElementCount`; proof-value variants on `SerializationError` | Deleted; do not re-add |
| `Eq` derives or bounds | Banned codebase-wide |
| Streaming workaround for forged length prefixes | No: intentional panic |
| `catch_unwind` at boundaries | No |
| WASM tree methods; per-hash WASM hasher classes | Permanently excluded |
| Rename `ffi_rln_leaves_set` | No: mirrors the native getter |
| Per-crate `Cargo.lock` | Deleted; one root lock |
| Drop the static graph cache to silence valgrind | No: known false positive (one-time init) |
| Drop `Zeroizing` in the Poseidon2 hot path for speed | No: secret hygiene wins (cost measured, accepted) |
| Pre-generated `MontFp!` Poseidon constants file | Reverted; runtime table plus golden test |
| Seed the RNG in `test_leaf_setting_with_index` | Dropped; the underlying bug is fixed and covered |
| Per-hash methods on hash-agnostic boundary types (`toProofValues*`) | Removed; proof values come from proving or `fromBytes` only |
| Port the Poseidon round-number and MDS scripts to Rust | Declined: golden vectors are the gate; a port would emit different RP than circomlib |
| Add an exhaustive witness solver to circom-rln for the post-fork templates | Rejected: cannot run on Poseidon templates; uniqueness follows from `<==`-only logic plus circomlib `Num2Bits` / `IsZero` |

## 13. Tool notes and local permission setup

- First session with any tool: if the developer has no local instruction file for this repo
  yet, create one from this skeleton (sections, not content; fill it from the developer's
  answers and keep it gitignored), importing or pointing to this file first:

  ```text
  L1  How to work here   local tooling, hooks, memory and backup rules of this workstation
  L2  Scratch index      per-task context files (where, what, status), not auto-loaded
  L3  User rules         reply language, commit/push policy, anything the developer wants
  N   Local notes        dated "why" and measurements behind the AGENTS.md rules (not rules)
  W   Work state         what is open, who reviews, backlog, next steps; shrinks as work ships
  ```

  Number the local file with its own scheme (L / N / W above), never with this file's
  section numbers, so a reference like "§3" always means AGENTS.md. The local file is
  gitignored, so a fresh clone or a careless cleanup loses it: keep an automatic mirror
  outside the repo (copy the local file and its scratch files after every edit, delete a
  mirror copy when its scratch file is retired; Claude Code users can use the tool's own
  per-project directory under `~/.claude/`).

- First session with any tool: if the tool has no local permission settings for this repo,
  create them before the first task so that build, test, lint and read-only git/gh commands
  run without prompts, everything that writes outside the working tree (commit, push, PR)
  prompts, and recursive `rm`, force push, hard reset, `git clean -f`, `git branch -D`,
  `cargo publish`, `gh pr merge` and `gh release` are denied outright. Show the developer
  the file you created.
- Local tooling is the developer's choice, not repo policy: skills, plugins, MCP servers,
  hooks, code-graph or indexing tools and their outputs stay in the developer's gitignored
  files and are never required or described here. A rule in this file must be followable
  with the plain tool and the repo alone.
- Claude Code: the repo-level `CLAUDE.md` is gitignored and personal; it imports this file
  with an `@AGENTS.md` line near the top, then holds only local workflow, local tooling and
  work state. If `.claude/settings.local.json` is missing, create it with this content (hooks are
  optional):

  ```json
  { "permissions": {
      "allow": ["Bash(cargo check *)", "Bash(cargo build *)", "Bash(cargo test *)",
        "Bash(cargo clippy *)", "Bash(cargo run *)", "Bash(cargo doc *)", "Bash(cargo fmt *)",
        "Bash(cargo +nightly fmt *)", "Bash(cargo make *)", "Bash(cargo package *)",
        "Bash(make build)", "Bash(make test)", "Bash(rg *)",
        "Bash(git status*)", "Bash(git diff *)", "Bash(git log *)", "Bash(git show *)",
        "Bash(git blame *)", "Bash(git ls-files *)",
        "Bash(gh pr view *)", "Bash(gh pr list *)", "Bash(gh pr diff *)", "Bash(gh pr checks *)",
        "Bash(gh issue view *)", "Bash(gh run view *)"],
      "deny": ["Bash(rm -rf *)", "Bash(rm -fr *)", "Bash(rm -r *)", "Bash(rm -R *)",
        "Bash(git push --force*)", "Bash(git push *--force*)", "Bash(git reset --hard*)",
        "Bash(git clean -f*)", "Bash(git branch -D *)",
        "Bash(cargo publish *)", "Bash(gh pr merge *)", "Bash(gh release *)"] } }
  ```

- Codex: `~/.codex/config.toml` with `approval_policy = "on-request"` and
  `sandbox_mode = "workspace-write"`; the same allow/deny intent as above.
- Gemini CLI: set `contextFileName` to `AGENTS.md`, or keep a `GEMINI.md` that imports it.
- Copilot: `.github/copilot-instructions.md`, if added, should point here instead of copying.
- Any tool: personal files and tool outputs stay gitignored. `.gitignore` already lists
  `CLAUDE.md`, `CLAUDE.local.md`, `.claude/`, `GEMINI.md`, `.gemini/`, `.codex/`, `.cursor/`,
  `.windsurf/`, `.aider*` and `graphify-out/`; add a new tool's file there before creating it.
