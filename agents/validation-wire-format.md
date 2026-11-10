<!-- markdownlint-configure-file {
  "MD013": { "line_length": 100, "tables": false, "code_blocks": false }
} -->
# Zerokit agent policy: Validation, errors, wire format

Reference file for `AGENTS.md`; same precedence, same "keep it true" rule (section 0 there).
Read it before a task touches this area.

- NO `.unwrap()`, `panic!()`, `unreachable!()` in library code (tests may). Sanctioned
  `.expect("message")` sites: `impl Default for PmTreeSledConfig`, embedded Poseidon constant
  init, and the arity `.expect` in `PoseidonHash::hash` and `Poseidon2Hash::hash`. DO NOT
  re-flag them.
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
  matching arkworks; callers bound input size.
- `Proof` / `PartialProof` are LE-only. All BE impls live in `protocol/serialize.rs`;
  endianness is chosen by `_le` / `_be` suffixes, never an enum. Enum wire = one tag byte
  (`0` Single, `1` Multi) then the inner struct. Hand-written deserialize reads with
  `Validate::No` and checks at the end.
- Size constants are private to `protocol/serialize.rs` and never in the prelude; sizes
  delegate to arkworks `serialized_size`. Tests pin wire widths and tags as literals and never
  import source constants. The prelude re-exports the arkworks serialize traits.
- WASM/FFI boundary errors: `.map_err(|err| err.to_string())` only, no `catch_unwind`.
