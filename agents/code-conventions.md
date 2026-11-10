<!-- markdownlint-configure-file {
  "MD013": { "line_length": 100, "tables": false, "code_blocks": false }
} -->
# Zerokit agent policy: Code conventions

Reference file for `AGENTS.md`; same precedence, same "keep it true" rule (section 0 there).
Read it before a task touches this area.

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
  100 chars (rustfmt does not wrap comments). Module headers use `//`, not `//!`. Intra-doc
  links: a type in scope is linked bare, a type out of scope by explicit path, a private
  target is a plain backtick. Gate: `cargo doc -p rln --no-deps` with zero warnings. Vendored
  `iden3calc/*` comments stay as they are.
- Audit one-liners (all must print nothing, the last must warn nothing; `rg` is ripgrep,
  see the host check in `AGENTS.md` section 7):

```bash
git grep -nP '\x{2014}' -- '*.rs' '*.toml' '*.md'   # em-dash: use comma, colon, parentheses or period
rg -n 'derive\([^)]*\bEq\b' --type rust                                             # Eq derives
rg -n 'impl<[^>]*:[^>]*>' --type rust | grep -vE 'where|const [A-Z_]+:'             # inline impl bounds
rg -n 'mod tests\b' --type rust                                                     # plural test module
rg -n '#\[error\("[a-z]' --type rust                                                # lowercase error messages
rg -U --pcre2 -n '#\[(test|wasm_bindgen_test)\]\s+(pub )?fn (?!test_)' --type rust  # test_ prefix
cargo doc -p rln --no-deps
```
