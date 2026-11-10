<!-- markdownlint-configure-file {
  "MD013": { "line_length": 100, "tables": false, "code_blocks": false }
} -->
# Zerokit agent policy: Tests and benches

Reference file for `AGENTS.md`; same precedence, same "keep it true" rule (section 0 there).
Read it before a task touches this area.

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
  and overflow in FFI code are real findings. No suppression file is tracked.
- Benches (Criterion): one file per grouping, suffix `_benchmark.rs`, `[[bench]]` name
  matches, bench id exactly `<RustType>::<method>`, arm order = trait order, depth 20,
  `LEAF_COUNT = 8192`, cache `(leaf, proof)` outside `b.iter`. NEVER call
  `group.throughput(...)` (breaks the CI comparison action). PRs that would break the
  comparison carry the `skip-benchmark` label.
- Coverage CI: `cargo tarpaulin --engine llvm --timeout 300` (ptrace hangs on sled threads).
