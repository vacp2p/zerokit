<!-- markdownlint-configure-file {
  "MD013": { "line_length": 100, "tables": false, "code_blocks": false }
} -->
# Zerokit agent policy: Circuits and embedded resources

Reference file for `AGENTS.md`; same precedence, same "keep it true" rule (section 0 there).
Read it before a task touches this area.

- Circuits come from the `vacp2p/circom-rln` fork of Rate-Limiting-Nullifier/circom-rln
  v1.0.0. Externally audited at v1.0.0: `rln_single`, `withdraw`,
  `MerkleTreeInclusionProof`, `RangeCheck`. Everything post-fork (`rln_multi`,
  `ConditionalRangeCheck`, the Poseidon2 circuits) is not externally audited; say so in docs.
- `poseidon2_constants.circom` keeps its `if / else if / else` shape with no `assert` and no
  fall-through array return (static-analysis tools misread anything else).
- Resource regeneration: build the circuits in circom-rln, convert zkeys with
  `rln/convert_zkey.sh`, build the witness graph with circom-witnesscalc `build-circuit` at the
  pinned revision with `--locked` (newer revisions write a graph format the vendored parser
  does not read). Golden vectors come from rust-poseidon-bn254-pure. Static-analysis runners
  (circomspect, Picus, zkFuzz) live under `scripts/` in circom-rln; verdicts are recorded in
  that repo's PR descriptions, not here.
