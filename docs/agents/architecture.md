<!-- markdownlint-configure-file {
  "MD013": { "line_length": 100, "tables": false, "code_blocks": false }
} -->
# Zerokit agent policy: Architecture invariants

Reference file for `AGENTS.md`; same precedence, same "keep it true" rule (section 0 there).
Read it before a task touches this area.

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
  not on the trait; trees store it as a field. Arity capability is a documented contract on
  `ZerokitHasher::hash` (the `///` doc, not a trait bound).
- Round parameters: `POSEIDON_ROUND_PARAMS` (t = 2..17, circomlib parity) and
  `POSEIDON2_ROUND_PARAMS` (t = 2..4, RF 8, RP 56, HorizenLabs "new" set) in utils; golden
  tests against circomlibjs, the Nomos vectors and rust-poseidon-bn254-pure pin them. Any
  parameter change must keep those tests green. Poseidon2 is one-shot per arity with the zero
  LAST (`[inputs.., 0]`); Poseidon1 stays circomlib zero-first.
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
