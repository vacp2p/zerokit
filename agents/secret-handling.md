<!-- markdownlint-configure-file {
  "MD013": { "line_length": 100, "tables": false, "code_blocks": false }
} -->
# Zerokit agent policy: Secret handling

Reference file for `AGENTS.md`; same precedence, same "keep it true" rule (section 0 there).
Read it before a task touches this area.

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
