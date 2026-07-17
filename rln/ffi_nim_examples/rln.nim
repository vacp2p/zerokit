# Embed rpaths to find Cargo's built library relative to the executable
when defined(macosx):
  {.passL: "-Wl,-rpath,@executable_path/../../target/release".}
when defined(linux):
  {.passL: "-Wl,-rpath,'$ORIGIN/../../target/release'".}

# Portable dynlib name with override capability (-d:RLN_LIB:"...")
when defined(macosx):
  const RLN_LIB* {.strdefine.} = "librln.dylib"
elif defined(linux):
  const RLN_LIB* {.strdefine.} = "librln.so"
elif defined(windows):
  const RLN_LIB* {.strdefine.} = "rln.dll"
else:
  const RLN_LIB* {.strdefine.} = "rln"

# FFI objects
type
  CSize* = csize_t
  Fr* = object
  SecretFr* = object
  RLN* = object
  Proof* = object
  PartialProof* = object
  Witness* = object
  PartialWitness* = object
  ProofValues* = object

  Vec_Fr* = object
    dataPtr*: ptr Fr
    len*: CSize
    cap*: CSize

  Vec_uint8* = object
    dataPtr*: ptr uint8
    len*: CSize
    cap*: CSize

  Vec_bool* = object
    dataPtr*: ptr bool
    len*: CSize
    cap*: CSize

  Vec_size* = object
    dataPtr*: ptr CSize
    len*: CSize
    cap*: CSize

  MerkleProof* = object

  IdentityKeys* = object
    identity_secret*: ptr SecretFr
    id_commitment*: ptr Fr

  ExtendedIdentityKeys* = object
    identity_trapdoor*: ptr SecretFr
    identity_nullifier*: ptr SecretFr
    identity_secret*: ptr SecretFr
    id_commitment*: ptr Fr

  CBoolResult* = object
    ok*: bool
    err*: Vec_uint8

  UsizeResult* = object
    ok*: CSize
    err*: Vec_uint8

  RLNResult* = object
    ok*: ptr RLN
    err*: Vec_uint8

  ProofResult* = object
    ok*: ptr Proof
    err*: Vec_uint8

  PartialProofResult* = object
    ok*: ptr PartialProof
    err*: Vec_uint8

  WitnessResult* = object
    ok*: ptr Witness
    err*: Vec_uint8

  PartialWitnessResult* = object
    ok*: ptr PartialWitness
    err*: Vec_uint8

  ProofValuesResult* = object
    ok*: ptr ProofValues
    err*: Vec_uint8

  MerkleProofResult* = object
    ok*: ptr MerkleProof
    err*: Vec_uint8

  IdentityKeysResult* = object
    ok*: ptr IdentityKeys
    err*: Vec_uint8

  ExtendedIdentityKeysResult* = object
    ok*: ptr ExtendedIdentityKeys
    err*: Vec_uint8

  FrResult* = object
    ok*: ptr Fr
    err*: Vec_uint8

  SecretFrResult* = object
    ok*: ptr SecretFr
    err*: Vec_uint8

  VecFrResult* = object
    ok*: Vec_Fr
    err*: Vec_uint8

  VecU8Result* = object
    ok*: Vec_uint8
    err*: Vec_uint8

  VecBoolResult* = object
    ok*: Vec_bool
    err*: Vec_uint8

  VecSizeResult* = object
    ok*: Vec_size
    err*: Vec_uint8

# Fr functions
proc ffi_fr_zero*(): ptr Fr {.importc: "ffi_fr_zero", cdecl,
    dynlib: RLN_LIB.}
proc ffi_fr_one*(): ptr Fr {.importc: "ffi_fr_one", cdecl, dynlib: RLN_LIB.}
proc ffi_fr_to_bytes_le*(fr: ptr Fr): VecU8Result {.importc: "ffi_fr_to_bytes_le",
    cdecl, dynlib: RLN_LIB.}
proc ffi_fr_to_bytes_be*(fr: ptr Fr): VecU8Result {.importc: "ffi_fr_to_bytes_be",
    cdecl, dynlib: RLN_LIB.}
proc ffi_fr_from_bytes_le*(bytes: ptr Vec_uint8): FrResult {.importc: "ffi_fr_from_bytes_le",
    cdecl, dynlib: RLN_LIB.}
proc ffi_fr_from_bytes_be*(bytes: ptr Vec_uint8): FrResult {.importc: "ffi_fr_from_bytes_be",
    cdecl, dynlib: RLN_LIB.}
proc ffi_uint_to_fr*(value: uint32): ptr Fr {.importc: "ffi_uint_to_fr",
    cdecl, dynlib: RLN_LIB.}
proc ffi_fr_debug*(fr: ptr Fr): Vec_uint8 {.importc: "ffi_fr_debug", cdecl,
    dynlib: RLN_LIB.}
proc ffi_fr_free*(x: ptr Fr) {.importc: "ffi_fr_free", cdecl,
    dynlib: RLN_LIB.}

# Vec<Fr> functions
proc ffi_vec_fr_new*(capacity: CSize): Vec_Fr {.importc: "ffi_vec_fr_new",
    cdecl, dynlib: RLN_LIB.}
proc ffi_vec_fr_from_fr*(fr: ptr Fr): Vec_Fr {.importc: "ffi_vec_fr_from_fr",
    cdecl, dynlib: RLN_LIB.}
proc ffi_vec_fr_push*(v: ptr Vec_Fr, fr: ptr Fr) {.importc: "ffi_vec_fr_push",
    cdecl, dynlib: RLN_LIB.}
proc ffi_vec_fr_len*(v: ptr Vec_Fr): CSize {.importc: "ffi_vec_fr_len",
    cdecl, dynlib: RLN_LIB.}
proc ffi_vec_fr_get*(v: ptr Vec_Fr, i: CSize): ptr Fr {.importc: "ffi_vec_fr_get",
    cdecl, dynlib: RLN_LIB.}
proc ffi_vec_fr_to_bytes_le*(v: ptr Vec_Fr): VecU8Result {.importc: "ffi_vec_fr_to_bytes_le",
    cdecl, dynlib: RLN_LIB.}
proc ffi_vec_fr_to_bytes_be*(v: ptr Vec_Fr): VecU8Result {.importc: "ffi_vec_fr_to_bytes_be",
    cdecl, dynlib: RLN_LIB.}
proc ffi_vec_fr_from_bytes_le*(bytes: ptr Vec_uint8): VecFrResult {.importc: "ffi_vec_fr_from_bytes_le",
    cdecl, dynlib: RLN_LIB.}
proc ffi_vec_fr_from_bytes_be*(bytes: ptr Vec_uint8): VecFrResult {.importc: "ffi_vec_fr_from_bytes_be",
    cdecl, dynlib: RLN_LIB.}
proc ffi_vec_fr_debug*(v: ptr Vec_Fr): Vec_uint8 {.importc: "ffi_vec_fr_debug",
    cdecl, dynlib: RLN_LIB.}
proc ffi_vec_fr_free*(v: Vec_Fr) {.importc: "ffi_vec_fr_free", cdecl,
    dynlib: RLN_LIB.}

# Vec<uint8> functions
proc ffi_vec_u8_to_bytes_le*(v: ptr Vec_uint8): VecU8Result {.importc: "ffi_vec_u8_to_bytes_le",
    cdecl, dynlib: RLN_LIB.}
proc ffi_vec_u8_to_bytes_be*(v: ptr Vec_uint8): VecU8Result {.importc: "ffi_vec_u8_to_bytes_be",
    cdecl, dynlib: RLN_LIB.}
proc ffi_vec_u8_from_bytes_le*(bytes: ptr Vec_uint8): VecU8Result {.importc: "ffi_vec_u8_from_bytes_le",
    cdecl, dynlib: RLN_LIB.}
proc ffi_vec_u8_from_bytes_be*(bytes: ptr Vec_uint8): VecU8Result {.importc: "ffi_vec_u8_from_bytes_be",
    cdecl, dynlib: RLN_LIB.}
proc ffi_vec_u8_debug*(v: ptr Vec_uint8): Vec_uint8 {.importc: "ffi_vec_u8_debug",
    cdecl, dynlib: RLN_LIB.}
proc ffi_vec_u8_free*(v: Vec_uint8) {.importc: "ffi_vec_u8_free", cdecl,
    dynlib: RLN_LIB.}

# Vec<bool> functions
proc ffi_vec_bool_free*(v: Vec_bool) {.importc: "ffi_vec_bool_free", cdecl,
    dynlib: RLN_LIB.}

# Vec<usize> functions
proc ffi_vec_usize_free*(v: Vec_size) {.importc: "ffi_vec_usize_free", cdecl,
    dynlib: RLN_LIB.}

# Hashing functions
proc ffi_hash_to_field_le*(input: ptr Vec_uint8): ptr Fr {.importc: "ffi_hash_to_field_le",
    cdecl, dynlib: RLN_LIB.}
proc ffi_hash_to_field_be*(input: ptr Vec_uint8): ptr Fr {.importc: "ffi_hash_to_field_be",
    cdecl, dynlib: RLN_LIB.}
proc ffi_poseidon_hash_pair*(a: ptr Fr,
    b: ptr Fr): ptr Fr {.importc: "ffi_poseidon_hash_pair", cdecl,
    dynlib: RLN_LIB.}

# SecretFr functions
proc ffi_secret_fr_eq*(a: ptr SecretFr, b: ptr SecretFr): bool {.importc: "ffi_secret_fr_eq",
    cdecl, dynlib: RLN_LIB.}
proc ffi_secret_fr_debug*(secret: ptr SecretFr): Vec_uint8 {.importc: "ffi_secret_fr_debug",
    cdecl, dynlib: RLN_LIB.}
proc ffi_secret_fr_free*(secret: ptr SecretFr) {.importc: "ffi_secret_fr_free",
    cdecl, dynlib: RLN_LIB.}

# Identity key functions
proc ffi_identity_keys_generate*(): ptr IdentityKeys {.importc: "ffi_identity_keys_generate",
  cdecl, dynlib: RLN_LIB.}
proc ffi_identity_keys_generate_seeded*(
  seed: ptr Vec_uint8): ptr IdentityKeys {.importc: "ffi_identity_keys_generate_seeded",
     cdecl, dynlib: RLN_LIB.}
proc ffi_identity_keys_get_secret*(identity: ptr IdentityKeys): ptr SecretFr {.importc: "ffi_identity_keys_get_secret",
  cdecl, dynlib: RLN_LIB.}
proc ffi_identity_keys_get_commitment*(identity: ptr IdentityKeys): ptr Fr {.importc: "ffi_identity_keys_get_commitment",
  cdecl, dynlib: RLN_LIB.}
proc ffi_identity_keys_to_bytes_le*(identity: ptr IdentityKeys): VecU8Result {.importc: "ffi_identity_keys_to_bytes_le",
  cdecl, dynlib: RLN_LIB.}
proc ffi_identity_keys_to_bytes_be*(identity: ptr IdentityKeys): VecU8Result {.importc: "ffi_identity_keys_to_bytes_be",
  cdecl, dynlib: RLN_LIB.}
proc ffi_identity_keys_from_bytes_le*(bytes: ptr Vec_uint8): IdentityKeysResult {.importc: "ffi_identity_keys_from_bytes_le",
  cdecl, dynlib: RLN_LIB.}
proc ffi_identity_keys_from_bytes_be*(bytes: ptr Vec_uint8): IdentityKeysResult {.importc: "ffi_identity_keys_from_bytes_be",
  cdecl, dynlib: RLN_LIB.}
proc ffi_identity_keys_free*(identity: ptr IdentityKeys) {.importc: "ffi_identity_keys_free",
  cdecl, dynlib: RLN_LIB.}

# Extended identity key functions
proc ffi_extended_identity_keys_generate*(
  ): ptr ExtendedIdentityKeys {.importc: "ffi_extended_identity_keys_generate",

cdecl, dynlib: RLN_LIB.}
proc ffi_extended_identity_keys_generate_seeded*(
  seed: ptr Vec_uint8): ptr ExtendedIdentityKeys {.importc: "ffi_extended_identity_keys_generate_seeded",
     cdecl, dynlib: RLN_LIB.}
proc ffi_extended_identity_keys_get_trapdoor*(
  identity: ptr ExtendedIdentityKeys): ptr SecretFr {.importc: "ffi_extended_identity_keys_get_trapdoor",
     cdecl, dynlib: RLN_LIB.}
proc ffi_extended_identity_keys_get_nullifier*(
  identity: ptr ExtendedIdentityKeys): ptr SecretFr {.importc: "ffi_extended_identity_keys_get_nullifier",
     cdecl, dynlib: RLN_LIB.}
proc ffi_extended_identity_keys_get_secret*(
  identity: ptr ExtendedIdentityKeys): ptr SecretFr {.importc: "ffi_extended_identity_keys_get_secret",
     cdecl, dynlib: RLN_LIB.}
proc ffi_extended_identity_keys_get_commitment*(
  identity: ptr ExtendedIdentityKeys): ptr Fr {.importc: "ffi_extended_identity_keys_get_commitment",
     cdecl, dynlib: RLN_LIB.}
proc ffi_extended_identity_keys_to_bytes_le*(
  identity: ptr ExtendedIdentityKeys): VecU8Result {.importc: "ffi_extended_identity_keys_to_bytes_le",
     cdecl, dynlib: RLN_LIB.}
proc ffi_extended_identity_keys_to_bytes_be*(
  identity: ptr ExtendedIdentityKeys): VecU8Result {.importc: "ffi_extended_identity_keys_to_bytes_be",
     cdecl, dynlib: RLN_LIB.}
proc ffi_extended_identity_keys_from_bytes_le*(
  bytes: ptr Vec_uint8): ExtendedIdentityKeysResult {.importc: "ffi_extended_identity_keys_from_bytes_le",
     cdecl, dynlib: RLN_LIB.}
proc ffi_extended_identity_keys_from_bytes_be*(
  bytes: ptr Vec_uint8): ExtendedIdentityKeysResult {.importc: "ffi_extended_identity_keys_from_bytes_be",
     cdecl, dynlib: RLN_LIB.}
proc ffi_extended_identity_keys_free*(identity: ptr ExtendedIdentityKeys) {.importc: "ffi_extended_identity_keys_free",
  cdecl, dynlib: RLN_LIB.}

# CString functions
proc ffi_c_string_free*(s: Vec_uint8) {.importc: "ffi_c_string_free", cdecl,
    dynlib: RLN_LIB.}

# RLN instance functions
proc ffi_rln_new_stateless*(zkey_data: ptr Vec_uint8,
    graph_data: ptr Vec_uint8): RLNResult {.importc: "ffi_rln_new_stateless",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_new_stateless_default*(): ptr RLN {.importc: "ffi_rln_new_stateless_default",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_new_with_full_merkle_tree*(tree_depth: CSize,
    zkey_data: ptr Vec_uint8,
    graph_data: ptr Vec_uint8): RLNResult {.importc: "ffi_rln_new_with_full_merkle_tree",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_new_with_full_merkle_tree_default*(): RLNResult {.
    importc: "ffi_rln_new_with_full_merkle_tree_default",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_new_with_optimal_merkle_tree*(tree_depth: CSize,
    zkey_data: ptr Vec_uint8,
    graph_data: ptr Vec_uint8): RLNResult {.importc: "ffi_rln_new_with_optimal_merkle_tree",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_new_with_optimal_merkle_tree_default*(): RLNResult {.
    importc: "ffi_rln_new_with_optimal_merkle_tree_default",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_new_with_pm_tree*(tree_depth: CSize,
    zkey_data: ptr Vec_uint8,
    graph_data: ptr Vec_uint8,
    config_path: cstring): RLNResult {.importc: "ffi_rln_new_with_pm_tree",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_new_with_pm_tree_default*(): RLNResult {.
    importc: "ffi_rln_new_with_pm_tree_default",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_generate_proof*(rln: ptr RLN,
    witness: ptr Witness): ProofResult {.importc: "ffi_rln_generate_proof",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_verify*(rln: ptr RLN,
    proof: ptr Proof): CBoolResult {.importc: "ffi_rln_verify",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_verify_with_signal*(rln: ptr RLN,
    proof: ptr Proof,
    x: ptr Fr): CBoolResult {.importc: "ffi_rln_verify_with_signal",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_verify_with_roots*(rln: ptr RLN,
    proof: ptr Proof,
    roots: ptr Vec_Fr,
    x: ptr Fr): CBoolResult {.importc: "ffi_rln_verify_with_roots",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_generate_partial_proof*(rln: ptr RLN,
    witness: ptr PartialWitness): PartialProofResult {.importc: "ffi_rln_generate_partial_proof",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_finish_proof*(rln: ptr RLN,
    partial: ptr PartialProof,
    witness: ptr Witness): ProofResult {.importc: "ffi_rln_finish_proof",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_free*(rln: ptr RLN) {.importc: "ffi_rln_free",
    cdecl, dynlib: RLN_LIB.}

# RLNMerkleProof functions
proc ffi_rln_merkle_proof_new*(path_elements: ptr Vec_Fr,
    identity_path_index: ptr Vec_uint8): ptr MerkleProof {.importc: "ffi_rln_merkle_proof_new",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_merkle_proof_get_path_elements*(
  p: ptr MerkleProof): Vec_Fr {.importc: "ffi_rln_merkle_proof_get_path_elements",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_merkle_proof_get_identity_path_index*(
  p: ptr MerkleProof): Vec_uint8 {.importc: "ffi_rln_merkle_proof_get_identity_path_index",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_merkle_proof_to_bytes_le*(
  p: ptr MerkleProof): VecU8Result {.importc: "ffi_rln_merkle_proof_to_bytes_le",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_merkle_proof_to_bytes_be*(
  p: ptr MerkleProof): VecU8Result {.importc: "ffi_rln_merkle_proof_to_bytes_be",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_merkle_proof_from_bytes_le*(
  bytes: ptr Vec_uint8): MerkleProofResult {.importc: "ffi_rln_merkle_proof_from_bytes_le",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_merkle_proof_from_bytes_be*(
  bytes: ptr Vec_uint8): MerkleProofResult {.importc: "ffi_rln_merkle_proof_from_bytes_be",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_merkle_proof_free*(p: ptr MerkleProof) {.importc: "ffi_rln_merkle_proof_free",
    cdecl, dynlib: RLN_LIB.}

# RLNWitnessInput functions
proc ffi_rln_witness_input_new_single*(identity_secret: ptr SecretFr,
    user_message_limit: ptr Fr, message_id: ptr Fr,
    merkle_proof: ptr MerkleProof, x: ptr Fr,
    external_nullifier: ptr Fr): WitnessResult {.importc: "ffi_rln_witness_input_new_single",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_witness_input_new_multi*(identity_secret: ptr SecretFr,
    user_message_limit: ptr Fr, message_ids: ptr Vec_Fr,
    merkle_proof: ptr MerkleProof, x: ptr Fr,
    external_nullifier: ptr Fr,
    selector_used: ptr Vec_bool): WitnessResult {.importc: "ffi_rln_witness_input_new_multi",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_witness_input_get_identity_secret*(
  w: ptr Witness): ptr SecretFr {.importc: "ffi_rln_witness_input_get_identity_secret",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_witness_input_get_user_message_limit*(
  w: ptr Witness): ptr Fr {.importc: "ffi_rln_witness_input_get_user_message_limit",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_witness_input_get_message_id*(
  w: ptr Witness): FrResult {.importc: "ffi_rln_witness_input_get_message_id",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_witness_input_get_message_ids*(
  w: ptr Witness): VecFrResult {.importc: "ffi_rln_witness_input_get_message_ids",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_witness_input_get_path_elements*(
  w: ptr Witness): Vec_Fr {.importc: "ffi_rln_witness_input_get_path_elements",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_witness_input_get_merkle_proof*(
  w: ptr Witness): ptr MerkleProof {.importc: "ffi_rln_witness_input_get_merkle_proof",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_witness_input_get_identity_path_index*(
  w: ptr Witness): Vec_uint8 {.importc: "ffi_rln_witness_input_get_identity_path_index",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_witness_input_get_x*(w: ptr Witness): ptr Fr {.importc: "ffi_rln_witness_input_get_x",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_witness_input_get_external_nullifier*(
  w: ptr Witness): ptr Fr {.importc: "ffi_rln_witness_input_get_external_nullifier",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_witness_input_get_selector_used*(
  w: ptr Witness): VecBoolResult {.importc: "ffi_rln_witness_input_get_selector_used",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_witness_input_to_bytes_le*(w: ptr Witness): VecU8Result {.importc: "ffi_rln_witness_input_to_bytes_le",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_witness_input_to_bytes_be*(w: ptr Witness): VecU8Result {.importc: "ffi_rln_witness_input_to_bytes_be",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_witness_input_from_bytes_le*(bytes: ptr Vec_uint8): WitnessResult {.importc: "ffi_rln_witness_input_from_bytes_le",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_witness_input_from_bytes_be*(bytes: ptr Vec_uint8): WitnessResult {.importc: "ffi_rln_witness_input_from_bytes_be",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_witness_input_free*(w: ptr Witness) {.importc: "ffi_rln_witness_input_free",
    cdecl, dynlib: RLN_LIB.}

# RLNPartialWitnessInput functions
proc ffi_rln_partial_witness_input_new*(identity_secret: ptr SecretFr,
    user_message_limit: ptr Fr,
    merkle_proof: ptr MerkleProof): PartialWitnessResult {.importc: "ffi_rln_partial_witness_input_new",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_partial_witness_input_get_identity_secret*(
  w: ptr PartialWitness): ptr SecretFr {.importc: "ffi_rln_partial_witness_input_get_identity_secret",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_partial_witness_input_get_user_message_limit*(
  w: ptr PartialWitness): ptr Fr {.importc: "ffi_rln_partial_witness_input_get_user_message_limit",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_partial_witness_input_get_path_elements*(
  w: ptr PartialWitness): Vec_Fr {.importc: "ffi_rln_partial_witness_input_get_path_elements",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_partial_witness_input_get_identity_path_index*(
  w: ptr PartialWitness): Vec_uint8 {.importc: "ffi_rln_partial_witness_input_get_identity_path_index",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_witness_input_to_partial_witness*(
  w: ptr Witness): ptr PartialWitness {.importc: "ffi_rln_witness_input_to_partial_witness",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_partial_witness_input_to_bytes_le*(
  w: ptr PartialWitness): VecU8Result {.importc: "ffi_rln_partial_witness_input_to_bytes_le",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_partial_witness_input_to_bytes_be*(
  w: ptr PartialWitness): VecU8Result {.importc: "ffi_rln_partial_witness_input_to_bytes_be",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_partial_witness_input_from_bytes_le*(
  bytes: ptr Vec_uint8): PartialWitnessResult {.importc: "ffi_rln_partial_witness_input_from_bytes_le",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_partial_witness_input_from_bytes_be*(
  bytes: ptr Vec_uint8): PartialWitnessResult {.importc: "ffi_rln_partial_witness_input_from_bytes_be",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_partial_witness_input_free*(
  w: ptr PartialWitness) {.importc: "ffi_rln_partial_witness_input_free",
    cdecl, dynlib: RLN_LIB.}

# RLNProof functions
proc ffi_rln_proof_get_values*(p: ptr Proof): ptr ProofValues {.importc: "ffi_rln_proof_get_values",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_proof_to_bytes_le*(p: ptr Proof): VecU8Result {.importc: "ffi_rln_proof_to_bytes_le",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_proof_to_bytes_mixed*(p: ptr Proof): VecU8Result {.importc: "ffi_rln_proof_to_bytes_mixed",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_proof_from_bytes_le*(bytes: ptr Vec_uint8): ProofResult {.importc: "ffi_rln_proof_from_bytes_le",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_proof_from_bytes_mixed*(bytes: ptr Vec_uint8): ProofResult {.importc: "ffi_rln_proof_from_bytes_mixed",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_proof_free*(p: ptr Proof) {.importc: "ffi_rln_proof_free",
    cdecl, dynlib: RLN_LIB.}

# RLNPartialProof functions
proc ffi_rln_partial_proof_to_bytes_le*(
  p: ptr PartialProof): VecU8Result {.importc: "ffi_rln_partial_proof_to_bytes_le",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_partial_proof_from_bytes_le*(
  bytes: ptr Vec_uint8): PartialProofResult {.importc: "ffi_rln_partial_proof_from_bytes_le",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_partial_proof_free*(p: ptr PartialProof) {.importc: "ffi_rln_partial_proof_free",
    cdecl, dynlib: RLN_LIB.}

# RLNProofValues functions
proc ffi_rln_proof_values_get_root*(pv: ptr ProofValues): ptr Fr {.importc: "ffi_rln_proof_values_get_root",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_proof_values_get_x*(pv: ptr ProofValues): ptr Fr {.importc: "ffi_rln_proof_values_get_x",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_proof_values_get_external_nullifier*(
  pv: ptr ProofValues): ptr Fr {.importc: "ffi_rln_proof_values_get_external_nullifier",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_proof_values_get_y*(pv: ptr ProofValues): FrResult {.importc: "ffi_rln_proof_values_get_y",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_proof_values_get_nullifier*(
  pv: ptr ProofValues): FrResult {.importc: "ffi_rln_proof_values_get_nullifier",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_proof_values_get_selector_used*(
  pv: ptr ProofValues): VecBoolResult {.importc: "ffi_rln_proof_values_get_selector_used",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_proof_values_get_ys*(pv: ptr ProofValues): VecFrResult {.importc: "ffi_rln_proof_values_get_ys",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_proof_values_get_nullifiers*(
  pv: ptr ProofValues): VecFrResult {.importc: "ffi_rln_proof_values_get_nullifiers",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_proof_values_to_bytes_le*(
  pv: ptr ProofValues): VecU8Result {.importc: "ffi_rln_proof_values_to_bytes_le",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_proof_values_to_bytes_be*(
  pv: ptr ProofValues): VecU8Result {.importc: "ffi_rln_proof_values_to_bytes_be",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_proof_values_from_bytes_le*(
  bytes: ptr Vec_uint8): ProofValuesResult {.importc: "ffi_rln_proof_values_from_bytes_le",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_proof_values_from_bytes_be*(
  bytes: ptr Vec_uint8): ProofValuesResult {.importc: "ffi_rln_proof_values_from_bytes_be",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_proof_values_free*(pv: ptr ProofValues) {.importc: "ffi_rln_proof_values_free",
    cdecl, dynlib: RLN_LIB.}

# Identity secret recovery
proc ffi_rln_compute_id_secret*(share1_x: ptr Fr, share1_y: ptr Fr,
    share2_x: ptr Fr,
    share2_y: ptr Fr): SecretFrResult {.importc: "ffi_rln_compute_id_secret",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_recover_id_secret*(pv1: ptr ProofValues,
    pv2: ptr ProofValues): SecretFrResult {.importc: "ffi_rln_recover_id_secret",
    cdecl, dynlib: RLN_LIB.}

# Merkle tree operations (stateful mode)
proc ffi_rln_tree_depth*(rln: ptr RLN): UsizeResult {.importc: "ffi_rln_tree_depth",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_leaves_set*(rln: ptr RLN): UsizeResult {.importc: "ffi_rln_leaves_set",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_get_root*(rln: ptr RLN): FrResult {.importc: "ffi_rln_get_root",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_get_subtree_root*(rln: ptr RLN, level: CSize,
    index: CSize): FrResult {.importc: "ffi_rln_get_subtree_root", cdecl,
    dynlib: RLN_LIB.}
proc ffi_rln_set_leaf*(rln: ptr RLN, index: CSize,
    leaf: ptr Fr): CBoolResult {.importc: "ffi_rln_set_leaf", cdecl,
    dynlib: RLN_LIB.}
proc ffi_rln_set_leaves_from*(rln: ptr RLN, index: CSize,
    leaves: ptr Vec_Fr): CBoolResult {.importc: "ffi_rln_set_leaves_from",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_init_tree_with_leaves*(rln: ptr RLN,
    leaves: ptr Vec_Fr): CBoolResult {.importc: "ffi_rln_init_tree_with_leaves",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_get_leaf*(rln: ptr RLN,
    index: CSize): FrResult {.importc: "ffi_rln_get_leaf", cdecl,
    dynlib: RLN_LIB.}
proc ffi_rln_get_empty_leaves_indices*(rln: ptr RLN): VecSizeResult {.importc: "ffi_rln_get_empty_leaves_indices",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_atomic_operation*(rln: ptr RLN, index: CSize,
    leaves: ptr Vec_Fr,
    indices: ptr Vec_size): CBoolResult {.importc: "ffi_rln_atomic_operation",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_set_next_leaf*(rln: ptr RLN,
    leaf: ptr Fr): CBoolResult {.importc: "ffi_rln_set_next_leaf", cdecl,
    dynlib: RLN_LIB.}
proc ffi_rln_delete_leaf*(rln: ptr RLN,
    index: CSize): CBoolResult {.importc: "ffi_rln_delete_leaf", cdecl,
    dynlib: RLN_LIB.}
proc ffi_rln_get_merkle_proof*(rln: ptr RLN,
    index: CSize): MerkleProofResult {.importc: "ffi_rln_get_merkle_proof",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_set_metadata*(rln: ptr RLN,
    metadata: ptr Vec_uint8): CBoolResult {.importc: "ffi_rln_set_metadata",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_get_metadata*(rln: ptr RLN): VecU8Result {.importc: "ffi_rln_get_metadata",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_close*(rln: ptr RLN): CBoolResult {.importc: "ffi_rln_close",
    cdecl, dynlib: RLN_LIB.}

proc asVecU8(buf: var seq[uint8]): Vec_uint8 =
  result.dataPtr = if buf.len > 0: addr buf[0] else: nil
  result.len = csize_t(buf.len)
  result.cap = csize_t(buf.len)

proc asString(v: Vec_uint8): string =
  if v.dataPtr.isNil:
    return ""
  result = newString(v.len.int)
  if v.len > 0:
    copyMem(addr result[0], v.dataPtr, v.len.int)

proc fileToBytes(path: string): seq[uint8] =
  let s = readFile(path)
  result = newSeq[uint8](s.len)
  if s.len > 0:
    copyMem(addr result[0], unsafeAddr s[0], s.len)

proc strToBytes(s: string): seq[uint8] =
  result = newSeq[uint8](s.len)
  if s.len > 0:
    copyMem(addr result[0], unsafeAddr s[0], s.len)
