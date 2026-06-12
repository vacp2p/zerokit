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
  CFr* = object
  RLN* = object
  Proof* = object
  PartialProof* = object
  Witness* = object
  PartialWitness* = object
  ProofValues* = object

  Vec_CFr* = object
    dataPtr*: ptr CFr
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
    path_elements*: Vec_CFr
    path_index*: Vec_uint8

  CBoolResult* = object
    ok*: bool
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

  CFrResult* = object
    ok*: ptr CFr
    err*: Vec_uint8

  VecCFrResult* = object
    ok*: Vec_CFr
    err*: Vec_uint8

  VecU8Result* = object
    ok*: Vec_uint8
    err*: Vec_uint8

  VecBoolResult* = object
    ok*: Vec_bool
    err*: Vec_uint8

# CFr functions
proc ffi_cfr_zero*(): ptr CFr {.importc: "ffi_cfr_zero", cdecl,
    dynlib: RLN_LIB.}
proc ffi_cfr_one*(): ptr CFr {.importc: "ffi_cfr_one", cdecl, dynlib: RLN_LIB.}
proc ffi_cfr_to_bytes_le*(cfr: ptr CFr): VecU8Result {.importc: "ffi_cfr_to_bytes_le",
    cdecl, dynlib: RLN_LIB.}
proc ffi_cfr_to_bytes_be*(cfr: ptr CFr): VecU8Result {.importc: "ffi_cfr_to_bytes_be",
    cdecl, dynlib: RLN_LIB.}
proc ffi_bytes_le_to_cfr*(bytes: ptr Vec_uint8): CFrResult {.importc: "ffi_bytes_le_to_cfr",
    cdecl, dynlib: RLN_LIB.}
proc ffi_bytes_be_to_cfr*(bytes: ptr Vec_uint8): CFrResult {.importc: "ffi_bytes_be_to_cfr",
    cdecl, dynlib: RLN_LIB.}
proc ffi_uint_to_cfr*(value: uint32): ptr CFr {.importc: "ffi_uint_to_cfr",
    cdecl, dynlib: RLN_LIB.}
proc ffi_cfr_debug*(cfr: ptr CFr): Vec_uint8 {.importc: "ffi_cfr_debug", cdecl,
    dynlib: RLN_LIB.}
proc ffi_cfr_free*(x: ptr CFr) {.importc: "ffi_cfr_free", cdecl,
    dynlib: RLN_LIB.}

# Vec<CFr> functions
proc ffi_vec_cfr_new*(capacity: CSize): Vec_CFr {.importc: "ffi_vec_cfr_new",
    cdecl, dynlib: RLN_LIB.}
proc ffi_vec_cfr_from_cfr*(cfr: ptr CFr): Vec_CFr {.importc: "ffi_vec_cfr_from_cfr",
    cdecl, dynlib: RLN_LIB.}
proc ffi_vec_cfr_push*(v: ptr Vec_CFr, cfr: ptr CFr) {.importc: "ffi_vec_cfr_push",
    cdecl, dynlib: RLN_LIB.}
proc ffi_vec_cfr_len*(v: ptr Vec_CFr): CSize {.importc: "ffi_vec_cfr_len",
    cdecl, dynlib: RLN_LIB.}
proc ffi_vec_cfr_get*(v: ptr Vec_CFr, i: CSize): ptr CFr {.importc: "ffi_vec_cfr_get",
    cdecl, dynlib: RLN_LIB.}
proc ffi_vec_cfr_to_bytes_le*(v: ptr Vec_CFr): VecU8Result {.importc: "ffi_vec_cfr_to_bytes_le",
    cdecl, dynlib: RLN_LIB.}
proc ffi_vec_cfr_to_bytes_be*(v: ptr Vec_CFr): VecU8Result {.importc: "ffi_vec_cfr_to_bytes_be",
    cdecl, dynlib: RLN_LIB.}
proc ffi_bytes_le_to_vec_cfr*(bytes: ptr Vec_uint8): VecCFrResult {.importc: "ffi_bytes_le_to_vec_cfr",
    cdecl, dynlib: RLN_LIB.}
proc ffi_bytes_be_to_vec_cfr*(bytes: ptr Vec_uint8): VecCFrResult {.importc: "ffi_bytes_be_to_vec_cfr",
    cdecl, dynlib: RLN_LIB.}
proc ffi_vec_cfr_debug*(v: ptr Vec_CFr): Vec_uint8 {.importc: "ffi_vec_cfr_debug",
    cdecl, dynlib: RLN_LIB.}
proc ffi_vec_cfr_free*(v: Vec_CFr) {.importc: "ffi_vec_cfr_free", cdecl,
    dynlib: RLN_LIB.}

# Vec<uint8> functions
proc ffi_vec_u8_to_bytes_le*(v: ptr Vec_uint8): VecU8Result {.importc: "ffi_vec_u8_to_bytes_le",
    cdecl, dynlib: RLN_LIB.}
proc ffi_vec_u8_to_bytes_be*(v: ptr Vec_uint8): VecU8Result {.importc: "ffi_vec_u8_to_bytes_be",
    cdecl, dynlib: RLN_LIB.}
proc ffi_bytes_le_to_vec_u8*(bytes: ptr Vec_uint8): VecU8Result {.importc: "ffi_bytes_le_to_vec_u8",
    cdecl, dynlib: RLN_LIB.}
proc ffi_bytes_be_to_vec_u8*(bytes: ptr Vec_uint8): VecU8Result {.importc: "ffi_bytes_be_to_vec_u8",
    cdecl, dynlib: RLN_LIB.}
proc ffi_vec_u8_debug*(v: ptr Vec_uint8): Vec_uint8 {.importc: "ffi_vec_u8_debug",
    cdecl, dynlib: RLN_LIB.}
proc ffi_vec_u8_free*(v: Vec_uint8) {.importc: "ffi_vec_u8_free", cdecl,
    dynlib: RLN_LIB.}

# Hashing functions
proc ffi_hash_to_field_le*(input: ptr Vec_uint8): ptr CFr {.importc: "ffi_hash_to_field_le",
    cdecl, dynlib: RLN_LIB.}
proc ffi_hash_to_field_be*(input: ptr Vec_uint8): ptr CFr {.importc: "ffi_hash_to_field_be",
    cdecl, dynlib: RLN_LIB.}
proc ffi_poseidon_hash_pair*(a: ptr CFr,
    b: ptr CFr): ptr CFr {.importc: "ffi_poseidon_hash_pair", cdecl,
    dynlib: RLN_LIB.}

# Identity functions
proc ffi_key_gen*(): Vec_CFr {.importc: "ffi_key_gen", cdecl, dynlib: RLN_LIB.}
proc ffi_seeded_key_gen*(seed: ptr Vec_uint8): Vec_CFr {.importc: "ffi_seeded_key_gen",
    cdecl, dynlib: RLN_LIB.}

# ExtendedIdentity functions
proc ffi_extended_key_gen*(): Vec_CFr {.importc: "ffi_extended_key_gen", cdecl,
    dynlib: RLN_LIB.}
proc ffi_seeded_extended_key_gen*(seed: ptr Vec_uint8): Vec_CFr {.importc: "ffi_seeded_extended_key_gen",
    cdecl, dynlib: RLN_LIB.}

# CString functions
proc ffi_c_string_free*(s: Vec_uint8) {.importc: "ffi_c_string_free", cdecl,
    dynlib: RLN_LIB.}

# RLN instance functions
proc ffi_rln_v3_new_stateless*(zkey_data: ptr Vec_uint8,
    graph_data: ptr Vec_uint8): RLNResult {.importc: "ffi_rln_v3_new_stateless",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_v3_new_stateless_default*(): ptr RLN {.importc: "ffi_rln_v3_new_stateless_default",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_v3_new_with_full_merkle_tree*(tree_depth: CSize,
    zkey_data: ptr Vec_uint8,
    graph_data: ptr Vec_uint8): RLNResult {.importc: "ffi_rln_v3_new_with_full_merkle_tree",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_v3_new_with_full_merkle_tree_default*(): ptr RLN {.importc: "ffi_rln_v3_new_with_full_merkle_tree_default",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_v3_new_with_optimal_merkle_tree*(tree_depth: CSize,
    zkey_data: ptr Vec_uint8,
    graph_data: ptr Vec_uint8): RLNResult {.importc: "ffi_rln_v3_new_with_optimal_merkle_tree",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_v3_new_with_optimal_merkle_tree_default*(): ptr RLN {.importc: "ffi_rln_v3_new_with_optimal_merkle_tree_default",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_v3_new_with_pm_tree*(tree_depth: CSize,
    zkey_data: ptr Vec_uint8,
    graph_data: ptr Vec_uint8,
    config_path: cstring): RLNResult {.importc: "ffi_rln_v3_new_with_pm_tree",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_v3_new_with_pm_tree_default*(config_path: cstring): ptr RLN {.
    importc: "ffi_rln_v3_new_with_pm_tree_default",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_v3_generate_proof*(rln: ptr ptr RLN,
    witness: ptr ptr Witness): ProofResult {.importc: "ffi_rln_v3_generate_proof",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_v3_verify*(rln: ptr ptr RLN,
    proof: ptr ptr Proof,
    x: ptr CFr): CBoolResult {.importc: "ffi_rln_v3_verify",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_v3_verify_with_roots*(rln: ptr ptr RLN,
    proof: ptr ptr Proof,
    roots: ptr Vec_CFr,
    x: ptr CFr): CBoolResult {.importc: "ffi_rln_v3_verify_with_roots",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_v3_generate_partial_proof*(rln: ptr ptr RLN,
    witness: ptr ptr PartialWitness): PartialProofResult {.importc: "ffi_rln_v3_generate_partial_proof",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_v3_finish_proof*(rln: ptr ptr RLN,
    partial: ptr ptr PartialProof,
    witness: ptr ptr Witness): ProofResult {.importc: "ffi_rln_v3_finish_proof",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_v3_free*(rln: ptr RLN) {.importc: "ffi_rln_v3_free",
    cdecl, dynlib: RLN_LIB.}

# RLNWitnessInput functions
proc ffi_rln_v3_witness_input_new_single*(identity_secret: ptr CFr,
    user_message_limit: ptr CFr, message_id: ptr CFr,
    path_elements: ptr Vec_CFr, identity_path_index: ptr Vec_uint8, x: ptr CFr,
    external_nullifier: ptr CFr): WitnessResult {.importc: "ffi_rln_v3_witness_input_new_single",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_v3_witness_input_new_multi*(identity_secret: ptr CFr,
    user_message_limit: ptr CFr, message_ids: ptr Vec_CFr,
    path_elements: ptr Vec_CFr, identity_path_index: ptr Vec_uint8, x: ptr CFr,
    external_nullifier: ptr CFr,
    selector_used: ptr Vec_bool): WitnessResult {.importc: "ffi_rln_v3_witness_input_new_multi",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_v3_witness_input_get_identity_secret*(
  w: ptr ptr Witness): ptr CFr {.importc: "ffi_rln_v3_witness_input_get_identity_secret",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_v3_witness_input_get_user_message_limit*(
  w: ptr ptr Witness): ptr CFr {.importc: "ffi_rln_v3_witness_input_get_user_message_limit",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_v3_witness_input_get_message_id*(
  w: ptr ptr Witness): CFrResult {.importc: "ffi_rln_v3_witness_input_get_message_id",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_v3_witness_input_get_message_ids*(
  w: ptr ptr Witness): VecCFrResult {.importc: "ffi_rln_v3_witness_input_get_message_ids",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_v3_witness_input_get_path_elements*(
  w: ptr ptr Witness): Vec_CFr {.importc: "ffi_rln_v3_witness_input_get_path_elements",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_v3_witness_input_get_identity_path_index*(
  w: ptr ptr Witness): Vec_uint8 {.importc: "ffi_rln_v3_witness_input_get_identity_path_index",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_v3_witness_input_get_x*(w: ptr ptr Witness): ptr CFr {.importc: "ffi_rln_v3_witness_input_get_x",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_v3_witness_input_get_external_nullifier*(
  w: ptr ptr Witness): ptr CFr {.importc: "ffi_rln_v3_witness_input_get_external_nullifier",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_v3_witness_input_get_selector_used*(
  w: ptr ptr Witness): VecBoolResult {.importc: "ffi_rln_v3_witness_input_get_selector_used",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_v3_witness_to_bytes_le*(w: ptr ptr Witness): VecU8Result {.importc: "ffi_rln_v3_witness_to_bytes_le",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_v3_witness_to_bytes_be*(w: ptr ptr Witness): VecU8Result {.importc: "ffi_rln_v3_witness_to_bytes_be",
    cdecl, dynlib: RLN_LIB.}
proc ffi_bytes_le_to_rln_v3_witness*(bytes: ptr Vec_uint8): WitnessResult {.importc: "ffi_bytes_le_to_rln_v3_witness",
    cdecl, dynlib: RLN_LIB.}
proc ffi_bytes_be_to_rln_v3_witness*(bytes: ptr Vec_uint8): WitnessResult {.importc: "ffi_bytes_be_to_rln_v3_witness",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_v3_witness_input_free*(w: ptr Witness) {.importc: "ffi_rln_v3_witness_input_free",
    cdecl, dynlib: RLN_LIB.}

# RLNPartialWitnessInput functions
proc ffi_rln_v3_partial_witness_input_new*(identity_secret: ptr CFr,
    user_message_limit: ptr CFr, path_elements: ptr Vec_CFr,
    identity_path_index: ptr Vec_uint8): PartialWitnessResult {.importc: "ffi_rln_v3_partial_witness_input_new",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_v3_partial_witness_input_get_identity_secret*(
  w: ptr ptr PartialWitness): ptr CFr {.importc: "ffi_rln_v3_partial_witness_input_get_identity_secret",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_v3_partial_witness_input_get_user_message_limit*(
  w: ptr ptr PartialWitness): ptr CFr {.importc: "ffi_rln_v3_partial_witness_input_get_user_message_limit",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_v3_partial_witness_input_get_path_elements*(
  w: ptr ptr PartialWitness): Vec_CFr {.importc: "ffi_rln_v3_partial_witness_input_get_path_elements",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_v3_partial_witness_input_get_identity_path_index*(
  w: ptr ptr PartialWitness): Vec_uint8 {.importc: "ffi_rln_v3_partial_witness_input_get_identity_path_index",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_v3_witness_to_partial_witness*(
  w: ptr ptr Witness): ptr PartialWitness {.importc: "ffi_rln_v3_witness_to_partial_witness",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_v3_partial_witness_to_bytes_le*(
  w: ptr ptr PartialWitness): VecU8Result {.importc: "ffi_rln_v3_partial_witness_to_bytes_le",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_v3_partial_witness_to_bytes_be*(
  w: ptr ptr PartialWitness): VecU8Result {.importc: "ffi_rln_v3_partial_witness_to_bytes_be",
    cdecl, dynlib: RLN_LIB.}
proc ffi_bytes_le_to_rln_v3_partial_witness*(
  bytes: ptr Vec_uint8): PartialWitnessResult {.importc: "ffi_bytes_le_to_rln_v3_partial_witness",
    cdecl, dynlib: RLN_LIB.}
proc ffi_bytes_be_to_rln_v3_partial_witness*(
  bytes: ptr Vec_uint8): PartialWitnessResult {.importc: "ffi_bytes_be_to_rln_v3_partial_witness",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_v3_partial_witness_input_free*(
  w: ptr PartialWitness) {.importc: "ffi_rln_v3_partial_witness_input_free",
    cdecl, dynlib: RLN_LIB.}

# RLNProof functions
proc ffi_rln_v3_proof_get_values*(p: ptr ptr Proof): ptr ProofValues {.importc: "ffi_rln_v3_proof_get_values",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_v3_proof_to_bytes_le*(p: ptr ptr Proof): VecU8Result {.importc: "ffi_rln_v3_proof_to_bytes_le",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_v3_proof_to_bytes_mixed*(p: ptr ptr Proof): VecU8Result {.importc: "ffi_rln_v3_proof_to_bytes_mixed",
    cdecl, dynlib: RLN_LIB.}
proc ffi_bytes_le_to_rln_v3_proof*(bytes: ptr Vec_uint8): ProofResult {.importc: "ffi_bytes_le_to_rln_v3_proof",
    cdecl, dynlib: RLN_LIB.}
proc ffi_bytes_mixed_to_rln_v3_proof*(bytes: ptr Vec_uint8): ProofResult {.importc: "ffi_bytes_mixed_to_rln_v3_proof",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_v3_proof_free*(p: ptr Proof) {.importc: "ffi_rln_v3_proof_free",
    cdecl, dynlib: RLN_LIB.}

# RLNPartialProof functions
proc ffi_rln_v3_partial_proof_to_bytes_le*(
  p: ptr ptr PartialProof): VecU8Result {.importc: "ffi_rln_v3_partial_proof_to_bytes_le",
    cdecl, dynlib: RLN_LIB.}
proc ffi_bytes_le_to_rln_v3_partial_proof*(
  bytes: ptr Vec_uint8): PartialProofResult {.importc: "ffi_bytes_le_to_rln_v3_partial_proof",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_v3_partial_proof_free*(p: ptr PartialProof) {.importc: "ffi_rln_v3_partial_proof_free",
    cdecl, dynlib: RLN_LIB.}

# RLNProofValues functions
proc ffi_rln_v3_proof_values_get_root*(pv: ptr ptr ProofValues): ptr CFr {.importc: "ffi_rln_v3_proof_values_get_root",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_v3_proof_values_get_x*(pv: ptr ptr ProofValues): ptr CFr {.importc: "ffi_rln_v3_proof_values_get_x",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_v3_proof_values_get_external_nullifier*(
  pv: ptr ptr ProofValues): ptr CFr {.importc: "ffi_rln_v3_proof_values_get_external_nullifier",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_v3_proof_values_get_y*(pv: ptr ptr ProofValues): CFrResult {.importc: "ffi_rln_v3_proof_values_get_y",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_v3_proof_values_get_nullifier*(
  pv: ptr ptr ProofValues): CFrResult {.importc: "ffi_rln_v3_proof_values_get_nullifier",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_v3_proof_values_get_selector_used*(
  pv: ptr ptr ProofValues): VecBoolResult {.importc: "ffi_rln_v3_proof_values_get_selector_used",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_v3_proof_values_get_ys*(pv: ptr ptr ProofValues): VecCFrResult {.importc: "ffi_rln_v3_proof_values_get_ys",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_v3_proof_values_get_nullifiers*(
  pv: ptr ptr ProofValues): VecCFrResult {.importc: "ffi_rln_v3_proof_values_get_nullifiers",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_v3_proof_values_to_bytes_le*(
  pv: ptr ptr ProofValues): VecU8Result {.importc: "ffi_rln_v3_proof_values_to_bytes_le",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_v3_proof_values_to_bytes_be*(
  pv: ptr ptr ProofValues): VecU8Result {.importc: "ffi_rln_v3_proof_values_to_bytes_be",
    cdecl, dynlib: RLN_LIB.}
proc ffi_bytes_le_to_rln_v3_proof_values*(
  bytes: ptr Vec_uint8): ProofValuesResult {.importc: "ffi_bytes_le_to_rln_v3_proof_values",
    cdecl, dynlib: RLN_LIB.}
proc ffi_bytes_be_to_rln_v3_proof_values*(
  bytes: ptr Vec_uint8): ProofValuesResult {.importc: "ffi_bytes_be_to_rln_v3_proof_values",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_v3_proof_values_free*(pv: ptr ProofValues) {.importc: "ffi_rln_v3_proof_values_free",
    cdecl, dynlib: RLN_LIB.}

# Identity secret recovery
proc ffi_rln_v3_compute_id_secret*(share1_x: ptr CFr, share1_y: ptr CFr,
    share2_x: ptr CFr,
    share2_y: ptr CFr): CFrResult {.importc: "ffi_rln_v3_compute_id_secret",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_v3_recover_id_secret*(pv1: ptr ptr ProofValues,
    pv2: ptr ptr ProofValues): CFrResult {.importc: "ffi_rln_v3_recover_id_secret",
    cdecl, dynlib: RLN_LIB.}

# Merkle tree operations (stateful mode)
proc ffi_rln_v3_merkle_proof_free*(p: ptr MerkleProof) {.importc: "ffi_rln_v3_merkle_proof_free",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_v3_delete_leaf*(rln: ptr ptr RLN,
    index: CSize): CBoolResult {.importc: "ffi_rln_v3_delete_leaf", cdecl,
    dynlib: RLN_LIB.}
proc ffi_rln_v3_set_leaf*(rln: ptr ptr RLN, index: CSize,
    leaf: ptr CFr): CBoolResult {.importc: "ffi_rln_v3_set_leaf", cdecl,
    dynlib: RLN_LIB.}
proc ffi_rln_v3_get_leaf*(rln: ptr ptr RLN,
    index: CSize): CFrResult {.importc: "ffi_rln_v3_get_leaf", cdecl,
    dynlib: RLN_LIB.}
proc ffi_rln_v3_leaves_set*(rln: ptr ptr RLN): CSize {.importc: "ffi_rln_v3_leaves_set",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_v3_set_next_leaf*(rln: ptr ptr RLN,
    leaf: ptr CFr): CBoolResult {.importc: "ffi_rln_v3_set_next_leaf", cdecl,
    dynlib: RLN_LIB.}
proc ffi_rln_v3_set_leaves_from*(rln: ptr ptr RLN, index: CSize,
    leaves: ptr Vec_CFr): CBoolResult {.importc: "ffi_rln_v3_set_leaves_from",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_v3_init_tree_with_leaves*(rln: ptr ptr RLN,
    leaves: ptr Vec_CFr): CBoolResult {.importc: "ffi_rln_v3_init_tree_with_leaves",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_v3_atomic_operation*(rln: ptr ptr RLN, index: CSize,
    leaves: ptr Vec_CFr,
    indices: ptr Vec_size): CBoolResult {.importc: "ffi_rln_v3_atomic_operation",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_v3_seq_atomic_operation*(rln: ptr ptr RLN,
    leaves: ptr Vec_CFr,
    indices: ptr Vec_uint8): CBoolResult {.importc: "ffi_rln_v3_seq_atomic_operation",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_v3_get_root*(rln: ptr ptr RLN): ptr CFr {.importc: "ffi_rln_v3_get_root",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_v3_get_merkle_proof*(rln: ptr ptr RLN,
    index: CSize): MerkleProofResult {.importc: "ffi_rln_v3_get_merkle_proof",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_v3_set_metadata*(rln: ptr ptr RLN,
    metadata: ptr Vec_uint8): CBoolResult {.importc: "ffi_rln_v3_set_metadata",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_v3_get_metadata*(rln: ptr ptr RLN): VecU8Result {.importc: "ffi_rln_v3_get_metadata",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_v3_flush*(rln: ptr ptr RLN): CBoolResult {.importc: "ffi_rln_v3_flush",
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
