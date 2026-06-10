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
  FFI_RLNV3* = object
  FFI_RLNV3Proof* = object
  FFI_RLNV3PartialProof* = object
  FFI_RLNV3WitnessInput* = object
  FFI_RLNV3PartialWitnessInput* = object
  FFI_RLNV3ProofValues* = object

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

  FFI_RLNV3MerkleProof* = object
    path_elements*: Vec_CFr
    path_index*: Vec_uint8

  CBoolResult* = object
    ok*: bool
    err*: Vec_uint8

  CResultRLNV3Ptr* = object
    ok*: ptr FFI_RLNV3
    err*: Vec_uint8

  CResultProofPtr* = object
    ok*: ptr FFI_RLNV3Proof
    err*: Vec_uint8

  CResultPartialProofPtr* = object
    ok*: ptr FFI_RLNV3PartialProof
    err*: Vec_uint8

  CResultWitnessInputPtr* = object
    ok*: ptr FFI_RLNV3WitnessInput
    err*: Vec_uint8

  CResultPartialWitnessInputPtr* = object
    ok*: ptr FFI_RLNV3PartialWitnessInput
    err*: Vec_uint8

  CResultProofValuesPtr* = object
    ok*: ptr FFI_RLNV3ProofValues
    err*: Vec_uint8

  CResultMerkleProofPtr* = object
    ok*: ptr FFI_RLNV3MerkleProof
    err*: Vec_uint8

  CResultCFrPtr* = object
    ok*: ptr CFr
    err*: Vec_uint8

  CResultVecCFr* = object
    ok*: Vec_CFr
    err*: Vec_uint8

  CResultVecU8* = object
    ok*: Vec_uint8
    err*: Vec_uint8

  CResultVecBool* = object
    ok*: Vec_bool
    err*: Vec_uint8

# CFr functions
proc ffi_cfr_zero*(): ptr CFr {.importc: "ffi_cfr_zero", cdecl,
    dynlib: RLN_LIB.}
proc ffi_cfr_one*(): ptr CFr {.importc: "ffi_cfr_one", cdecl, dynlib: RLN_LIB.}
proc ffi_cfr_free*(x: ptr CFr) {.importc: "ffi_cfr_free", cdecl,
    dynlib: RLN_LIB.}
proc ffi_uint_to_cfr*(value: uint32): ptr CFr {.importc: "ffi_uint_to_cfr",
    cdecl, dynlib: RLN_LIB.}
proc ffi_cfr_debug*(cfr: ptr CFr): Vec_uint8 {.importc: "ffi_cfr_debug", cdecl,
    dynlib: RLN_LIB.}
proc ffi_cfr_to_bytes_le*(cfr: ptr CFr): CResultVecU8 {.importc: "ffi_cfr_to_bytes_le",
    cdecl, dynlib: RLN_LIB.}
proc ffi_cfr_to_bytes_be*(cfr: ptr CFr): CResultVecU8 {.importc: "ffi_cfr_to_bytes_be",
    cdecl, dynlib: RLN_LIB.}
proc ffi_bytes_le_to_cfr*(bytes: ptr Vec_uint8): CResultCFrPtr {.importc: "ffi_bytes_le_to_cfr",
    cdecl, dynlib: RLN_LIB.}
proc ffi_bytes_be_to_cfr*(bytes: ptr Vec_uint8): CResultCFrPtr {.importc: "ffi_bytes_be_to_cfr",
    cdecl, dynlib: RLN_LIB.}

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
proc ffi_vec_cfr_to_bytes_le*(v: ptr Vec_CFr): CResultVecU8 {.importc: "ffi_vec_cfr_to_bytes_le",
    cdecl, dynlib: RLN_LIB.}
proc ffi_vec_cfr_to_bytes_be*(v: ptr Vec_CFr): CResultVecU8 {.importc: "ffi_vec_cfr_to_bytes_be",
    cdecl, dynlib: RLN_LIB.}
proc ffi_bytes_le_to_vec_cfr*(bytes: ptr Vec_uint8): CResultVecCFr {.importc: "ffi_bytes_le_to_vec_cfr",
    cdecl, dynlib: RLN_LIB.}
proc ffi_bytes_be_to_vec_cfr*(bytes: ptr Vec_uint8): CResultVecCFr {.importc: "ffi_bytes_be_to_vec_cfr",
    cdecl, dynlib: RLN_LIB.}
proc ffi_vec_cfr_debug*(v: ptr Vec_CFr): Vec_uint8 {.importc: "ffi_vec_cfr_debug",
    cdecl, dynlib: RLN_LIB.}
proc ffi_vec_cfr_free*(v: Vec_CFr) {.importc: "ffi_vec_cfr_free", cdecl,
    dynlib: RLN_LIB.}

# Vec<uint8> functions
proc ffi_vec_u8_to_bytes_le*(v: ptr Vec_uint8): CResultVecU8 {.importc: "ffi_vec_u8_to_bytes_le",
    cdecl, dynlib: RLN_LIB.}
proc ffi_vec_u8_to_bytes_be*(v: ptr Vec_uint8): CResultVecU8 {.importc: "ffi_vec_u8_to_bytes_be",
    cdecl, dynlib: RLN_LIB.}
proc ffi_bytes_le_to_vec_u8*(bytes: ptr Vec_uint8): CResultVecU8 {.importc: "ffi_bytes_le_to_vec_u8",
    cdecl, dynlib: RLN_LIB.}
proc ffi_bytes_be_to_vec_u8*(bytes: ptr Vec_uint8): CResultVecU8 {.importc: "ffi_bytes_be_to_vec_u8",
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

# Keygen function
proc ffi_key_gen*(): Vec_CFr {.importc: "ffi_key_gen", cdecl, dynlib: RLN_LIB.}
proc ffi_seeded_key_gen*(seed: ptr Vec_uint8): Vec_CFr {.importc: "ffi_seeded_key_gen",
    cdecl, dynlib: RLN_LIB.}
proc ffi_extended_key_gen*(): Vec_CFr {.importc: "ffi_extended_key_gen", cdecl,
    dynlib: RLN_LIB.}
proc ffi_seeded_extended_key_gen*(seed: ptr Vec_uint8): Vec_CFr {.importc: "ffi_seeded_extended_key_gen",
    cdecl, dynlib: RLN_LIB.}

# RLN instance functions
proc ffi_rln_v3_new_stateless*(zkey_data: ptr Vec_uint8,
    graph_data: ptr Vec_uint8): CResultRLNV3Ptr {.importc: "ffi_rln_v3_new_stateless",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_v3_new_with_pm_tree*(tree_depth: CSize, zkey_data: ptr Vec_uint8,
    graph_data: ptr Vec_uint8,
    config_path: cstring): CResultRLNV3Ptr {.importc: "ffi_rln_v3_new_with_pm_tree",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_v3_new_with_full_merkle_tree*(tree_depth: CSize,
    zkey_data: ptr Vec_uint8,
    graph_data: ptr Vec_uint8): CResultRLNV3Ptr {.importc: "ffi_rln_v3_new_with_full_merkle_tree",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_v3_new_with_optimal_merkle_tree*(tree_depth: CSize,
    zkey_data: ptr Vec_uint8,
    graph_data: ptr Vec_uint8): CResultRLNV3Ptr {.importc: "ffi_rln_v3_new_with_optimal_merkle_tree",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_v3_generate_proof*(rln: ptr ptr FFI_RLNV3,
    witness: ptr ptr FFI_RLNV3WitnessInput): CResultProofPtr {.importc: "ffi_rln_v3_generate_proof",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_v3_verify*(rln: ptr ptr FFI_RLNV3, proof: ptr ptr FFI_RLNV3Proof,
    x: ptr CFr): CBoolResult {.importc: "ffi_rln_v3_verify", cdecl,
    dynlib: RLN_LIB.}
proc ffi_rln_v3_verify_with_roots*(rln: ptr ptr FFI_RLNV3,
    proof: ptr ptr FFI_RLNV3Proof, roots: ptr Vec_CFr,
    x: ptr CFr): CBoolResult {.importc: "ffi_rln_v3_verify_with_roots", cdecl,
    dynlib: RLN_LIB.}
proc ffi_rln_v3_generate_partial_proof*(rln: ptr ptr FFI_RLNV3,
    witness: ptr ptr FFI_RLNV3PartialWitnessInput): CResultPartialProofPtr {.importc: "ffi_rln_v3_generate_partial_proof",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_v3_finish_proof*(rln: ptr ptr FFI_RLNV3,
    partial: ptr ptr FFI_RLNV3PartialProof,
    witness: ptr ptr FFI_RLNV3WitnessInput): CResultProofPtr {.importc: "ffi_rln_v3_finish_proof",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_v3_free*(rln: ptr FFI_RLNV3) {.importc: "ffi_rln_v3_free", cdecl,
    dynlib: RLN_LIB.}

# RLNWitnessInput functions
proc ffi_rln_v3_witness_input_new_single*(identity_secret: ptr CFr,
    user_message_limit: ptr CFr, message_id: ptr CFr,
    path_elements: ptr Vec_CFr, identity_path_index: ptr Vec_uint8, x: ptr CFr,
    external_nullifier: ptr CFr): CResultWitnessInputPtr {.importc: "ffi_rln_v3_witness_input_new_single",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_v3_witness_input_new_multi*(identity_secret: ptr CFr,
    user_message_limit: ptr CFr, message_ids: ptr Vec_CFr,
    path_elements: ptr Vec_CFr, identity_path_index: ptr Vec_uint8, x: ptr CFr,
    external_nullifier: ptr CFr,
    selector_used: ptr Vec_bool): CResultWitnessInputPtr {.importc: "ffi_rln_v3_witness_input_new_multi",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_v3_witness_input_get_identity_secret*(
  w: ptr ptr FFI_RLNV3WitnessInput): ptr CFr {.importc: "ffi_rln_v3_witness_input_get_identity_secret",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_v3_witness_input_get_user_message_limit*(
  w: ptr ptr FFI_RLNV3WitnessInput): ptr CFr {.importc: "ffi_rln_v3_witness_input_get_user_message_limit",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_v3_witness_input_get_message_id*(
  w: ptr ptr FFI_RLNV3WitnessInput): CResultCFrPtr {.importc: "ffi_rln_v3_witness_input_get_message_id",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_v3_witness_input_get_message_ids*(
  w: ptr ptr FFI_RLNV3WitnessInput): CResultVecCFr {.importc: "ffi_rln_v3_witness_input_get_message_ids",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_v3_witness_input_get_path_elements*(
  w: ptr ptr FFI_RLNV3WitnessInput): Vec_CFr {.importc: "ffi_rln_v3_witness_input_get_path_elements",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_v3_witness_input_get_identity_path_index*(
  w: ptr ptr FFI_RLNV3WitnessInput): Vec_uint8 {.importc: "ffi_rln_v3_witness_input_get_identity_path_index",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_v3_witness_input_get_x*(w: ptr ptr FFI_RLNV3WitnessInput): ptr CFr {.importc: "ffi_rln_v3_witness_input_get_x",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_v3_witness_input_get_external_nullifier*(
  w: ptr ptr FFI_RLNV3WitnessInput): ptr CFr {.importc: "ffi_rln_v3_witness_input_get_external_nullifier",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_v3_witness_input_get_selector_used*(
  w: ptr ptr FFI_RLNV3WitnessInput): CResultVecBool {.importc: "ffi_rln_v3_witness_input_get_selector_used",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_v3_witness_to_bytes_le*(w: ptr ptr FFI_RLNV3WitnessInput): CResultVecU8 {.importc: "ffi_rln_v3_witness_to_bytes_le",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_v3_witness_to_bytes_be*(w: ptr ptr FFI_RLNV3WitnessInput): CResultVecU8 {.importc: "ffi_rln_v3_witness_to_bytes_be",
    cdecl, dynlib: RLN_LIB.}
proc ffi_bytes_le_to_rln_v3_witness*(bytes: ptr Vec_uint8): CResultWitnessInputPtr {.importc: "ffi_bytes_le_to_rln_v3_witness",
    cdecl, dynlib: RLN_LIB.}
proc ffi_bytes_be_to_rln_v3_witness*(bytes: ptr Vec_uint8): CResultWitnessInputPtr {.importc: "ffi_bytes_be_to_rln_v3_witness",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_v3_witness_to_partial_witness*(
  w: ptr ptr FFI_RLNV3WitnessInput): ptr FFI_RLNV3PartialWitnessInput {.importc: "ffi_rln_v3_witness_to_partial_witness",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_v3_witness_input_free*(w: ptr FFI_RLNV3WitnessInput) {.importc: "ffi_rln_v3_witness_input_free",
    cdecl, dynlib: RLN_LIB.}

# RLNPartialWitnessInput functions
proc ffi_rln_v3_partial_witness_input_new*(identity_secret: ptr CFr,
    user_message_limit: ptr CFr, path_elements: ptr Vec_CFr,
    identity_path_index: ptr Vec_uint8): CResultPartialWitnessInputPtr {.importc: "ffi_rln_v3_partial_witness_input_new",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_v3_partial_witness_input_get_identity_secret*(
  w: ptr ptr FFI_RLNV3PartialWitnessInput): ptr CFr {.importc: "ffi_rln_v3_partial_witness_input_get_identity_secret",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_v3_partial_witness_input_get_user_message_limit*(
  w: ptr ptr FFI_RLNV3PartialWitnessInput): ptr CFr {.importc: "ffi_rln_v3_partial_witness_input_get_user_message_limit",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_v3_partial_witness_input_get_path_elements*(
  w: ptr ptr FFI_RLNV3PartialWitnessInput): Vec_CFr {.importc: "ffi_rln_v3_partial_witness_input_get_path_elements",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_v3_partial_witness_input_get_identity_path_index*(
  w: ptr ptr FFI_RLNV3PartialWitnessInput): Vec_uint8 {.importc: "ffi_rln_v3_partial_witness_input_get_identity_path_index",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_v3_partial_witness_to_bytes_le*(
  w: ptr ptr FFI_RLNV3PartialWitnessInput): CResultVecU8 {.importc: "ffi_rln_v3_partial_witness_to_bytes_le",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_v3_partial_witness_to_bytes_be*(
  w: ptr ptr FFI_RLNV3PartialWitnessInput): CResultVecU8 {.importc: "ffi_rln_v3_partial_witness_to_bytes_be",
    cdecl, dynlib: RLN_LIB.}
proc ffi_bytes_le_to_rln_v3_partial_witness*(
  bytes: ptr Vec_uint8): CResultPartialWitnessInputPtr {.importc: "ffi_bytes_le_to_rln_v3_partial_witness",
    cdecl, dynlib: RLN_LIB.}
proc ffi_bytes_be_to_rln_v3_partial_witness*(
  bytes: ptr Vec_uint8): CResultPartialWitnessInputPtr {.importc: "ffi_bytes_be_to_rln_v3_partial_witness",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_v3_partial_witness_input_free*(
  w: ptr FFI_RLNV3PartialWitnessInput) {.importc: "ffi_rln_v3_partial_witness_input_free",
    cdecl, dynlib: RLN_LIB.}

# RLNProof functions
proc ffi_rln_v3_proof_get_values*(p: ptr ptr FFI_RLNV3Proof): ptr FFI_RLNV3ProofValues {.importc: "ffi_rln_v3_proof_get_values",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_v3_proof_to_bytes_le*(p: ptr ptr FFI_RLNV3Proof): CResultVecU8 {.importc: "ffi_rln_v3_proof_to_bytes_le",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_v3_proof_to_bytes_mixed*(p: ptr ptr FFI_RLNV3Proof): CResultVecU8 {.importc: "ffi_rln_v3_proof_to_bytes_mixed",
    cdecl, dynlib: RLN_LIB.}
proc ffi_bytes_le_to_rln_v3_proof*(bytes: ptr Vec_uint8): CResultProofPtr {.importc: "ffi_bytes_le_to_rln_v3_proof",
    cdecl, dynlib: RLN_LIB.}
proc ffi_bytes_mixed_to_rln_v3_proof*(bytes: ptr Vec_uint8): CResultProofPtr {.importc: "ffi_bytes_mixed_to_rln_v3_proof",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_v3_proof_free*(p: ptr FFI_RLNV3Proof) {.importc: "ffi_rln_v3_proof_free",
    cdecl, dynlib: RLN_LIB.}

# RLNPartialProof functions
proc ffi_rln_v3_partial_proof_to_bytes_le*(
  p: ptr ptr FFI_RLNV3PartialProof): CResultVecU8 {.importc: "ffi_rln_v3_partial_proof_to_bytes_le",
    cdecl, dynlib: RLN_LIB.}
proc ffi_bytes_le_to_rln_v3_partial_proof*(
  bytes: ptr Vec_uint8): CResultPartialProofPtr {.importc: "ffi_bytes_le_to_rln_v3_partial_proof",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_v3_partial_proof_free*(p: ptr FFI_RLNV3PartialProof) {.importc: "ffi_rln_v3_partial_proof_free",
    cdecl, dynlib: RLN_LIB.}

# RLNProofValues functions
proc ffi_rln_v3_proof_values_get_root*(pv: ptr ptr FFI_RLNV3ProofValues): ptr CFr {.importc: "ffi_rln_v3_proof_values_get_root",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_v3_proof_values_get_x*(pv: ptr ptr FFI_RLNV3ProofValues): ptr CFr {.importc: "ffi_rln_v3_proof_values_get_x",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_v3_proof_values_get_external_nullifier*(
  pv: ptr ptr FFI_RLNV3ProofValues): ptr CFr {.importc: "ffi_rln_v3_proof_values_get_external_nullifier",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_v3_proof_values_get_y*(pv: ptr ptr FFI_RLNV3ProofValues): CResultCFrPtr {.importc: "ffi_rln_v3_proof_values_get_y",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_v3_proof_values_get_nullifier*(
  pv: ptr ptr FFI_RLNV3ProofValues): CResultCFrPtr {.importc: "ffi_rln_v3_proof_values_get_nullifier",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_v3_proof_values_get_ys*(pv: ptr ptr FFI_RLNV3ProofValues): CResultVecCFr {.importc: "ffi_rln_v3_proof_values_get_ys",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_v3_proof_values_get_nullifiers*(
  pv: ptr ptr FFI_RLNV3ProofValues): CResultVecCFr {.importc: "ffi_rln_v3_proof_values_get_nullifiers",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_v3_proof_values_get_selector_used*(
  pv: ptr ptr FFI_RLNV3ProofValues): CResultVecBool {.importc: "ffi_rln_v3_proof_values_get_selector_used",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_v3_proof_values_to_bytes_le*(
  pv: ptr ptr FFI_RLNV3ProofValues): CResultVecU8 {.importc: "ffi_rln_v3_proof_values_to_bytes_le",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_v3_proof_values_to_bytes_be*(
  pv: ptr ptr FFI_RLNV3ProofValues): CResultVecU8 {.importc: "ffi_rln_v3_proof_values_to_bytes_be",
    cdecl, dynlib: RLN_LIB.}
proc ffi_bytes_le_to_rln_v3_proof_values*(
  bytes: ptr Vec_uint8): CResultProofValuesPtr {.importc: "ffi_bytes_le_to_rln_v3_proof_values",
    cdecl, dynlib: RLN_LIB.}
proc ffi_bytes_be_to_rln_v3_proof_values*(
  bytes: ptr Vec_uint8): CResultProofValuesPtr {.importc: "ffi_bytes_be_to_rln_v3_proof_values",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_v3_proof_values_free*(pv: ptr FFI_RLNV3ProofValues) {.importc: "ffi_rln_v3_proof_values_free",
    cdecl, dynlib: RLN_LIB.}

# Identity secret recovery
proc ffi_rln_v3_compute_id_secret*(share1_x: ptr CFr, share1_y: ptr CFr,
    share2_x: ptr CFr,
    share2_y: ptr CFr): CResultCFrPtr {.importc: "ffi_rln_v3_compute_id_secret",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_v3_recover_id_secret*(pv1: ptr ptr FFI_RLNV3ProofValues,
    pv2: ptr ptr FFI_RLNV3ProofValues): CResultCFrPtr {.importc: "ffi_rln_v3_recover_id_secret",
    cdecl, dynlib: RLN_LIB.}

# Merkle tree operations (stateful mode)
proc ffi_rln_v3_set_next_leaf*(rln: ptr ptr FFI_RLNV3,
    leaf: ptr CFr): CBoolResult {.importc: "ffi_rln_v3_set_next_leaf", cdecl,
    dynlib: RLN_LIB.}
proc ffi_rln_v3_set_leaf*(rln: ptr ptr FFI_RLNV3, index: CSize,
    leaf: ptr CFr): CBoolResult {.importc: "ffi_rln_v3_set_leaf", cdecl,
    dynlib: RLN_LIB.}
proc ffi_rln_v3_get_leaf*(rln: ptr ptr FFI_RLNV3,
    index: CSize): CResultCFrPtr {.importc: "ffi_rln_v3_get_leaf", cdecl,
    dynlib: RLN_LIB.}
proc ffi_rln_v3_delete_leaf*(rln: ptr ptr FFI_RLNV3,
    index: CSize): CBoolResult {.importc: "ffi_rln_v3_delete_leaf", cdecl,
    dynlib: RLN_LIB.}
proc ffi_rln_v3_leaves_set*(rln: ptr ptr FFI_RLNV3): CSize {.importc: "ffi_rln_v3_leaves_set",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_v3_get_root*(rln: ptr ptr FFI_RLNV3): ptr CFr {.importc: "ffi_rln_v3_get_root",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_v3_set_leaves_from*(rln: ptr ptr FFI_RLNV3, index: CSize,
    leaves: ptr Vec_CFr): CBoolResult {.importc: "ffi_rln_v3_set_leaves_from",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_v3_init_tree_with_leaves*(rln: ptr ptr FFI_RLNV3,
    leaves: ptr Vec_CFr): CBoolResult {.importc: "ffi_rln_v3_init_tree_with_leaves",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_v3_atomic_operation*(rln: ptr ptr FFI_RLNV3, index: CSize,
    leaves: ptr Vec_CFr,
    indices: ptr Vec_size): CBoolResult {.importc: "ffi_rln_v3_atomic_operation",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_v3_seq_atomic_operation*(rln: ptr ptr FFI_RLNV3,
    leaves: ptr Vec_CFr,
    indices: ptr Vec_uint8): CBoolResult {.importc: "ffi_rln_v3_seq_atomic_operation",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_v3_get_merkle_proof*(rln: ptr ptr FFI_RLNV3,
    index: CSize): CResultMerkleProofPtr {.importc: "ffi_rln_v3_get_merkle_proof",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_v3_merkle_proof_free*(p: ptr FFI_RLNV3MerkleProof) {.importc: "ffi_rln_v3_merkle_proof_free",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_v3_set_metadata*(rln: ptr ptr FFI_RLNV3,
    metadata: ptr Vec_uint8): CBoolResult {.importc: "ffi_rln_v3_set_metadata",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_v3_get_metadata*(rln: ptr ptr FFI_RLNV3): CResultVecU8 {.importc: "ffi_rln_v3_get_metadata",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_v3_flush*(rln: ptr ptr FFI_RLNV3): CBoolResult {.importc: "ffi_rln_v3_flush",
    cdecl, dynlib: RLN_LIB.}

# Helpers functions
proc ffi_c_string_free*(s: Vec_uint8) {.importc: "ffi_c_string_free", cdecl,
    dynlib: RLN_LIB.}

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

proc main() =
  const treeDepth = 20

  echo "Creating RLN instance"
  let zkeyPath = "../resources/tree_depth_20/rln_final.arkzkey"
  let graphPath = "../resources/tree_depth_20/graph.bin"
  var zkeyBytes = fileToBytes(zkeyPath)
  var graphBytes = fileToBytes(graphPath)
  var zkeyData = asVecU8(zkeyBytes)
  var graphData = asVecU8(graphBytes)
  when defined(ffiStateless):
    let rlnInstanceResult = ffi_rln_v3_new_stateless(addr zkeyData,
        addr graphData)
  else:
    let rlnInstanceResult = ffi_rln_v3_new_with_pm_tree(csize_t(treeDepth),
        addr zkeyData, addr graphData, "")
  if rlnInstanceResult.ok.isNil:
    stderr.writeLine("RLN instance creation error: " & asString(
        rlnInstanceResult.err))
    ffi_c_string_free(rlnInstanceResult.err)
    return
  var rlnInstance = rlnInstanceResult.ok
  echo "  - RLN instance created successfully"
  echo "  - circuit tree depth = " & $treeDepth

  echo "\nGenerating identity keys"
  var keys = ffi_key_gen()
  let identitySecret = ffi_vec_cfr_get(addr keys, csize_t(0))
  let idCommitment = ffi_vec_cfr_get(addr keys, csize_t(1))
  echo "  - identity generated successfully"
  echo "  - identity secret = " & asString(ffi_cfr_debug(identitySecret))
  echo "  - id commitment = " & asString(ffi_cfr_debug(idCommitment))

  echo "\nCreating message limit"
  let userMessageLimit = ffi_uint_to_cfr(10'u32)
  echo "  - user message limit = " & asString(ffi_cfr_debug(userMessageLimit))

  echo "\nComputing rate commitment"
  let rateCommitment = ffi_poseidon_hash_pair(idCommitment, userMessageLimit)
  echo "  - rate commitment = " & asString(ffi_cfr_debug(rateCommitment))

  echo "\nCFr serialization: CFr <-> bytes"
  let serRateCommitmentResult = ffi_cfr_to_bytes_le(rateCommitment)
  if serRateCommitmentResult.err.dataPtr != nil:
    stderr.writeLine("Rate commitment serialization error: " & asString(
        serRateCommitmentResult.err))
    ffi_c_string_free(serRateCommitmentResult.err)
    return
  var serRateCommitment = serRateCommitmentResult.ok
  echo "  - serialized rate commitment = " & asString(ffi_vec_u8_debug(
      addr serRateCommitment))
  let deserRateCommitmentResult = ffi_bytes_le_to_cfr(addr serRateCommitment)
  if deserRateCommitmentResult.ok.isNil:
    stderr.writeLine("Rate commitment deserialization error: " & asString(
        deserRateCommitmentResult.err))
    ffi_c_string_free(deserRateCommitmentResult.err)
    return
  let deserRateCommitment = deserRateCommitmentResult.ok
  echo "  - deserialized rate commitment = " & asString(ffi_cfr_debug(deserRateCommitment))
  ffi_vec_u8_free(serRateCommitment)
  ffi_cfr_free(deserRateCommitment)

  when defined(ffiStateless):
    echo "\nBuilding Merkle path for stateless mode"
    let defaultLeaf = ffi_cfr_zero()
    var defaultHashes: seq[ptr CFr]
    defaultHashes.add(ffi_poseidon_hash_pair(defaultLeaf, defaultLeaf))
    for i in 1 ..< treeDepth - 1:
      defaultHashes.add(ffi_poseidon_hash_pair(defaultHashes[i - 1],
          defaultHashes[i - 1]))
    var pathElements = ffi_vec_cfr_new(csize_t(treeDepth))
    ffi_vec_cfr_push(addr pathElements, defaultLeaf)
    for i in 1 ..< treeDepth:
      ffi_vec_cfr_push(addr pathElements, defaultHashes[i - 1])
    var identityPathIndex = newSeq[uint8](treeDepth)
    var identityPathIndexVec = asVecU8(identityPathIndex)

    echo "\nVec<CFr> serialization: Vec<CFr> <-> bytes"
    let serPathElementsResult = ffi_vec_cfr_to_bytes_le(addr pathElements)
    if serPathElementsResult.err.dataPtr != nil:
      stderr.writeLine("Path elements serialization error: " & asString(
          serPathElementsResult.err))
      ffi_c_string_free(serPathElementsResult.err)
      return
    var serPathElements = serPathElementsResult.ok
    echo "  - serialized path elements = " & asString(ffi_vec_u8_debug(
        addr serPathElements))
    let deserPathElementsResult = ffi_bytes_le_to_vec_cfr(addr serPathElements)
    if deserPathElementsResult.err.dataPtr != nil:
      stderr.writeLine("Path elements deserialization error: " & asString(
          deserPathElementsResult.err))
      ffi_c_string_free(deserPathElementsResult.err)
      return
    var deserPathElements = deserPathElementsResult.ok
    echo "  - deserialized path elements = " & asString(ffi_vec_cfr_debug(
        addr deserPathElements))
    ffi_vec_cfr_free(deserPathElements)
    ffi_vec_u8_free(serPathElements)

    echo "\nVec<uint8> serialization: Vec<uint8> <-> bytes"
    let serPathIndexResult = ffi_vec_u8_to_bytes_le(addr identityPathIndexVec)
    if serPathIndexResult.err.dataPtr != nil:
      stderr.writeLine("Path index serialization error: " & asString(
          serPathIndexResult.err))
      ffi_c_string_free(serPathIndexResult.err)
      return
    var serPathIndex = serPathIndexResult.ok
    echo "  - serialized path index = " & asString(ffi_vec_u8_debug(
        addr serPathIndex))
    let deserPathIndexResult = ffi_bytes_le_to_vec_u8(addr serPathIndex)
    if deserPathIndexResult.err.dataPtr != nil:
      stderr.writeLine("Path index deserialization error: " & asString(
          deserPathIndexResult.err))
      ffi_c_string_free(deserPathIndexResult.err)
      return
    var deserPathIndex = deserPathIndexResult.ok
    echo "  - deserialized path index = " & asString(ffi_vec_u8_debug(
        addr deserPathIndex))
    ffi_vec_u8_free(deserPathIndex)
    ffi_vec_u8_free(serPathIndex)

    echo "\nComputing Merkle root for stateless mode"
    echo "  - computing root for index 0 with rate commitment"
    var computedRoot = ffi_poseidon_hash_pair(rateCommitment, defaultLeaf)
    for i in 1 ..< treeDepth:
      let nextRoot = ffi_poseidon_hash_pair(computedRoot, defaultHashes[i - 1])
      ffi_cfr_free(computedRoot)
      computedRoot = nextRoot
    echo "  - computed root = " & asString(ffi_cfr_debug(computedRoot))
  else:
    echo "\nAdding rate commitment to tree"
    let setLeafResult = ffi_rln_v3_set_next_leaf(addr rlnInstance, rateCommitment)
    if not setLeafResult.ok:
      stderr.writeLine("Adding rate commitment error: " & asString(
          setLeafResult.err))
      ffi_c_string_free(setLeafResult.err)
      return
    echo "  - rate commitment added at leaf 0"

    echo "\nGetting Merkle proof"
    let merkleProofResult = ffi_rln_v3_get_merkle_proof(addr rlnInstance,
        csize_t(0))
    if merkleProofResult.ok.isNil:
      stderr.writeLine("Merkle proof error: " & asString(merkleProofResult.err))
      ffi_c_string_free(merkleProofResult.err)
      return
    let merkleProof = merkleProofResult.ok
    echo "  - merkle proof obtained"

    echo "\nVec<CFr> serialization: Vec<CFr> <-> bytes"
    let serPathElementsResult = ffi_vec_cfr_to_bytes_le(
        addr merkleProof.path_elements)
    if serPathElementsResult.err.dataPtr != nil:
      stderr.writeLine("Path elements serialization error: " & asString(
          serPathElementsResult.err))
      ffi_c_string_free(serPathElementsResult.err)
      return
    var serPathElements = serPathElementsResult.ok
    echo "  - serialized path elements = " & asString(ffi_vec_u8_debug(
        addr serPathElements))
    let deserPathElementsResult = ffi_bytes_le_to_vec_cfr(addr serPathElements)
    if deserPathElementsResult.err.dataPtr != nil:
      stderr.writeLine("Path elements deserialization error: " & asString(
          deserPathElementsResult.err))
      ffi_c_string_free(deserPathElementsResult.err)
      return
    var deserPathElements = deserPathElementsResult.ok
    echo "  - deserialized path elements = " & asString(ffi_vec_cfr_debug(
        addr deserPathElements))
    ffi_vec_cfr_free(deserPathElements)
    ffi_vec_u8_free(serPathElements)

    echo "\nVec<uint8> serialization: Vec<uint8> <-> bytes"
    let serPathIndexResult = ffi_vec_u8_to_bytes_le(addr merkleProof.path_index)
    if serPathIndexResult.err.dataPtr != nil:
      stderr.writeLine("Path index serialization error: " & asString(
          serPathIndexResult.err))
      ffi_c_string_free(serPathIndexResult.err)
      return
    var serPathIndex = serPathIndexResult.ok
    echo "  - serialized path index = " & asString(ffi_vec_u8_debug(
        addr serPathIndex))
    let deserPathIndexResult = ffi_bytes_le_to_vec_u8(addr serPathIndex)
    if deserPathIndexResult.err.dataPtr != nil:
      stderr.writeLine("Path index deserialization error: " & asString(
          deserPathIndexResult.err))
      ffi_c_string_free(deserPathIndexResult.err)
      return
    var deserPathIndex = deserPathIndexResult.ok
    echo "  - deserialized path index = " & asString(ffi_vec_u8_debug(
        addr deserPathIndex))
    ffi_vec_u8_free(deserPathIndex)
    ffi_vec_u8_free(serPathIndex)

  echo "\nHashing first signal"
  var signal1: array[32, uint8] = [1'u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
  var signal1Vec = Vec_uint8(dataPtr: addr signal1[0], len: csize_t(32),
      cap: csize_t(32))
  let x1 = ffi_hash_to_field_le(addr signal1Vec)
  echo "  - x1 = " & asString(ffi_cfr_debug(x1))

  echo "\nHashing epoch"
  let epochStr = "test-epoch"
  var epochBuf = strToBytes(epochStr)
  var epochVec = asVecU8(epochBuf)
  let epoch = ffi_hash_to_field_le(addr epochVec)
  echo "  - epoch = " & asString(ffi_cfr_debug(epoch))

  echo "\nHashing RLN identifier"
  let rlnIdStr = "test-rln-identifier"
  var rlnIdBuf = strToBytes(rlnIdStr)
  var rlnIdVec = asVecU8(rlnIdBuf)
  let rlnIdentifier = ffi_hash_to_field_le(addr rlnIdVec)
  echo "  - RLN identifier = " & asString(ffi_cfr_debug(rlnIdentifier))

  echo "\nComputing Poseidon hash for external nullifier"
  let externalNullifier = ffi_poseidon_hash_pair(epoch, rlnIdentifier)
  echo "  - external nullifier = " & asString(ffi_cfr_debug(externalNullifier))

  echo "\nCreating first message id"
  let messageId1 = ffi_uint_to_cfr(0'u32)
  echo "  - message id = " & asString(ffi_cfr_debug(messageId1))

  echo "\nCreating first RLN witness"
  when defined(ffiStateless):
    let witness1Result = ffi_rln_v3_witness_input_new_single(identitySecret,
        userMessageLimit, messageId1, addr pathElements,
        addr identityPathIndexVec, x1, externalNullifier)
  else:
    let witness1Result = ffi_rln_v3_witness_input_new_single(identitySecret,
        userMessageLimit, messageId1, addr merkleProof.path_elements,
        addr merkleProof.path_index, x1, externalNullifier)
  if witness1Result.ok.isNil:
    stderr.writeLine("First witness creation error: " & asString(
        witness1Result.err))
    ffi_c_string_free(witness1Result.err)
    return
  var witness1 = witness1Result.ok
  echo "  - first RLN witness created successfully"

  echo "\nRLNWitnessInput serialization: RLNWitnessInput <-> bytes"
  let serWitness1Result = ffi_rln_v3_witness_to_bytes_le(addr witness1)
  if serWitness1Result.err.dataPtr != nil:
    stderr.writeLine("Witness serialization error: " & asString(
        serWitness1Result.err))
    ffi_c_string_free(serWitness1Result.err)
    return
  var serWitness1 = serWitness1Result.ok
  echo "  - serialized witness = " & asString(ffi_vec_u8_debug(
      addr serWitness1))
  let deserWitness1Result = ffi_bytes_le_to_rln_v3_witness(addr serWitness1)
  if deserWitness1Result.ok.isNil:
    stderr.writeLine("Witness deserialization error: " & asString(
        deserWitness1Result.err))
    ffi_c_string_free(deserWitness1Result.err)
    return
  let deserWitness1 = deserWitness1Result.ok
  echo "  - witness deserialized successfully"
  ffi_rln_v3_witness_input_free(deserWitness1)
  ffi_vec_u8_free(serWitness1)

  echo "\nGenerating first RLN proof"
  let rlnProof1Result = ffi_rln_v3_generate_proof(addr rlnInstance, addr witness1)
  if rlnProof1Result.ok.isNil:
    stderr.writeLine("Proof generation error: " & asString(rlnProof1Result.err))
    ffi_c_string_free(rlnProof1Result.err)
    return
  var rlnProof1 = rlnProof1Result.ok
  echo "  - proof generated successfully"

  echo "\nGetting first RLN proof values"
  var proofValues1 = ffi_rln_v3_proof_get_values(addr rlnProof1)
  echo "  - proof values extracted successfully"
  let yResult = ffi_rln_v3_proof_values_get_y(addr proofValues1)
  if yResult.ok.isNil:
    stderr.writeLine("Get y error: " & asString(yResult.err))
    ffi_c_string_free(yResult.err)
    return
  echo "  - y = " & asString(ffi_cfr_debug(yResult.ok))
  ffi_cfr_free(yResult.ok)
  let nullifierResult = ffi_rln_v3_proof_values_get_nullifier(addr proofValues1)
  if nullifierResult.ok.isNil:
    stderr.writeLine("Get nullifier error: " & asString(nullifierResult.err))
    ffi_c_string_free(nullifierResult.err)
    return
  echo "  - nullifier = " & asString(ffi_cfr_debug(nullifierResult.ok))
  ffi_cfr_free(nullifierResult.ok)
  let proofValues1Root = ffi_rln_v3_proof_values_get_root(addr proofValues1)
  echo "  - root = " & asString(ffi_cfr_debug(proofValues1Root))
  ffi_cfr_free(proofValues1Root)
  let proofValues1X = ffi_rln_v3_proof_values_get_x(addr proofValues1)
  echo "  - x = " & asString(ffi_cfr_debug(proofValues1X))
  ffi_cfr_free(proofValues1X)
  let proofValues1ExternalNullifier = ffi_rln_v3_proof_values_get_external_nullifier(
      addr proofValues1)
  echo "  - external nullifier = " & asString(ffi_cfr_debug(proofValues1ExternalNullifier))
  ffi_cfr_free(proofValues1ExternalNullifier)

  echo "\nRLNProof serialization: RLNProof <-> bytes"
  let serProof1Result = ffi_rln_v3_proof_to_bytes_le(addr rlnProof1)
  if serProof1Result.err.dataPtr != nil:
    stderr.writeLine("Proof serialization error: " & asString(
        serProof1Result.err))
    ffi_c_string_free(serProof1Result.err)
    return
  var serProof1 = serProof1Result.ok
  echo "  - serialized proof = " & asString(ffi_vec_u8_debug(addr serProof1))
  let deserProof1Result = ffi_bytes_le_to_rln_v3_proof(addr serProof1)
  if deserProof1Result.ok.isNil:
    stderr.writeLine("Proof deserialization error: " & asString(
        deserProof1Result.err))
    ffi_c_string_free(deserProof1Result.err)
    return
  let deserProof1 = deserProof1Result.ok
  echo "  - proof deserialized successfully"
  ffi_rln_v3_proof_free(deserProof1)
  ffi_vec_u8_free(serProof1)

  echo "\nRLNProofValues serialization: RLNProofValues <-> bytes"
  let serProofValues1Result = ffi_rln_v3_proof_values_to_bytes_le(
      addr proofValues1)
  if serProofValues1Result.err.dataPtr != nil:
    stderr.writeLine("Proof values serialization error: " & asString(
        serProofValues1Result.err))
    ffi_c_string_free(serProofValues1Result.err)
    return
  var serProofValues1 = serProofValues1Result.ok
  echo "  - serialized proof values = " & asString(ffi_vec_u8_debug(
      addr serProofValues1))
  let deserProofValues1Result = ffi_bytes_le_to_rln_v3_proof_values(
      addr serProofValues1)
  if deserProofValues1Result.ok.isNil:
    stderr.writeLine("RLN proof values deserialization error: " & asString(
        deserProofValues1Result.err))
    ffi_c_string_free(deserProofValues1Result.err)
    return
  var deserProofValues1 = deserProofValues1Result.ok
  echo "  - proof values deserialized successfully"
  let deserProofValues1ExternalNullifier = ffi_rln_v3_proof_values_get_external_nullifier(
      addr deserProofValues1)
  echo "  - deserialized external nullifier = " & asString(ffi_cfr_debug(deserProofValues1ExternalNullifier))
  ffi_cfr_free(deserProofValues1ExternalNullifier)
  ffi_rln_v3_proof_values_free(deserProofValues1)
  ffi_vec_u8_free(serProofValues1)

  echo "\nVerifying first proof"
  when defined(ffiStateless):
    var roots = ffi_vec_cfr_new(csize_t(1))
    ffi_vec_cfr_push(addr roots, computedRoot)
    let verify1Result = ffi_rln_v3_verify_with_roots(addr rlnInstance,
        addr rlnProof1, addr roots, x1)
  else:
    let verify1Result = ffi_rln_v3_verify(addr rlnInstance, addr rlnProof1, x1)
  if verify1Result.err.dataPtr != nil:
    stderr.writeLine("Proof verification error: " & asString(verify1Result.err))
    ffi_c_string_free(verify1Result.err)
    return
  if verify1Result.ok:
    echo "  - first proof verified successfully"
  else:
    echo "First proof verification failed"
    return

  echo "\nSimulating double-signaling attack (same epoch, different message)"

  echo "\nHashing second signal"
  var signal2: array[32, uint8] = [11'u8, 12, 13, 14, 15, 16, 17, 18, 19, 20, 0,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
  var signal2Vec = Vec_uint8(dataPtr: addr signal2[0], len: csize_t(32),
      cap: csize_t(32))
  let x2 = ffi_hash_to_field_le(addr signal2Vec)
  echo "  - x2 = " & asString(ffi_cfr_debug(x2))

  echo "\nCreating second message with the same id"
  let messageId2 = ffi_uint_to_cfr(0'u32)
  echo "  - message id = " & asString(ffi_cfr_debug(messageId2))

  echo "\nCreating second RLN witness"
  when defined(ffiStateless):
    let witness2Result = ffi_rln_v3_witness_input_new_single(identitySecret,
        userMessageLimit, messageId2, addr pathElements,
        addr identityPathIndexVec, x2, externalNullifier)
  else:
    let witness2Result = ffi_rln_v3_witness_input_new_single(identitySecret,
        userMessageLimit, messageId2, addr merkleProof.path_elements,
        addr merkleProof.path_index, x2, externalNullifier)
  if witness2Result.ok.isNil:
    stderr.writeLine("Second witness creation error: " & asString(
        witness2Result.err))
    ffi_c_string_free(witness2Result.err)
    return
  var witness2 = witness2Result.ok
  echo "  - second RLN witness created successfully"

  echo "\nGenerating second RLN proof"
  let rlnProof2Result = ffi_rln_v3_generate_proof(addr rlnInstance, addr witness2)
  if rlnProof2Result.ok.isNil:
    stderr.writeLine("Second proof generation error: " & asString(
        rlnProof2Result.err))
    ffi_c_string_free(rlnProof2Result.err)
    return
  var rlnProof2 = rlnProof2Result.ok
  echo "  - second proof generated successfully"

  echo "\nGetting second RLN proof values"
  var proofValues2 = ffi_rln_v3_proof_get_values(addr rlnProof2)
  echo "  - second proof values extracted successfully"

  echo "\nVerifying second proof"
  when defined(ffiStateless):
    let verify2Result = ffi_rln_v3_verify_with_roots(addr rlnInstance,
        addr rlnProof2, addr roots, x2)
  else:
    let verify2Result = ffi_rln_v3_verify(addr rlnInstance, addr rlnProof2, x2)
  if verify2Result.err.dataPtr != nil:
    stderr.writeLine("Proof verification error: " & asString(verify2Result.err))
    ffi_c_string_free(verify2Result.err)
    return
  if verify2Result.ok:
    echo "  - second proof verified successfully"

    echo "\nRecovering identity secret"
    let recoverResult = ffi_rln_v3_recover_id_secret(addr proofValues1,
        addr proofValues2)
    if recoverResult.ok.isNil:
      stderr.writeLine("Identity recovery error: " & asString(
          recoverResult.err))
      ffi_c_string_free(recoverResult.err)
      return
    let recoveredSecret = recoverResult.ok
    echo "  - recovered secret = " & asString(ffi_cfr_debug(recoveredSecret))
    echo "  - identity secret = " & asString(ffi_cfr_debug(identitySecret))
    echo "  - identity recovered successfully"
    ffi_cfr_free(recoveredSecret)
  else:
    echo "Second proof verification failed"

  echo "\nCreating partial witness from first witness fields"
  let witness1IdentitySecret = ffi_rln_v3_witness_input_get_identity_secret(addr witness1)
  let witness1UserMessageLimit = ffi_rln_v3_witness_input_get_user_message_limit(addr witness1)
  var witness1PathElements = ffi_rln_v3_witness_input_get_path_elements(addr witness1)
  var witness1PathIndex = ffi_rln_v3_witness_input_get_identity_path_index(addr witness1)
  let partialWitnessResult = ffi_rln_v3_partial_witness_input_new(
      witness1IdentitySecret, witness1UserMessageLimit,
      addr witness1PathElements, addr witness1PathIndex)
  ffi_cfr_free(witness1IdentitySecret)
  ffi_cfr_free(witness1UserMessageLimit)
  ffi_vec_cfr_free(witness1PathElements)
  ffi_vec_u8_free(witness1PathIndex)
  if partialWitnessResult.ok.isNil:
    stderr.writeLine("Partial witness creation error: " & asString(
        partialWitnessResult.err))
    ffi_c_string_free(partialWitnessResult.err)
    return
  var partialWitness = partialWitnessResult.ok
  echo "  - partial witness created successfully"

  echo "\nRLNPartialWitnessInput serialization: RLNPartialWitnessInput <-> bytes"
  let serPartialWitnessResult = ffi_rln_v3_partial_witness_to_bytes_le(
      addr partialWitness)
  if serPartialWitnessResult.err.dataPtr != nil:
    stderr.writeLine("Partial witness serialization error: " & asString(
        serPartialWitnessResult.err))
    ffi_c_string_free(serPartialWitnessResult.err)
    return
  var serPartialWitness = serPartialWitnessResult.ok
  echo "  - serialized partial witness = " & asString(ffi_vec_u8_debug(
      addr serPartialWitness))
  let deserPartialWitnessResult = ffi_bytes_le_to_rln_v3_partial_witness(
      addr serPartialWitness)
  if deserPartialWitnessResult.ok.isNil:
    stderr.writeLine("Partial witness deserialization error: " & asString(
        deserPartialWitnessResult.err))
    ffi_c_string_free(deserPartialWitnessResult.err)
    return
  var deserPartialWitness = deserPartialWitnessResult.ok
  echo "  - partial witness deserialized successfully"

  echo "\nGenerating partial ZK proof"
  let partialProofResult = ffi_rln_v3_generate_partial_proof(addr rlnInstance,
      addr deserPartialWitness)
  if partialProofResult.ok.isNil:
    stderr.writeLine("Partial proof generation error: " & asString(
        partialProofResult.err))
    ffi_c_string_free(partialProofResult.err)
    return
  var partialProof = partialProofResult.ok
  echo "  - partial proof generated successfully"

  echo "\nRLNPartialProof serialization: RLNPartialProof <-> bytes"
  let serPartialProofResult = ffi_rln_v3_partial_proof_to_bytes_le(
      addr partialProof)
  if serPartialProofResult.err.dataPtr != nil:
    stderr.writeLine("Partial proof serialization error: " & asString(
        serPartialProofResult.err))
    ffi_c_string_free(serPartialProofResult.err)
    return
  var serPartialProof = serPartialProofResult.ok
  echo "  - serialized partial proof = " & asString(ffi_vec_u8_debug(
      addr serPartialProof))
  let deserPartialProofResult = ffi_bytes_le_to_rln_v3_partial_proof(
      addr serPartialProof)
  if deserPartialProofResult.ok.isNil:
    stderr.writeLine("Partial proof deserialization error: " & asString(
        deserPartialProofResult.err))
    ffi_c_string_free(deserPartialProofResult.err)
    return
  var deserPartialProof = deserPartialProofResult.ok
  echo "  - partial proof deserialized successfully"

  echo "\nFinishing proof with full witness"
  let fullProofResult = ffi_rln_v3_finish_proof(addr rlnInstance,
      addr deserPartialProof, addr witness1)
  if fullProofResult.ok.isNil:
    stderr.writeLine("Finish proof error: " & asString(fullProofResult.err))
    ffi_c_string_free(fullProofResult.err)
    return
  var fullProof = fullProofResult.ok
  echo "  - partial proof finished successfully"

  echo "\nVerifying full proof"
  when defined(ffiStateless):
    let verifyFullResult = ffi_rln_v3_verify_with_roots(addr rlnInstance,
        addr fullProof, addr roots, x1)
  else:
    let verifyFullResult = ffi_rln_v3_verify(addr rlnInstance, addr fullProof, x1)
  if verifyFullResult.err.dataPtr != nil:
    stderr.writeLine("Full proof verification error: " & asString(
        verifyFullResult.err))
    ffi_c_string_free(verifyFullResult.err)
    return
  if verifyFullResult.ok:
    echo "  - full proof verified successfully"
  else:
    echo "Full proof verification failed"

  ffi_rln_v3_proof_free(fullProof)
  ffi_rln_v3_partial_proof_free(deserPartialProof)
  ffi_vec_u8_free(serPartialProof)
  ffi_rln_v3_partial_proof_free(partialProof)
  ffi_rln_v3_partial_witness_input_free(deserPartialWitness)
  ffi_vec_u8_free(serPartialWitness)
  ffi_rln_v3_partial_witness_input_free(partialWitness)
  ffi_rln_v3_proof_values_free(proofValues2)
  ffi_rln_v3_proof_free(rlnProof2)
  ffi_rln_v3_witness_input_free(witness2)
  ffi_cfr_free(messageId2)
  ffi_rln_v3_proof_values_free(proofValues1)
  ffi_rln_v3_proof_free(rlnProof1)
  ffi_rln_v3_witness_input_free(witness1)
  ffi_cfr_free(messageId1)
  when defined(ffiStateless):
    ffi_vec_cfr_free(roots)
    ffi_cfr_free(computedRoot)
    ffi_vec_cfr_free(pathElements)
    for h in defaultHashes:
      ffi_cfr_free(h)
    ffi_cfr_free(defaultLeaf)
  else:
    ffi_rln_v3_merkle_proof_free(merkleProof)
  ffi_cfr_free(x2)
  ffi_cfr_free(x1)
  ffi_cfr_free(externalNullifier)
  ffi_cfr_free(rlnIdentifier)
  ffi_cfr_free(epoch)
  ffi_cfr_free(rateCommitment)
  ffi_cfr_free(userMessageLimit)
  ffi_vec_cfr_free(keys)
  ffi_rln_v3_free(rlnInstance)

main()
