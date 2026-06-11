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
