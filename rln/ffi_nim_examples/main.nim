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
  FFI_RLN* = object
  FFI_RLNProof* = object
  FFI_RLNWitnessInput* = object

  Vec_CFr* = object
    dataPtr*: ptr CFr
    len*: CSize
    cap*: CSize

  Vec_uint8* = object
    dataPtr*: ptr uint8
    len*: CSize
    cap*: CSize

  SliceRefU8* = object
    dataPtr*: ptr uint8
    len*: CSize

  FFI_MerkleProof* = object
    path_elements*: Vec_CFr
    path_index*: Vec_uint8

  CResultRLNPtrVecU8* = object
    ok*: ptr FFI_RLN
    err*: Vec_uint8

  CResultProofPtrVecU8* = object
    ok*: ptr FFI_RLNProof
    err*: Vec_uint8

  CResultWitnessInputPtrVecU8* = object
    ok*: ptr FFI_RLNWitnessInput
    err*: Vec_uint8

  FFI_RLNProofValues* = object

  CResultCFrPtrVecU8* = object
    ok*: ptr CFr
    err*: Vec_uint8

  CResultRLNProofValuesPtrVecU8* = object
    ok*: ptr FFI_RLNProofValues
    err*: Vec_uint8

  CResultMerkleProofPtrVecU8* = object
    ok*: ptr FFI_MerkleProof
    err*: Vec_uint8

  CResultVecCFrVecU8* = object
    ok*: Vec_CFr
    err*: Vec_uint8

  CResultVecU8VecU8* = object
    ok*: Vec_uint8
    err*: Vec_uint8

  CResultBigIntJsonVecU8* = object
    ok*: Vec_uint8
    err*: Vec_uint8

  CBoolResult* = object
    ok*: bool
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
proc ffi_cfr_to_bytes_le*(cfr: ptr CFr): Vec_uint8 {.importc: "ffi_cfr_to_bytes_le",
    cdecl, dynlib: RLN_LIB.}
proc ffi_cfr_to_bytes_be*(cfr: ptr CFr): Vec_uint8 {.importc: "ffi_cfr_to_bytes_be",
    cdecl, dynlib: RLN_LIB.}
proc ffi_bytes_le_to_cfr*(bytes: ptr Vec_uint8): CResultCFrPtrVecU8 {.importc: "ffi_bytes_le_to_cfr",
    cdecl, dynlib: RLN_LIB.}
proc ffi_bytes_be_to_cfr*(bytes: ptr Vec_uint8): CResultCFrPtrVecU8 {.importc: "ffi_bytes_be_to_cfr",
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
proc ffi_vec_cfr_to_bytes_le*(v: ptr Vec_CFr): Vec_uint8 {.importc: "ffi_vec_cfr_to_bytes_le",
    cdecl, dynlib: RLN_LIB.}
proc ffi_vec_cfr_to_bytes_be*(v: ptr Vec_CFr): Vec_uint8 {.importc: "ffi_vec_cfr_to_bytes_be",
    cdecl, dynlib: RLN_LIB.}
proc ffi_bytes_le_to_vec_cfr*(bytes: ptr Vec_uint8): CResultVecCFrVecU8 {.importc: "ffi_bytes_le_to_vec_cfr",
    cdecl, dynlib: RLN_LIB.}
proc ffi_bytes_be_to_vec_cfr*(bytes: ptr Vec_uint8): CResultVecCFrVecU8 {.importc: "ffi_bytes_be_to_vec_cfr",
    cdecl, dynlib: RLN_LIB.}
proc ffi_vec_cfr_debug*(v: ptr Vec_CFr): Vec_uint8 {.importc: "ffi_vec_cfr_debug",
    cdecl, dynlib: RLN_LIB.}
proc ffi_vec_cfr_free*(v: Vec_CFr) {.importc: "ffi_vec_cfr_free", cdecl,
    dynlib: RLN_LIB.}

# Vec<u8> functions
proc ffi_vec_u8_to_bytes_le*(v: ptr Vec_uint8): Vec_uint8 {.importc: "ffi_vec_u8_to_bytes_le",
    cdecl, dynlib: RLN_LIB.}
proc ffi_vec_u8_to_bytes_be*(v: ptr Vec_uint8): Vec_uint8 {.importc: "ffi_vec_u8_to_bytes_be",
    cdecl, dynlib: RLN_LIB.}
proc ffi_bytes_le_to_vec_u8*(bytes: ptr Vec_uint8): CResultVecU8VecU8 {.importc: "ffi_bytes_le_to_vec_u8",
    cdecl, dynlib: RLN_LIB.}
proc ffi_bytes_be_to_vec_u8*(bytes: ptr Vec_uint8): CResultVecU8VecU8 {.importc: "ffi_bytes_be_to_vec_u8",
    cdecl, dynlib: RLN_LIB.}
proc ffi_vec_u8_debug*(v: ptr Vec_uint8): Vec_uint8 {.importc: "ffi_vec_u8_debug",
    cdecl, dynlib: RLN_LIB.}
proc ffi_vec_u8_free*(v: Vec_uint8) {.importc: "ffi_vec_u8_free", cdecl,
    dynlib: RLN_LIB.}

# Hashing functions
proc ffi_hash_to_field_le*(input: ptr Vec_uint8): CResultCFrPtrVecU8 {.importc: "ffi_hash_to_field_le",
    cdecl, dynlib: RLN_LIB.}
proc ffi_hash_to_field_be*(input: ptr Vec_uint8): CResultCFrPtrVecU8 {.importc: "ffi_hash_to_field_be",
    cdecl, dynlib: RLN_LIB.}
proc ffi_poseidon_hash_pair*(a: ptr CFr,
    b: ptr CFr): CResultCFrPtrVecU8 {.importc: "ffi_poseidon_hash_pair", cdecl,
    dynlib: RLN_LIB.}

# Keygen function
proc ffi_key_gen*(): CResultVecCFrVecU8 {.importc: "ffi_key_gen", cdecl,
    dynlib: RLN_LIB.}
proc ffi_seeded_key_gen*(seed: ptr Vec_uint8): CResultVecCFrVecU8 {.importc: "ffi_seeded_key_gen",
    cdecl, dynlib: RLN_LIB.}
proc ffi_extended_key_gen*(): CResultVecCFrVecU8 {.importc: "ffi_extended_key_gen",
    cdecl, dynlib: RLN_LIB.}
proc ffi_seeded_extended_key_gen*(seed: ptr Vec_uint8): CResultVecCFrVecU8 {.importc: "ffi_seeded_extended_key_gen",
    cdecl, dynlib: RLN_LIB.}

# RLN instance functions
when defined(ffiStateless):
  proc ffi_rln_new*(): CResultRLNPtrVecU8 {.importc: "ffi_rln_new", cdecl,
      dynlib: RLN_LIB.}
  proc ffi_rln_new_with_params*(zkey_data: ptr Vec_uint8,
      graph_data: ptr Vec_uint8): CResultRLNPtrVecU8 {.importc: "ffi_rln_new_with_params",
      cdecl, dynlib: RLN_LIB.}
else:
  proc ffi_rln_new*(treeDepth: CSize, config: cstring): CResultRLNPtrVecU8 {.importc: "ffi_rln_new",
      cdecl, dynlib: RLN_LIB.}
  proc ffi_rln_new_with_params*(treeDepth: CSize, zkey_data: ptr Vec_uint8,
      graph_data: ptr Vec_uint8, config: cstring): CResultRLNPtrVecU8 {.importc: "ffi_rln_new_with_params",
      cdecl, dynlib: RLN_LIB.}

proc ffi_rln_free*(rln: ptr FFI_RLN) {.importc: "ffi_rln_free", cdecl,
    dynlib: RLN_LIB.}

# Witness input functions
proc ffi_rln_witness_input_new*(
  identity_secret: ptr CFr,
  user_message_limit: ptr CFr,
  message_id: ptr CFr,
  path_elements: ptr Vec_CFr,
  identity_path_index: ptr Vec_uint8,
  x: ptr CFr,
  external_nullifier: ptr CFr
): CResultWitnessInputPtrVecU8 {.importc: "ffi_rln_witness_input_new", cdecl,
    dynlib: RLN_LIB.}
proc ffi_rln_witness_to_bytes_le*(witness: ptr ptr FFI_RLNWitnessInput): Vec_uint8 {.importc: "ffi_rln_witness_to_bytes_le",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_witness_to_bytes_be*(witness: ptr ptr FFI_RLNWitnessInput): Vec_uint8 {.importc: "ffi_rln_witness_to_bytes_be",
    cdecl, dynlib: RLN_LIB.}
proc ffi_bytes_le_to_rln_witness*(bytes: ptr Vec_uint8): CResultWitnessInputPtrVecU8 {.importc: "ffi_bytes_le_to_rln_witness",
    cdecl, dynlib: RLN_LIB.}
proc ffi_bytes_be_to_rln_witness*(bytes: ptr Vec_uint8): CResultWitnessInputPtrVecU8 {.importc: "ffi_bytes_be_to_rln_witness",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_witness_to_bigint_json*(witness: ptr ptr FFI_RLNWitnessInput): CResultBigIntJsonVecU8 {.importc: "ffi_rln_witness_to_bigint_json",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_witness_input_free*(witness: ptr FFI_RLNWitnessInput) {.importc: "ffi_rln_witness_input_free",
    cdecl, dynlib: RLN_LIB.}

# Proof generation/verification functions
proc ffi_generate_rln_proof*(
  rln: ptr ptr FFI_RLN,
  witness: ptr ptr FFI_RLNWitnessInput
): CResultProofPtrVecU8 {.importc: "ffi_generate_rln_proof", cdecl,
    dynlib: RLN_LIB.}

proc ffi_generate_rln_proof_with_witness*(
  rln: ptr ptr FFI_RLN,
  calculated_witness: ptr Vec_uint8,
  witness: ptr ptr FFI_RLNWitnessInput
): CResultProofPtrVecU8 {.importc: "ffi_generate_rln_proof_with_witness",
    cdecl, dynlib: RLN_LIB.}

when not defined(ffiStateless):
  proc ffi_verify_rln_proof*(
    rln: ptr ptr FFI_RLN,
    proof: ptr ptr FFI_RLNProof,
    x: ptr CFr
  ): CBoolResult {.importc: "ffi_verify_rln_proof", cdecl,
      dynlib: RLN_LIB.}

proc ffi_verify_with_roots*(
  rln: ptr ptr FFI_RLN,
  proof: ptr ptr FFI_RLNProof,
  roots: ptr Vec_CFr,
  x: ptr CFr
): CBoolResult {.importc: "ffi_verify_with_roots", cdecl,
    dynlib: RLN_LIB.}

proc ffi_rln_proof_free*(p: ptr FFI_RLNProof) {.importc: "ffi_rln_proof_free",
    cdecl, dynlib: RLN_LIB.}

# Merkle tree operations (non-stateless mode)
when not defined(ffiStateless):
  proc ffi_set_tree*(rln: ptr ptr FFI_RLN,
      tree_depth: CSize): CBoolResult {.importc: "ffi_set_tree",
      cdecl, dynlib: RLN_LIB.}
  proc ffi_delete_leaf*(rln: ptr ptr FFI_RLN,
      index: CSize): CBoolResult {.importc: "ffi_delete_leaf",
      cdecl, dynlib: RLN_LIB.}
  proc ffi_set_leaf*(rln: ptr ptr FFI_RLN, index: CSize,
      leaf: ptr CFr): CBoolResult {.importc: "ffi_set_leaf",
      cdecl, dynlib: RLN_LIB.}
  proc ffi_get_leaf*(rln: ptr ptr FFI_RLN,
      index: CSize): CResultCFrPtrVecU8 {.importc: "ffi_get_leaf",
      cdecl, dynlib: RLN_LIB.}
  proc ffi_set_next_leaf*(rln: ptr ptr FFI_RLN,
      leaf: ptr CFr): CBoolResult {.importc: "ffi_set_next_leaf",
      cdecl, dynlib: RLN_LIB.}
  proc ffi_set_leaves_from*(rln: ptr ptr FFI_RLN, index: CSize,
      leaves: ptr Vec_CFr): CBoolResult {.importc: "ffi_set_leaves_from",
      cdecl, dynlib: RLN_LIB.}
  proc ffi_init_tree_with_leaves*(rln: ptr ptr FFI_RLN,
      leaves: ptr Vec_CFr): CBoolResult {.importc: "ffi_init_tree_with_leaves",
      cdecl, dynlib: RLN_LIB.}
  proc ffi_atomic_operation*(rln: ptr ptr FFI_RLN, index: CSize,
      leaves: ptr Vec_CFr,
      indices: ptr Vec_uint8): CBoolResult {.importc: "ffi_atomic_operation",
      cdecl, dynlib: RLN_LIB.}
  proc ffi_seq_atomic_operation*(rln: ptr ptr FFI_RLN, leaves: ptr Vec_CFr,
      indices: ptr Vec_uint8): CBoolResult {.importc: "ffi_seq_atomic_operation",
      cdecl, dynlib: RLN_LIB.}
  proc ffi_get_root*(rln: ptr ptr FFI_RLN): ptr CFr {.importc: "ffi_get_root",
      cdecl, dynlib: RLN_LIB.}
  proc ffi_leaves_set*(rln: ptr ptr FFI_RLN): CSize {.importc: "ffi_leaves_set",
      cdecl, dynlib: RLN_LIB.}
  proc ffi_get_merkle_proof*(rln: ptr ptr FFI_RLN,
      index: CSize): CResultMerkleProofPtrVecU8 {.importc: "ffi_get_merkle_proof",
      cdecl, dynlib: RLN_LIB.}
  proc ffi_set_metadata*(rln: ptr ptr FFI_RLN,
      metadata: ptr Vec_uint8): CBoolResult {.importc: "ffi_set_metadata",
      cdecl, dynlib: RLN_LIB.}
  proc ffi_get_metadata*(rln: ptr ptr FFI_RLN): CResultVecU8VecU8 {.importc: "ffi_get_metadata",
      cdecl, dynlib: RLN_LIB.}
  proc ffi_flush*(rln: ptr ptr FFI_RLN): CBoolResult {.importc: "ffi_flush",
      cdecl, dynlib: RLN_LIB.}
  proc ffi_merkle_proof_free*(p: ptr FFI_MerkleProof) {.importc: "ffi_merkle_proof_free",
      cdecl, dynlib: RLN_LIB.}

# Identity secret recovery
proc ffi_recover_id_secret*(proof_values_1: ptr ptr FFI_RLNProofValues,
    proof_values_2: ptr ptr FFI_RLNProofValues): CResultCFrPtrVecU8 {.importc: "ffi_recover_id_secret",
    cdecl, dynlib: RLN_LIB.}

# RLNProof serialization
proc ffi_rln_proof_to_bytes_le*(proof: ptr ptr FFI_RLNProof): Vec_uint8 {.importc: "ffi_rln_proof_to_bytes_le",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_proof_to_bytes_be*(proof: ptr ptr FFI_RLNProof): Vec_uint8 {.importc: "ffi_rln_proof_to_bytes_be",
    cdecl, dynlib: RLN_LIB.}
proc ffi_bytes_le_to_rln_proof*(bytes: ptr Vec_uint8): CResultProofPtrVecU8 {.importc: "ffi_bytes_le_to_rln_proof",
    cdecl, dynlib: RLN_LIB.}
proc ffi_bytes_be_to_rln_proof*(bytes: ptr Vec_uint8): CResultProofPtrVecU8 {.importc: "ffi_bytes_be_to_rln_proof",
    cdecl, dynlib: RLN_LIB.}

# RLNProofValues functions
proc ffi_rln_proof_get_values*(proof: ptr ptr FFI_RLNProof): ptr FFI_RLNProofValues {.importc: "ffi_rln_proof_get_values",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_proof_values_get_y*(pv: ptr ptr FFI_RLNProofValues): ptr CFr {.importc: "ffi_rln_proof_values_get_y",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_proof_values_get_nullifier*(pv: ptr ptr FFI_RLNProofValues): ptr CFr {.importc: "ffi_rln_proof_values_get_nullifier",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_proof_values_get_root*(pv: ptr ptr FFI_RLNProofValues): ptr CFr {.importc: "ffi_rln_proof_values_get_root",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_proof_values_get_x*(pv: ptr ptr FFI_RLNProofValues): ptr CFr {.importc: "ffi_rln_proof_values_get_x",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_proof_values_get_external_nullifier*(pv: ptr ptr FFI_RLNProofValues): ptr CFr {.importc: "ffi_rln_proof_values_get_external_nullifier",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_proof_values_to_bytes_le*(pv: ptr ptr FFI_RLNProofValues): Vec_uint8 {.importc: "ffi_rln_proof_values_to_bytes_le",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_proof_values_to_bytes_be*(pv: ptr ptr FFI_RLNProofValues): Vec_uint8 {.importc: "ffi_rln_proof_values_to_bytes_be",
    cdecl, dynlib: RLN_LIB.}
proc ffi_bytes_le_to_rln_proof_values*(bytes: ptr Vec_uint8): CResultRLNProofValuesPtrVecU8 {.importc: "ffi_bytes_le_to_rln_proof_values",
    cdecl, dynlib: RLN_LIB.}
proc ffi_bytes_be_to_rln_proof_values*(bytes: ptr Vec_uint8): CResultRLNProofValuesPtrVecU8 {.importc: "ffi_bytes_be_to_rln_proof_values",
    cdecl, dynlib: RLN_LIB.}
proc ffi_rln_proof_values_free*(pv: ptr FFI_RLNProofValues) {.importc: "ffi_rln_proof_values_free",
    cdecl, dynlib: RLN_LIB.}

# Helpers functions
proc asVecU8*(buf: var seq[uint8]): Vec_uint8 =
  result.dataPtr = if buf.len == 0: nil else: addr buf[0]
  result.len = CSize(buf.len)
  result.cap = CSize(buf.len)

proc asString*(v: Vec_uint8): string =
  if v.dataPtr.isNil or v.len == 0: return ""
  result = newString(v.len.int)
  copyMem(addr result[0], v.dataPtr, v.len.int)

proc ffi_c_string_free*(s: Vec_uint8) {.importc: "ffi_c_string_free", cdecl,
    dynlib: RLN_LIB.}

when isMainModule:
  echo "Creating RLN instance"

  var rlnRes: CResultRLNPtrVecU8
  when defined(ffiStateless):
    rlnRes = ffi_rln_new()
  else:
    let config_path = """../resources/tree_depth_20/config.json""".cstring
    rlnRes = ffi_rln_new(CSize(20), config_path)

  if rlnRes.ok.isNil:
    stderr.writeLine "Initial RLN instance creation error: ", asString(rlnRes.err)
    ffi_c_string_free(rlnRes.err)
    quit 1

  var rln = rlnRes.ok
  echo "RLN instance created successfully"

  echo "\nGenerating identity keys"
  var keysResult = ffi_key_gen()
  if keysResult.err.dataPtr != nil:
    let errMsg = asString(keysResult.err)
    ffi_c_string_free(keysResult.err)
    echo "Key generation error: ", errMsg
    quit 1
  var keys = keysResult.ok
  let identitySecret = ffi_vec_cfr_get(addr keys, CSize(0))
  let idCommitment = ffi_vec_cfr_get(addr keys, CSize(1))
  echo "Identity generated"

  block:
    let debug = ffi_cfr_debug(identitySecret)
    echo "  - identity_secret = ", asString(debug)
    ffi_c_string_free(debug)

  block:
    let debug = ffi_cfr_debug(idCommitment)
    echo "  - id_commitment = ", asString(debug)
    ffi_c_string_free(debug)

  echo "\nCreating message limit"
  let userMessageLimit = ffi_uint_to_cfr(1'u32)

  block:
    let debug = ffi_cfr_debug(userMessageLimit)
    echo "  - user_message_limit = ", asString(debug)
    ffi_c_string_free(debug)

  echo "\nComputing rate commitment"
  let rateCommitmentResult = ffi_poseidon_hash_pair(idCommitment, userMessageLimit)
  if rateCommitmentResult.ok.isNil:
    let errMsg = asString(rateCommitmentResult.err)
    ffi_c_string_free(rateCommitmentResult.err)
    echo "Rate commitment hash error: ", errMsg
    quit 1
  let rateCommitment = rateCommitmentResult.ok

  block:
    let debug = ffi_cfr_debug(rateCommitment)
    echo "  - rate_commitment = ", asString(debug)
    ffi_c_string_free(debug)

  echo "\nCFr serialization: CFr <-> bytes"
  var serRateCommitment = ffi_cfr_to_bytes_be(rateCommitment)

  block:
    let debug = ffi_vec_u8_debug(addr serRateCommitment)
    echo "  - serialized rate_commitment = ", asString(debug)
    ffi_c_string_free(debug)

  let deserRateCommitmentResult = ffi_bytes_be_to_cfr(addr serRateCommitment)
  if deserRateCommitmentResult.ok.isNil:
    stderr.writeLine "Rate commitment deserialization error: ", asString(
        deserRateCommitmentResult.err)
    ffi_c_string_free(deserRateCommitmentResult.err)
    quit 1
  let deserRateCommitment = deserRateCommitmentResult.ok

  block:
    let debug = ffi_cfr_debug(deserRateCommitment)
    echo "  - deserialized rate_commitment = ", asString(debug)
    ffi_c_string_free(debug)

  ffi_vec_u8_free(serRateCommitment)
  ffi_cfr_free(deserRateCommitment)

  echo "\nVec<CFr> serialization: Vec<CFr> <-> bytes"
  var serKeys = ffi_vec_cfr_to_bytes_be(addr keys)

  block:
    let debug = ffi_vec_u8_debug(addr serKeys)
    echo "  - serialized keys = ", asString(debug)
    ffi_c_string_free(debug)

  let deserKeysResult = ffi_bytes_be_to_vec_cfr(addr serKeys)
  if deserKeysResult.err.dataPtr != nil:
    stderr.writeLine "Keys deserialization error: ", asString(
        deserKeysResult.err)
    ffi_c_string_free(deserKeysResult.err)
    quit 1

  block:
    var okKeys = deserKeysResult.ok
    let debug = ffi_vec_cfr_debug(addr okKeys)
    echo "  - deserialized identity_secret = ", asString(debug)
    ffi_c_string_free(debug)

  ffi_vec_cfr_free(deserKeysResult.ok)
  ffi_vec_u8_free(serKeys)

  when defined(ffiStateless):
    const treeDepth = 20
    const CFR_SIZE = 32

    echo "\nBuilding Merkle path for stateless mode"

    let defaultLeaf = ffi_cfr_zero()
    var defaultHashes: array[treeDepth-1, ptr CFr]
    block:
      let hashResult = ffi_poseidon_hash_pair(defaultLeaf, defaultLeaf)
      if hashResult.ok.isNil:
        let errMsg = asString(hashResult.err)
        ffi_c_string_free(hashResult.err)
        echo "Poseidon hash error: ", errMsg
        quit 1
      defaultHashes[0] = hashResult.ok
    for i in 1..treeDepth-2:
      let hashResult = ffi_poseidon_hash_pair(defaultHashes[i-1], defaultHashes[i-1])
      if hashResult.ok.isNil:
        let errMsg = asString(hashResult.err)
        ffi_c_string_free(hashResult.err)
        echo "Poseidon hash error: ", errMsg
        quit 1
      defaultHashes[i] = hashResult.ok

    var pathElements = ffi_vec_cfr_new(CSize(treeDepth))
    ffi_vec_cfr_push(addr pathElements, defaultLeaf)
    for i in 0..treeDepth-2:
      ffi_vec_cfr_push(addr pathElements, defaultHashes[i])

    echo "\nVec<CFr> serialization: Vec<CFr> <-> bytes"
    var serPathElements = ffi_vec_cfr_to_bytes_be(addr pathElements)

    block:
      let debug = ffi_vec_u8_debug(addr serPathElements)
      echo "  - serialized path_elements = ", asString(debug)
      ffi_c_string_free(debug)

    let deserPathElements = ffi_bytes_be_to_vec_cfr(addr serPathElements)
    if deserPathElements.err.dataPtr != nil:
      stderr.writeLine "Path elements deserialization error: ", asString(
          deserPathElements.err)
      ffi_c_string_free(deserPathElements.err)
      quit 1

    block:
      var okPathElems = deserPathElements.ok
      let debug = ffi_vec_cfr_debug(addr okPathElems)
      echo "  - deserialized path_elements = ", asString(debug)
      ffi_c_string_free(debug)

    ffi_vec_cfr_free(deserPathElements.ok)
    ffi_vec_u8_free(serPathElements)

    var pathIndexSeq = newSeq[uint8](treeDepth)
    var identityPathIndex = asVecU8(pathIndexSeq)

    echo "\nVec<uint8> serialization: Vec<uint8> <-> bytes"
    var serPathIndex = ffi_vec_u8_to_bytes_be(addr identityPathIndex)

    block:
      let debug = ffi_vec_u8_debug(addr serPathIndex)
      echo "  - serialized path_index = ", asString(debug)
      ffi_c_string_free(debug)

    let deserPathIndex = ffi_bytes_be_to_vec_u8(addr serPathIndex)
    if deserPathIndex.err.dataPtr != nil:
      stderr.writeLine "Path index deserialization error: ", asString(
          deserPathIndex.err)
      ffi_c_string_free(deserPathIndex.err)
      quit 1

    block:
      var okPathIdx = deserPathIndex.ok
      let debug = ffi_vec_u8_debug(addr okPathIdx)
      echo "  - deserialized path_index = ", asString(debug)
      ffi_c_string_free(debug)

    ffi_vec_u8_free(deserPathIndex.ok)
    ffi_vec_u8_free(serPathIndex)

    echo "\nComputing Merkle root for stateless mode"
    echo "  - computing root for index 0 with rate_commitment"
    let rootResult = ffi_poseidon_hash_pair(rateCommitment, defaultLeaf)
    if rootResult.ok.isNil:
      let errMsg = asString(rootResult.err)
      ffi_c_string_free(rootResult.err)
      echo "Poseidon hash error: ", errMsg
      quit 1
    var computedRoot = rootResult.ok
    for i in 1..treeDepth-1:
      let nextResult = ffi_poseidon_hash_pair(computedRoot, defaultHashes[i-1])
      if nextResult.ok.isNil:
        let errMsg = asString(nextResult.err)
        ffi_c_string_free(nextResult.err)
        echo "Poseidon hash error: ", errMsg
        quit 1
      let next = nextResult.ok
      ffi_cfr_free(computedRoot)
      computedRoot = next

    block:
      let debug = ffi_cfr_debug(computedRoot)
      echo "  - computed_root = ", asString(debug)
      ffi_c_string_free(debug)
  else:
    echo "\nAdding rate_commitment to tree"
    var rcPtr = rateCommitment
    let setErr = ffi_set_next_leaf(addr rln, rcPtr)
    if not setErr.ok:
      stderr.writeLine "Set next leaf error: ", asString(setErr.err)
      ffi_c_string_free(setErr.err)
      quit 1

    let leafIndex = ffi_leaves_set(addr rln) - 1
    echo "  - added to tree at index ", leafIndex

    echo "\nGetting Merkle proof"
    let proofResult = ffi_get_merkle_proof(addr rln, leafIndex)
    if proofResult.ok.isNil:
      stderr.writeLine "Get proof error: ", asString(proofResult.err)
      ffi_c_string_free(proofResult.err)
      quit 1
    let merkleProof = proofResult.ok
    echo "  - proof obtained (depth: ", merkleProof.path_elements.len, ")"

  echo "\nHashing signal"
  var signal: array[32, uint8] = [1'u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
  var signalVec = Vec_uint8(dataPtr: cast[ptr uint8](addr signal[0]),
      len: CSize(signal.len), cap: CSize(signal.len))
  let xResult = ffi_hash_to_field_be(addr signalVec)
  if xResult.ok.isNil:
    stderr.writeLine "Hash signal error: ", asString(xResult.err)
    ffi_c_string_free(xResult.err)
    quit 1
  let x = xResult.ok

  block:
    let debug = ffi_cfr_debug(x)
    echo "  - x = ", asString(debug)
    ffi_c_string_free(debug)

  echo "\nHashing epoch"
  let epochStr = "test-epoch"
  var epochBytes = newSeq[uint8](epochStr.len)
  for i in 0..<epochStr.len: epochBytes[i] = uint8(epochStr[i])
  var epochVec = asVecU8(epochBytes)
  let epochResult = ffi_hash_to_field_be(addr epochVec)
  if epochResult.ok.isNil:
    stderr.writeLine "Hash epoch error: ", asString(epochResult.err)
    ffi_c_string_free(epochResult.err)
    quit 1
  let epoch = epochResult.ok

  block:
    let debug = ffi_cfr_debug(epoch)
    echo "  - epoch = ", asString(debug)
    ffi_c_string_free(debug)

  echo "\nHashing RLN identifier"
  let rlnIdStr = "test-rln-identifier"
  var rlnIdBytes = newSeq[uint8](rlnIdStr.len)
  for i in 0..<rlnIdStr.len: rlnIdBytes[i] = uint8(rlnIdStr[i])
  var rlnIdVec = asVecU8(rlnIdBytes)
  let rlnIdentifierResult = ffi_hash_to_field_be(addr rlnIdVec)
  if rlnIdentifierResult.ok.isNil:
    stderr.writeLine "Hash RLN identifier error: ", asString(
        rlnIdentifierResult.err)
    ffi_c_string_free(rlnIdentifierResult.err)
    quit 1
  let rlnIdentifier = rlnIdentifierResult.ok

  block:
    let debug = ffi_cfr_debug(rlnIdentifier)
    echo "  - rln_identifier = ", asString(debug)
    ffi_c_string_free(debug)

  echo "\nComputing Poseidon hash for external nullifier"
  let externalNullifierResult = ffi_poseidon_hash_pair(epoch, rlnIdentifier)
  if externalNullifierResult.ok.isNil:
    let errMsg = asString(externalNullifierResult.err)
    ffi_c_string_free(externalNullifierResult.err)
    echo "External nullifier hash error: ", errMsg
    quit 1
  let externalNullifier = externalNullifierResult.ok

  block:
    let debug = ffi_cfr_debug(externalNullifier)
    echo "  - external_nullifier = ", asString(debug)
    ffi_c_string_free(debug)

  echo "\nCreating message_id"
  let messageId = ffi_uint_to_cfr(0'u32)

  block:
    let debug = ffi_cfr_debug(messageId)
    echo "  - message_id = ", asString(debug)
    ffi_c_string_free(debug)

  echo "\nCreating RLN Witness"
  when defined(ffiStateless):
    var witnessRes = ffi_rln_witness_input_new(identitySecret,
        userMessageLimit, messageId, addr pathElements, addr identityPathIndex,
        x, externalNullifier)
    if witnessRes.ok.isNil:
      stderr.writeLine "RLN Witness creation error: ", asString(witnessRes.err)
      ffi_c_string_free(witnessRes.err)
      quit 1
    var witness = witnessRes.ok
    echo "RLN Witness created successfully"
  else:
    var witnessRes = ffi_rln_witness_input_new(identitySecret,
        userMessageLimit, messageId, addr merkleProof.path_elements,
        addr merkleProof.path_index, x, externalNullifier)
    if witnessRes.ok.isNil:
      stderr.writeLine "RLN Witness creation error: ", asString(witnessRes.err)
      ffi_c_string_free(witnessRes.err)
      quit 1
    var witness = witnessRes.ok
    echo "RLN Witness created successfully"

  echo "\nRLNWitnessInput serialization: RLNWitnessInput <-> bytes"
  var serWitness = ffi_rln_witness_to_bytes_be(addr witness)

  block:
    let debug = ffi_vec_u8_debug(addr serWitness)
    echo "  - serialized witness = ", asString(debug)
    ffi_c_string_free(debug)

  let deserWitnessResult = ffi_bytes_be_to_rln_witness(addr serWitness)
  if deserWitnessResult.ok.isNil:
    stderr.writeLine "Witness deserialization error: ", asString(
        deserWitnessResult.err)
    ffi_c_string_free(deserWitnessResult.err)
    quit 1

  echo "  - witness deserialized successfully"
  ffi_rln_witness_input_free(deserWitnessResult.ok)
  ffi_vec_u8_free(serWitness)

  echo "\nGenerating RLN Proof"
  var proofRes = ffi_generate_rln_proof(addr rln, addr witness)

  if proofRes.ok.isNil:
    stderr.writeLine "Proof generation error: ", asString(proofRes.err)
    ffi_c_string_free(proofRes.err)
    quit 1

  var proof = proofRes.ok
  echo "Proof generated successfully"

  echo "\nGetting proof values"
  var proofValues = ffi_rln_proof_get_values(addr proof)

  block:
    let y = ffi_rln_proof_values_get_y(addr proofValues)
    let debug = ffi_cfr_debug(y)
    echo "  - y = ", asString(debug)
    ffi_c_string_free(debug)
    ffi_cfr_free(y)

  block:
    let nullifier = ffi_rln_proof_values_get_nullifier(addr proofValues)
    let debug = ffi_cfr_debug(nullifier)
    echo "  - nullifier = ", asString(debug)
    ffi_c_string_free(debug)
    ffi_cfr_free(nullifier)

  block:
    let root = ffi_rln_proof_values_get_root(addr proofValues)
    let debug = ffi_cfr_debug(root)
    echo "  - root = ", asString(debug)
    ffi_c_string_free(debug)
    ffi_cfr_free(root)

  block:
    let xVal = ffi_rln_proof_values_get_x(addr proofValues)
    let debug = ffi_cfr_debug(xVal)
    echo "  - x = ", asString(debug)
    ffi_c_string_free(debug)
    ffi_cfr_free(xVal)

  block:
    let extNullifier = ffi_rln_proof_values_get_external_nullifier(
        addr proofValues)
    let debug = ffi_cfr_debug(extNullifier)
    echo "  - external_nullifier = ", asString(debug)
    ffi_c_string_free(debug)
    ffi_cfr_free(extNullifier)

  echo "\nRLNProof serialization: RLNProof <-> bytes"
  var serProof = ffi_rln_proof_to_bytes_be(addr proof)

  block:
    let debug = ffi_vec_u8_debug(addr serProof)
    echo "  - serialized proof = ", asString(debug)
    ffi_c_string_free(debug)

  let deserProofResult = ffi_bytes_be_to_rln_proof(addr serProof)
  if deserProofResult.ok.isNil:
    stderr.writeLine "Proof deserialization error: ", asString(
        deserProofResult.err)
    ffi_c_string_free(deserProofResult.err)
    quit 1

  var deserProof = deserProofResult.ok
  echo "  - proof deserialized successfully"

  echo "\nRLNProofValues serialization: RLNProofValues <-> bytes"
  var serProofValues = ffi_rln_proof_values_to_bytes_be(addr proofValues)

  block:
    let debug = ffi_vec_u8_debug(addr serProofValues)
    echo "  - serialized proof_values = ", asString(debug)
    ffi_c_string_free(debug)

  let deserProofValuesResult = ffi_bytes_be_to_rln_proof_values(
      addr serProofValues)
  if deserProofValuesResult.ok.isNil:
    stderr.writeLine "Proof values deserialization error: ", asString(
        deserProofValuesResult.err)
    ffi_c_string_free(deserProofValuesResult.err)
    quit 1
  var deserProofValues = deserProofValuesResult.ok
  echo "  - proof_values deserialized successfully"

  block:
    let deserExternalNullifier = ffi_rln_proof_values_get_external_nullifier(
        addr deserProofValues)
    let debug = ffi_cfr_debug(deserExternalNullifier)
    echo "  - deserialized external_nullifier = ", asString(debug)
    ffi_c_string_free(debug)
    ffi_cfr_free(deserExternalNullifier)

  ffi_rln_proof_values_free(deserProofValues)
  ffi_vec_u8_free(serProofValues)
  ffi_rln_proof_free(deserProof)
  ffi_vec_u8_free(serProof)

  echo "\nVerifying Proof"
  when defined(ffiStateless):
    var roots = ffi_vec_cfr_from_cfr(computedRoot)
    let verifyErr = ffi_verify_with_roots(addr rln, addr proof, addr roots, x)
  else:
    let verifyErr = ffi_verify_rln_proof(addr rln, addr proof, x)

  if not verifyErr.ok:
    stderr.writeLine "Proof verification error: ", asString(verifyErr.err)
    ffi_c_string_free(verifyErr.err)
    quit 1

  echo "Proof verified successfully"

  ffi_rln_proof_free(proof)

  echo "\nSimulating double-signaling attack (same epoch, different message)"

  echo "\nHashing second signal"
  var signal2: array[32, uint8] = [11'u8, 12, 13, 14, 15, 16, 17, 18, 19, 20, 0,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
  var signal2Vec = Vec_uint8(dataPtr: cast[ptr uint8](addr signal2[0]),
      len: CSize(signal2.len), cap: CSize(signal2.len))
  let x2Result = ffi_hash_to_field_be(addr signal2Vec)
  if x2Result.ok.isNil:
    stderr.writeLine "Hash second signal error: ", asString(x2Result.err)
    ffi_c_string_free(x2Result.err)
    quit 1
  let x2 = x2Result.ok

  block:
    let debug = ffi_cfr_debug(x2)
    echo "  - x2 = ", asString(debug)
    ffi_c_string_free(debug)

  echo "\nCreating second message with the same id"
  let messageId2 = ffi_uint_to_cfr(0'u32)

  block:
    let debug = ffi_cfr_debug(messageId2)
    echo "  - message_id2 = ", asString(debug)
    ffi_c_string_free(debug)

  echo "\nCreating second RLN Witness"
  when defined(ffiStateless):
    var witnessRes2 = ffi_rln_witness_input_new(identitySecret,
        userMessageLimit, messageId2, addr pathElements, addr identityPathIndex,
        x2, externalNullifier)
    if witnessRes2.ok.isNil:
      stderr.writeLine "Second RLN Witness creation error: ", asString(
          witnessRes2.err)
      ffi_c_string_free(witnessRes2.err)
      quit 1
    var witness2 = witnessRes2.ok
    echo "Second RLN Witness created successfully"
  else:
    var witnessRes2 = ffi_rln_witness_input_new(identitySecret,
        userMessageLimit, messageId2, addr merkleProof.path_elements,
        addr merkleProof.path_index, x2, externalNullifier)
    if witnessRes2.ok.isNil:
      stderr.writeLine "Second RLN Witness creation error: ", asString(
          witnessRes2.err)
      ffi_c_string_free(witnessRes2.err)
      quit 1
    var witness2 = witnessRes2.ok
    echo "Second RLN Witness created successfully"

  echo "\nGenerating second RLN Proof"
  var proofRes2 = ffi_generate_rln_proof(addr rln, addr witness2)

  if proofRes2.ok.isNil:
    stderr.writeLine "Second proof generation error: ", asString(proofRes2.err)
    ffi_c_string_free(proofRes2.err)
    quit 1

  var proof2 = proofRes2.ok
  echo "Second proof generated successfully"

  var proofValues2 = ffi_rln_proof_get_values(addr proof2)

  echo "\nVerifying second proof"
  when defined(ffiStateless):
    let verifyErr2 = ffi_verify_with_roots(addr rln, addr proof2, addr roots, x2)
  else:
    let verifyErr2 = ffi_verify_rln_proof(addr rln, addr proof2, x2)

  if not verifyErr2.ok:
    stderr.writeLine "Proof verification error: ", asString(
        verifyErr2.err)
    ffi_c_string_free(verifyErr2.err)
    quit 1

  echo "Second proof verified successfully"

  echo "\nRecovering identity secret"
  let recoverRes = ffi_recover_id_secret(addr proofValues, addr proofValues2)
  if recoverRes.ok.isNil:
    stderr.writeLine "Identity recovery error: ", asString(recoverRes.err)
    ffi_c_string_free(recoverRes.err)
    quit 1

  let recoveredSecret = recoverRes.ok

  block:
    let debug = ffi_cfr_debug(recoveredSecret)
    echo "  - recovered_secret = ", asString(debug)
    ffi_c_string_free(debug)

  block:
    let debug = ffi_cfr_debug(identitySecret)
    echo "  - original_secret  = ", asString(debug)
    ffi_c_string_free(debug)

  echo "Slashing successful: Identity is recovered!"
  ffi_cfr_free(recoveredSecret)

  ffi_rln_proof_values_free(proofValues2)
  ffi_rln_proof_values_free(proofValues)
  ffi_rln_proof_free(proof2)
  ffi_cfr_free(x2)
  ffi_cfr_free(messageId2)

  when defined(ffiStateless):
    ffi_rln_witness_input_free(witness2)
    ffi_rln_witness_input_free(witness)
    ffi_vec_cfr_free(roots)
    ffi_vec_cfr_free(pathElements)
    for i in 0..treeDepth-2:
      ffi_cfr_free(defaultHashes[i])
    ffi_cfr_free(defaultLeaf)
    ffi_cfr_free(computedRoot)
  else:
    ffi_rln_witness_input_free(witness2)
    ffi_rln_witness_input_free(witness)
    ffi_merkle_proof_free(merkleProof)

  ffi_cfr_free(rateCommitment)
  ffi_cfr_free(x)
  ffi_cfr_free(epoch)
  ffi_cfr_free(rlnIdentifier)
  ffi_cfr_free(externalNullifier)
  ffi_cfr_free(userMessageLimit)
  ffi_cfr_free(messageId)
  ffi_vec_cfr_free(keys)
  ffi_rln_free(rln)
