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

type
  CSize* = csize_t
  CFr* = object
  FFI2_RLN* = object
  FFI2_RLNProof* = object

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

  FFI2_MerkleProof* = object
    path_elements*: Vec_CFr
    path_index*: Vec_uint8

  CResultBoolPtrVecU8* = object
    ok*: ptr bool
    err*: Vec_uint8

  CResultRLNPtrVecU8* = object
    ok*: ptr FFI2_RLN
    err*: Vec_uint8

  CResultProofPtrVecU8* = object
    ok*: ptr FFI2_RLNProof
    err*: Vec_uint8

  CResultCFrPtrVecU8* = object
    ok*: ptr CFr
    err*: Vec_uint8

  CResultMerkleProofPtrVecU8* = object
    ok*: ptr FFI2_MerkleProof
    err*: Vec_uint8

# Fr helpers
proc cfr_zero*(): ptr CFr {.importc: "cfr_zero", cdecl, dynlib: RLN_LIB.}
proc cfr_free*(x: ptr CFr) {.importc: "cfr_free", cdecl, dynlib: RLN_LIB.}
proc cfr_from_uint*(value: uint32): ptr CFr {.importc: "cfr_from_uint", cdecl,
    dynlib: RLN_LIB.}
proc cfr_debug*(cfr: ptr CFr): Vec_uint8 {.importc: "cfr_debug", cdecl,
    dynlib: RLN_LIB.}

# Vectors
proc vec_cfr_get*(v: ptr Vec_CFr, i: CSize): ptr CFr {.importc: "vec_cfr_get",
    cdecl, dynlib: RLN_LIB.}
proc vec_cfr_free*(v: Vec_CFr) {.importc: "vec_cfr_free", cdecl,
    dynlib: RLN_LIB.}

# Hashing
proc ffi2_hash*(input: SliceRefU8): ptr CFr {.importc: "ffi2_hash", cdecl,
    dynlib: RLN_LIB.}
proc ffi2_poseidon_hash*(inputs: ptr Vec_CFr): ptr CFr {.importc: "ffi2_poseidon_hash",
    cdecl, dynlib: RLN_LIB.}

# Keygen
proc ffi2_key_gen*(): Vec_CFr {.importc: "ffi2_key_gen", cdecl,
    dynlib: RLN_LIB.}

# RLN instance
when defined(ffiStateless):
  proc ffi2_new*(): CResultRLNPtrVecU8 {.importc: "ffi2_new", cdecl,
      dynlib: RLN_LIB.}
else:
  proc ffi2_new*(treeDepth: CSize, config: cstring): CResultRLNPtrVecU8 {.importc: "ffi2_new",
      cdecl, dynlib: RLN_LIB.}

proc ffi2_rln_free*(rln: ptr FFI2_RLN) {.importc: "ffi2_rln_free", cdecl,
    dynlib: RLN_LIB.}

# Proof generation/verification
when defined(ffiStateless):
  proc ffi2_generate_rln_proof_with_witness*(
    rln: ptr ptr FFI2_RLN,
    identity_secret: ptr CFr,
    user_message_limit: ptr CFr,
    message_id: ptr CFr,
    path_elements: ptr Vec_CFr,
    identity_path_index: ptr Vec_uint8,
    x: ptr CFr,
    external_nullifier: ptr CFr
  ): CResultProofPtrVecU8 {.importc: "ffi2_generate_rln_proof_with_witness",
      cdecl, dynlib: RLN_LIB.}
else:
  proc ffi2_generate_rln_proof*(
    rln: ptr ptr FFI2_RLN,
    identity_secret: ptr CFr,
    user_message_limit: ptr CFr,
    message_id: ptr CFr,
    x: ptr CFr,
    external_nullifier: ptr CFr,
    leaf_index: CSize
  ): CResultProofPtrVecU8 {.importc: "ffi2_generate_rln_proof", cdecl,
      dynlib: RLN_LIB.}

when defined(ffiStateless):
  proc ffi2_verify_with_roots*(
    rln: ptr ptr FFI2_RLN,
    proof: ptr ptr FFI2_RLNProof,
    roots: ptr Vec_CFr
  ): CResultBoolPtrVecU8 {.importc: "ffi2_verify_with_roots", cdecl,
      dynlib: RLN_LIB.}
else:
  proc ffi2_verify_rln_proof*(
    rln: ptr ptr FFI2_RLN,
    proof: ptr ptr FFI2_RLNProof
  ): CResultBoolPtrVecU8 {.importc: "ffi2_verify_rln_proof", cdecl,
      dynlib: RLN_LIB.}

proc ffi2_rln_proof_free*(p: ptr FFI2_RLNProof) {.importc: "ffi2_rln_proof_free",
    cdecl, dynlib: RLN_LIB.}

# Merkle tree operations (non-stateless mode)
when not defined(ffiStateless):
  proc ffi2_set_next_leaf*(rln: ptr ptr FFI2_RLN,
      value: ptr ptr CFr): CResultBoolPtrVecU8 {.importc: "ffi2_set_next_leaf",
      cdecl, dynlib: RLN_LIB.}
  proc ffi2_leaves_set*(rln: ptr ptr FFI2_RLN): CSize {.importc: "ffi2_leaves_set",
      cdecl, dynlib: RLN_LIB.}
  proc ffi2_get_proof*(rln: ptr ptr FFI2_RLN,
      index: CSize): CResultMerkleProofPtrVecU8 {.importc: "ffi2_get_proof",
      cdecl, dynlib: RLN_LIB.}
  proc ffi2_merkle_proof_free*(p: ptr FFI2_MerkleProof) {.importc: "ffi2_merkle_proof_free",
      cdecl, dynlib: RLN_LIB.}

# Secret recovery
proc ffi2_recover_id_secret*(proof1: ptr ptr FFI2_RLNProof,
    proof2: ptr ptr FFI2_RLNProof): CResultCFrPtrVecU8 {.importc: "ffi2_recover_id_secret",
    cdecl, dynlib: RLN_LIB.}

# Helpers
proc asSliceRef*(buf: var seq[uint8]): SliceRefU8 =
  result.dataPtr = if buf.len == 0: nil else: addr buf[0]
  result.len = CSize(buf.len)

proc asVecU8*(buf: var seq[uint8]): Vec_uint8 =
  result.dataPtr = if buf.len == 0: nil else: addr buf[0]
  result.len = CSize(buf.len)
  result.cap = CSize(buf.len)

proc asString*(v: Vec_uint8): string =
  if v.dataPtr.isNil or v.len == 0: return ""
  result = newString(v.len.int)
  copyMem(addr result[0], v.dataPtr, v.len.int)

proc cfrToString*(cfr: ptr CFr): string =
  let debugVec = cfr_debug(cfr)
  result = asString(debugVec)

proc poseidon_pair(a, b: ptr CFr): ptr CFr =
  const CFR_SIZE = 32
  var buffer = alloc(CFR_SIZE * 2)
  copyMem(buffer, a, CFR_SIZE)
  copyMem(cast[pointer](cast[int](buffer) + CFR_SIZE), b, CFR_SIZE)

  var vec: Vec_CFr
  vec.dataPtr = cast[ptr CFr](buffer)
  vec.len = CSize(2)
  vec.cap = CSize(2)
  result = ffi2_poseidon_hash(addr vec)

  dealloc(buffer)

when isMainModule:
  echo "Creating RLN instance"

  var rlnRes: CResultRLNPtrVecU8
  when defined(ffiStateless):
    rlnRes = ffi2_new()
  else:
    let config = """{
      "tree_config": {
        "path": "pmtree-123456",
        "temporary": false,
        "cache_capacity": 1073741824,
        "flush_every_ms": 500,
        "mode": "HighThroughput",
        "use_compression": false
      }
    }""".cstring
    rlnRes = ffi2_new(CSize(20), config)

  if rlnRes.ok.isNil:
    stderr.writeLine "ffi2_new error: ", asString(rlnRes.err)
    quit 1

  var rln = rlnRes.ok
  echo "RLN instance created successfully"

  echo "\nGenerating identity keys"
  var keys = ffi2_key_gen()
  let identitySecret = keys.dataPtr
  let idCommitment = vec_cfr_get(addr keys, CSize(1))
  echo "Identity generated"
  echo "  - identity_secret = ", cfrToString(identitySecret)
  echo "  - id_commitment = ", cfrToString(idCommitment)

  echo "\nCreating message limit"
  let userMessageLimit = cfr_from_uint(1'u32)
  echo "  - user_message_limit = ", cfrToString(userMessageLimit)

  echo "\nComputing rate commitment"
  let rateCommitment = poseidon_pair(idCommitment, userMessageLimit)
  echo "  - rate_commitment = ", cfrToString(rateCommitment)

  when defined(ffiStateless):
    const treeDepth = 20
    echo "\nBuilding Merkle path for stateless mode"

    let defaultLeaf = cfr_zero()
    var defaultHashes: array[treeDepth-1, ptr CFr]
    defaultHashes[0] = poseidon_pair(defaultLeaf, defaultLeaf)
    for i in 1..treeDepth-2:
      defaultHashes[i] = poseidon_pair(defaultHashes[i-1], defaultHashes[i-1])

    const CFR_SIZE = 32
    var pathElemsBuffer = alloc(CFR_SIZE * treeDepth)
    copyMem(pathElemsBuffer, defaultLeaf, CFR_SIZE)
    for i in 1..treeDepth-1:
      copyMem(cast[pointer](cast[int](pathElemsBuffer) + i * CFR_SIZE),
              defaultHashes[i-1], CFR_SIZE)

    var pathElements: Vec_CFr
    pathElements.dataPtr = cast[ptr CFr](pathElemsBuffer)
    pathElements.len = CSize(treeDepth)
    pathElements.cap = CSize(treeDepth)

    var pathIndexSeq = newSeq[uint8](treeDepth)
    var identityPathIndex = asVecU8(pathIndexSeq)

    echo "  - computing root for index 0 with rate_commitment"
    var computedRoot = poseidon_pair(rateCommitment, defaultLeaf)
    for i in 1..treeDepth-1:
      let next = poseidon_pair(computedRoot, defaultHashes[i-1])
      cfr_free(computedRoot)
      computedRoot = next
    echo "  - computed_root = ", cfrToString(computedRoot)
  else:
    echo "\nAdding rate_commitment to tree"
    var rcPtr = rateCommitment
    let setRes = ffi2_set_next_leaf(addr rln, addr rcPtr)
    if setRes.ok.isNil or not setRes.ok[]:
      stderr.writeLine "set_next_leaf error: ", asString(setRes.err)
      vec_cfr_free(keys)
      ffi2_rln_free(rln)
      quit 1

    let leafIndex = ffi2_leaves_set(addr rln) - 1
    echo "  - added to tree at index ", leafIndex

    echo "\nGetting Merkle proof"
    let proofResult = ffi2_get_proof(addr rln, leafIndex)
    if proofResult.ok.isNil:
      stderr.writeLine "get_proof error: ", asString(proofResult.err)
      vec_cfr_free(keys)
      ffi2_rln_free(rln)
      quit 1
    let merkleProof = proofResult.ok
    echo "  - proof obtained (depth: ", merkleProof.path_elements.len, ")"

  echo "\nHashing signal"
  var signal: array[32, uint8] = [1'u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
  var signalSlice = SliceRefU8(dataPtr: cast[ptr uint8](addr signal[0]),
      len: CSize(signal.len))
  let x = ffi2_hash(signalSlice)
  echo "  - x = ", cfrToString(x)

  echo "\nHashing epoch"
  let epochStr = "test-epoch"
  var epochBytes = newSeq[uint8](epochStr.len)
  for i in 0..<epochStr.len: epochBytes[i] = uint8(epochStr[i])
  var epochSlice = asSliceRef(epochBytes)
  let epoch = ffi2_hash(epochSlice)
  echo "  - epoch = ", cfrToString(epoch)

  echo "\nHashing RLN identifier"
  let rlnIdStr = "test-rln-identifier"
  var rlnIdBytes = newSeq[uint8](rlnIdStr.len)
  for i in 0..<rlnIdStr.len: rlnIdBytes[i] = uint8(rlnIdStr[i])
  let rlnIdentifier = ffi2_hash(asSliceRef(rlnIdBytes))
  echo "  - rln_identifier = ", cfrToString(rlnIdentifier)

  echo "\nComputing Poseidon hash for external nullifier"
  let externalNullifier = poseidon_pair(epoch, rlnIdentifier)
  echo "  - external_nullifier = ", cfrToString(externalNullifier)

  echo "\nCreating message_id"
  let messageId = cfr_from_uint(0'u32)
  echo "  - message_id = ", cfrToString(messageId)

  echo "\nGenerating RLN Proof"
  var proofRes: CResultProofPtrVecU8
  when defined(ffiStateless):
    proofRes = ffi2_generate_rln_proof_with_witness(
      addr rln, identitySecret, userMessageLimit, messageId,
      addr pathElements, addr identityPathIndex, x, externalNullifier)
  else:
    proofRes = ffi2_generate_rln_proof(
      addr rln, identitySecret, userMessageLimit, messageId,
      x, externalNullifier, leafIndex)

  if proofRes.ok.isNil:
    stderr.writeLine "Proof generation failed: ", asString(proofRes.err)
    quit 1

  var proof = proofRes.ok
  echo "Proof generated successfully"

  echo "\nVerifying Proof"
  when defined(ffiStateless):
    var roots: Vec_CFr
    roots.dataPtr = computedRoot
    roots.len = CSize(1)
    roots.cap = CSize(1)
    let verifyRes = ffi2_verify_with_roots(addr rln, addr proof, addr roots)
  else:
    let verifyRes = ffi2_verify_rln_proof(addr rln, addr proof)

  if verifyRes.ok.isNil:
    stderr.writeLine "Proof verification error: ", asString(verifyRes.err)
    quit 1
  elif verifyRes.ok[]:
    echo "Proof verified successfully"
  else:
    echo "Proof verification failed"
    quit 1

  echo "\nSimulating double-signaling attack (same epoch, different message)"

  echo "\nHashing second signal"
  var signal2: array[32, uint8] = [11'u8, 12, 13, 14, 15, 16, 17, 18, 19, 20, 0,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
  var signal2Slice = SliceRefU8(dataPtr: cast[ptr uint8](addr signal2[0]),
      len: CSize(signal2.len))
  let x2 = ffi2_hash(signal2Slice)
  echo "  - x2 = ", cfrToString(x2)

  echo "\nCreating second message with the same id"
  let messageId2 = cfr_from_uint(0'u32)
  echo "  - message_id2 = ", cfrToString(messageId2)

  echo "\nGenerating second RLN Proof"
  var proofRes2: CResultProofPtrVecU8
  when defined(ffiStateless):
    proofRes2 = ffi2_generate_rln_proof_with_witness(
      addr rln, identitySecret, userMessageLimit, messageId2,
      addr pathElements, addr identityPathIndex, x2, externalNullifier)
  else:
    proofRes2 = ffi2_generate_rln_proof(
      addr rln, identitySecret, userMessageLimit, messageId2,
      x2, externalNullifier, leafIndex)

  if proofRes2.ok.isNil:
    stderr.writeLine "Second proof generation failed: ", asString(proofRes2.err)
    quit 1

  var proof2 = proofRes2.ok
  echo "Second proof generated successfully"

  echo "\nVerifying second proof"
  when defined(ffiStateless):
    let verifyRes2 = ffi2_verify_with_roots(addr rln, addr proof2, addr roots)
  else:
    let verifyRes2 = ffi2_verify_rln_proof(addr rln, addr proof2)

  if verifyRes2.ok.isNil:
    stderr.writeLine "Second proof verification error: ", asString(verifyRes2.err)
    quit 1
  elif verifyRes2.ok[]:
    echo "Second proof verified successfully"

    echo "\nRecovering identity secret"
    let recoverRes = ffi2_recover_id_secret(addr proof, addr proof2)
    if recoverRes.ok.isNil:
      stderr.writeLine "Identity recovery error: ", asString(recoverRes.err)
      quit 1
    else:
      let recoveredSecret = recoverRes.ok
      echo "  - recovered_secret = ", cfrToString(recoveredSecret)
      echo "  - original_secret  = ", cfrToString(identitySecret)
      echo "\nSlashing successful: Identity is recovered!"
      cfr_free(recoveredSecret)
  else:
    echo "Second proof verification failed"
    quit 1

  ffi2_rln_proof_free(proof2)
  cfr_free(x2)
  cfr_free(messageId2)
  ffi2_rln_proof_free(proof)
  when defined(ffiStateless):
    cfr_free(computedRoot)
    cfr_free(defaultLeaf)
    for i in 0..treeDepth-2: cfr_free(defaultHashes[i])
    dealloc(pathElemsBuffer)
  else:
    ffi2_merkle_proof_free(merkleProof)
  cfr_free(rateCommitment)
  cfr_free(x)
  cfr_free(epoch)
  cfr_free(rlnIdentifier)
  cfr_free(externalNullifier)
  cfr_free(userMessageLimit)
  cfr_free(messageId)
  vec_cfr_free(keys)
  ffi2_rln_free(rln)
