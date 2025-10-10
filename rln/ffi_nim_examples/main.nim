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

  SliceBoxedU8* = object
    dataPtr*: ptr uint8
    len*: CSize

  FFI2_RLNWitnessInput* = object
    identity_secret*: ptr CFr
    user_message_limit*: ptr CFr
    message_id*: ptr CFr
    path_elements*: Vec_CFr
    identity_path_index*: SliceBoxedU8
    x*: ptr CFr
    external_nullifier*: ptr CFr

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

  FFI2_MerkleProof* = object
    path_elements*: Vec_CFr
    path_index*: Vec_uint8

  CResultMerkleProofPtrVecU8* = object
    ok*: ptr FFI2_MerkleProof
    err*: Vec_uint8


# Fr helpers
proc cfr_zero*(): ptr CFr {.importc: "cfr_zero", cdecl, dynlib: RLN_LIB.}
proc cfr_free*(x: ptr CFr) {.importc: "cfr_free", cdecl, dynlib: RLN_LIB.}
proc cfr_debug*(x: ptr CFr) {.importc: "cfr_debug", cdecl, dynlib: RLN_LIB.}
proc cfr_from_uint*(value: uint32): ptr CFr {.importc: "cfr_from_uint", cdecl,
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

# Helper: Poseidon(a, b) -> CFr* (only used in stateless mode)
when defined(ffiStateless):
  proc poseidon(a, b: ptr CFr): ptr CFr =
    var in2: array[2, ptr CFr]
    in2[0] = a
    in2[1] = b
    var v: Vec_CFr
    v.dataPtr = cast[ptr CFr](addr in2[0])
    v.len = CSize(2)
    v.cap = CSize(2)
    result = ffi2_poseidon_hash(addr v)

# RLN instance: default to non-stateless ABI.
# Use -d:ffiStateless only if the Rust lib was built with the stateless feature.
when defined(ffiStateless):
  proc ffi2_new*(): CResultRLNPtrVecU8 {.importc: "ffi2_new", cdecl,
      dynlib: RLN_LIB.}
  proc ffi2_new_with_params*(zkey: SliceRefU8,
      graph: SliceRefU8): CResultRLNPtrVecU8 {.importc: "ffi2_new_with_params",
      cdecl, dynlib: RLN_LIB.}
else:
  proc ffi2_new*(treeDepth: CSize, config: cstring): CResultRLNPtrVecU8 {.importc: "ffi2_new",
      cdecl, dynlib: RLN_LIB.}
  proc ffi2_new_with_params*(treeDepth: CSize, zkey: SliceRefU8,
      graph: SliceRefU8,
      config: cstring): CResultRLNPtrVecU8 {.importc: "ffi2_new_with_params",
      cdecl, dynlib: RLN_LIB.}

proc ffi2_rln_free*(rln: ptr FFI2_RLN) {.importc: "ffi2_rln_free", cdecl,
    dynlib: RLN_LIB.}

# Witness builder
proc ffi2_rln_witness_input_new*(
  identity_secret: ptr CFr,
  user_message_limit: ptr CFr,
  message_id: ptr CFr,
  path_elements: ptr Vec_CFr,
  identity_path_index: ptr Vec_uint8,
  x: ptr CFr,
  external_nullifier: ptr CFr
): ptr FFI2_RLNWitnessInput {.importc: "ffi2_rln_witness_input_new", cdecl,
    dynlib: RLN_LIB.}

proc ffi2_rln_witness_input_free*(w: ptr FFI2_RLNWitnessInput) {.importc: "ffi2_rln_witness_input_free",
    cdecl, dynlib: RLN_LIB.}

# ZK Proof generation / verification
proc ffi2_generate_rln_proof_with_witness*(rln: ptr ptr FFI2_RLN,
    witness: ptr ptr FFI2_RLNWitnessInput): CResultProofPtrVecU8 {.importc: "ffi2_generate_rln_proof_with_witness",
    cdecl, dynlib: RLN_LIB.}

when not defined(ffiStateless):
  proc ffi2_generate_rln_proof*(rln: ptr ptr FFI2_RLN,
      witness: ptr ptr FFI2_RLNWitnessInput): CResultProofPtrVecU8 {.importc: "ffi2_generate_rln_proof",
      cdecl, dynlib: RLN_LIB.}
  proc ffi2_verify_rln_proof*(rln: ptr ptr FFI2_RLN,
      proof: ptr ptr FFI2_RLNProof): CResultBoolPtrVecU8 {.importc: "ffi2_verify_rln_proof",
      cdecl, dynlib: RLN_LIB.}

proc ffi2_verify_with_roots*(rln: ptr ptr FFI2_RLN,
    proof: ptr ptr FFI2_RLNProof,
    roots: ptr Vec_CFr): CResultBoolPtrVecU8 {.importc: "ffi2_verify_with_roots",
    cdecl, dynlib: RLN_LIB.}
proc ffi2_rln_proof_free*(p: ptr FFI2_RLNProof) {.importc: "ffi2_rln_proof_free",
    cdecl, dynlib: RLN_LIB.}

# Merkle tree helpers (non-stateless only)
when not defined(ffiStateless):
  proc ffi2_set_next_leaf*(rln: ptr ptr FFI2_RLN,
      value: ptr ptr CFr): CResultBoolPtrVecU8 {.importc: "ffi2_set_next_leaf",
      cdecl, dynlib: RLN_LIB.}
  proc ffi2_get_proof*(rln: ptr ptr FFI2_RLN,
      index: CSize): CResultMerkleProofPtrVecU8 {.importc: "ffi2_get_proof",
      cdecl, dynlib: RLN_LIB.}
  proc ffi2_merkle_proof_free*(p: ptr FFI2_MerkleProof) {.importc: "ffi2_merkle_proof_free",
      cdecl, dynlib: RLN_LIB.}
  proc ffi2_get_root*(rln: ptr ptr FFI2_RLN): ptr CFr {.importc: "ffi2_get_root",
      cdecl, dynlib: RLN_LIB.}

# Utility to read a file fully into a buffer
proc readAllBytes*(p: string): seq[uint8] =
  let s = readFile(p)
  result = newSeq[uint8](s.len)
  for i in 0..<s.len:
    result[i] = uint8(s[i])

# Helper to make SliceRefU8
proc asSliceRef*(buf: var seq[uint8]): SliceRefU8 =
  result.dataPtr = if buf.len == 0: nil else: addr buf[0]
  result.len = CSize(buf.len)

# Build a Vec_uint8 from a seq[uint8] (identity_path_index)
proc asVecU8*(buf: var seq[uint8]): Vec_uint8 =
  result.dataPtr = if buf.len == 0: nil else: addr buf[0]
  result.len = CSize(buf.len)
  result.cap = CSize(buf.len)

# Minimal print helper for error messages handed back as Vec_uint8 (not guaranteed to be UTF-8)
proc asString*(v: Vec_uint8): string =
  if v.dataPtr.isNil or v.len == 0: return ""
  result = newString(v.len.int)
  copyMem(addr result[0], v.dataPtr, v.len.int)

when isMainModule:
  # 1) Create RLN instance
  var rlnRes: CResultRLNPtrVecU8
  when defined(ffiStateless):
    rlnRes = ffi2_new()
  else:
    let config = """
      {
        "tree_config": {
          "path": "pmtree-mock",
          "temporary": true,
          "cache_capacity": 134217728,
          "flush_every_ms": 500,
          "mode": "HighThroughput",
          "use_compression": false
        }
      }
      """.cstring
    rlnRes = ffi2_new(CSize(20), config)
  if rlnRes.ok.isNil:
    stderr.writeLine "ffi2_new error: ", asString(rlnRes.err)
    quit 1

  var rln = rlnRes.ok
  echo "RLN created"

  # 2) Generate identity keys
  var keys = ffi2_key_gen()
  let identitySecret = keys.dataPtr # element 0
  let idCommitment = vec_cfr_get(addr keys, CSize(1))             # element 1

  # 3) User message limit and message id
  let userMessageLimit = cfr_from_uint(1'u32)
  let messageId = cfr_from_uint(0'u32)

  # 4) Hash signal
  var signal: array[32, uint8]
  for i in 0..<signal.len: signal[i] = uint8(i + 1)
  var signalSlice: SliceRefU8
  signalSlice.dataPtr = cast[ptr uint8](addr signal[0])
  signalSlice.len = CSize(signal.len)
  let x = ffi2_hash(signalSlice)

  # External nullifier
  let enStr = "test-epoch|test-rln-id"
  var enBytes = newSeq[uint8](enStr.len)
  for i in 0..<enStr.len: enBytes[i] = uint8(enStr[i])
  let externalNullifier = ffi2_hash(asSliceRef(enBytes))

  # 5) Obtain Merkle path
  when defined(ffiStateless):
    # Compute rate commitment Poseidon(id_commitment, user_message_limit)
    let rateCommitment = poseidon(idCommitment, userMessageLimit)

    # Build a local default path for index 0 (depth=20)
    const treeDepth = 20
    let defaultLeaf = cfr_zero()

    # defaultHashes[0] = H(0,0); defaultHashes[i] = H(defaultHashes[i-1], defaultHashes[i-1])
    var defaultHashes: array[treeDepth-1, ptr CFr]
    defaultHashes[0] = poseidon(defaultLeaf, defaultLeaf)
    for i in 1..treeDepth-2:
      defaultHashes[i] = poseidon(defaultHashes[i-1], defaultHashes[i-1])

    # Path elements: sibling at each level for index 0 (level0=0; then defaultHashes)
    var pathElemsArr: array[treeDepth, ptr CFr]
    pathElemsArr[0] = defaultLeaf
    for i in 1..treeDepth-1:
      pathElemsArr[i] = defaultHashes[i-1]
    var pathElements: Vec_CFr
    pathElements.dataPtr = cast[ptr CFr](addr pathElemsArr[0])
    pathElements.len = CSize(treeDepth)
    pathElements.cap = CSize(treeDepth)

    # path index: all zeros (left at each level)
    var pathIndexSeq = newSeq[uint8](treeDepth)
    for i in 0..<treeDepth: pathIndexSeq[i] = 0'u8
    let pathIndexVec = asVecU8(pathIndexSeq)

    # Compute the root with leaf at index 0 set to rateCommitment
    var computedRoot = poseidon(rateCommitment, defaultLeaf)
    for i in 1..treeDepth-1:
      let nextCur = poseidon(computedRoot, defaultHashes[i-1])
      cfr_free(computedRoot)
      computedRoot = nextCur

    # Build witness
    var witness = ffi2_rln_witness_input_new(
      identitySecret,
      userMessageLimit,
      messageId,
      addr pathElements,
      addr pathIndexVec,
      x,
      externalNullifier
    )
    echo "Witness built"

    # Prove
    var rlnPtr = rln
    var witnessPtr = witness
    let proveRes = ffi2_generate_rln_proof_with_witness(addr rlnPtr,
        addr witnessPtr)
    if proveRes.ok.isNil:
      stderr.writeLine "prove error: ", asString(proveRes.err)
      ffi2_rln_witness_input_free(witness)
      cfr_free(computedRoot)
      cfr_free(defaultLeaf)
      for i in 0..treeDepth-2: cfr_free(defaultHashes[i])
      cfr_free(rateCommitment)
      cfr_free(externalNullifier)
      cfr_free(x)
      cfr_free(messageId)
      cfr_free(userMessageLimit)
      vec_cfr_free(keys)
      ffi2_rln_free(rln)
      quit 2

    let proof = proveRes.ok
    echo "Proof generated"

    # Verify with roots
    var roots: Vec_CFr
    roots.dataPtr = computedRoot
    roots.len = CSize(1)
    roots.cap = CSize(1)
    let verifyRes = ffi2_verify_with_roots(addr rlnPtr, addr proof, addr roots)
    if verifyRes.ok.isNil:
      stderr.writeLine "verify error: ", asString(verifyRes.err)
    else:
      echo "Verify: ", (if verifyRes.ok[]: "OK" else: "FAIL")

    # Cleanup
    ffi2_rln_proof_free(proof)
    ffi2_rln_witness_input_free(witness)
    cfr_free(computedRoot)
    cfr_free(defaultLeaf)
    for i in 0..treeDepth-2: cfr_free(defaultHashes[i])
    cfr_free(rateCommitment)
    cfr_free(externalNullifier)
    cfr_free(x)
    cfr_free(messageId)
    cfr_free(userMessageLimit)
    vec_cfr_free(keys)
    ffi2_rln_free(rln)
    quit 0
  else:
    # Compute rate commitment Poseidon(id_commitment, user_message_limit)
    var rcArr: array[2, ptr CFr]
    rcArr[0] = idCommitment
    rcArr[1] = userMessageLimit
    var rcInputs: Vec_CFr
    rcInputs.dataPtr = cast[ptr CFr](addr rcArr[0])
    rcInputs.len = CSize(2)
    rcInputs.cap = CSize(2)
    let rateCommitment = ffi2_poseidon_hash(addr rcInputs)

    # Add rate commitment to the tree at next index (0)
    var rlnPtr2 = rln
    var rcPtr = rateCommitment
    let setRes = ffi2_set_next_leaf(addr rlnPtr2, addr rcPtr)
    if setRes.ok.isNil or not setRes.ok[]:
      stderr.writeLine "set_next_leaf error: ", asString(setRes.err)
      cfr_free(rateCommitment)
      cfr_free(externalNullifier)
      cfr_free(x)
      cfr_free(messageId)
      cfr_free(userMessageLimit)
      vec_cfr_free(keys)
      ffi2_rln_free(rln)
      quit 4

    # Get Merkle proof for index 0
    let mpRes = ffi2_get_proof(addr rlnPtr2, CSize(0))
    if mpRes.ok.isNil:
      stderr.writeLine "get_proof error: ", asString(mpRes.err)
      cfr_free(rateCommitment)
      cfr_free(externalNullifier)
      cfr_free(x)
      cfr_free(messageId)
      cfr_free(userMessageLimit)
      vec_cfr_free(keys)
      ffi2_rln_free(rln)
      quit 5
    let merkleProof = mpRes.ok

    # Build witness
    var witness = ffi2_rln_witness_input_new(
      identitySecret,
      userMessageLimit,
      messageId,
      addr merkleProof.path_elements,
      addr merkleProof.path_index,
      x,
      externalNullifier
    )
    echo "Witness built"

    # 8) Prove
    var rlnPtr = rln
    var witnessPtr = witness
    let proveRes = ffi2_generate_rln_proof(addr rlnPtr, addr witnessPtr)
    if proveRes.ok.isNil:
      stderr.writeLine "prove error: ", asString(proveRes.err)
      if merkleProof != nil: ffi2_merkle_proof_free(merkleProof)
      if witness != nil: ffi2_rln_witness_input_free(witness)
      cfr_free(rateCommitment)
      cfr_free(externalNullifier)
      cfr_free(x)
      cfr_free(messageId)
      cfr_free(userMessageLimit)
      vec_cfr_free(keys)
      ffi2_rln_free(rln)
      quit 2

    let proof = proveRes.ok
    echo "Proof generated"

    # 9) Verify with roots (non-stateless)
    let verifyRes = ffi2_verify_rln_proof(addr rlnPtr, addr proof)
    if verifyRes.ok.isNil:
      stderr.writeLine "verify error: ", asString(verifyRes.err)
    else:
      echo "Verify: ", (if verifyRes.ok[]: "OK" else: "FAIL")

    # 10) Cleanup
    ffi2_rln_proof_free(proof)
    ffi2_rln_witness_input_free(witness)
    ffi2_merkle_proof_free(merkleProof)
    cfr_free(rateCommitment)
    cfr_free(externalNullifier)
    cfr_free(x)
    cfr_free(messageId)
    cfr_free(userMessageLimit)
    vec_cfr_free(keys)
    ffi2_rln_free(rln)
