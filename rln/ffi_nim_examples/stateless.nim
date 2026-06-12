include "common"

proc main() =
  var rlnInstance = initRLNStateless()
  if rlnInstance.isNil:
    return

  var member = createMember()

  echo "\nComputing Merkle path for stateless mode"
  let defaultLeaf = ffi_cfr_zero()
  var defaultHashes: array[treeDepth - 1, ptr CFr]
  defaultHashes[0] = ffi_poseidon_hash_pair(defaultLeaf, defaultLeaf)
  for i in 1 ..< treeDepth - 1:
    defaultHashes[i] = ffi_poseidon_hash_pair(defaultHashes[i - 1],
        defaultHashes[i - 1])
  var pathElements = ffi_vec_cfr_new(csize_t(treeDepth))
  ffi_vec_cfr_push(addr pathElements, defaultLeaf)
  for i in 1 ..< treeDepth:
    ffi_vec_cfr_push(addr pathElements, defaultHashes[i - 1])
  var pathIndexData: array[treeDepth, uint8]
  var pathIndex = Vec_uint8(dataPtr: addr pathIndexData[0],
      len: csize_t(treeDepth), cap: csize_t(treeDepth))

  echo "\nComputing Merkle root for stateless mode"
  echo "  - computing root for index 0 with rate commitment"
  var computedRoot = ffi_poseidon_hash_pair(member.rateCommitment, defaultLeaf)
  for i in 1 ..< treeDepth:
    let nextRoot = ffi_poseidon_hash_pair(computedRoot, defaultHashes[i - 1])
    ffi_cfr_free(computedRoot)
    computedRoot = nextRoot
  printCfr("computed root", computedRoot)
  var roots = ffi_vec_cfr_new(csize_t(1))
  ffi_vec_cfr_push(addr roots, computedRoot)

  let externalNullifier = computeExternalNullifier()

  echo "\nHashing signal"
  var signal: array[32, uint8] = [1'u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
  let x = hashSignal(signal)
  printCfr("x", x)

  echo "\nCreating message id"
  let messageId = ffi_uint_to_cfr(0'u32)
  printCfr("message id", messageId)

  echo "\nCreating RLN witness"
  let witnessResult = ffi_rln_witness_input_new_single(member.identitySecret,
      member.userMessageLimit, messageId, addr pathElements, addr pathIndex, x,
      externalNullifier)
  if witnessResult.ok.isNil:
    stderr.writeLine("Witness creation error: " & asString(witnessResult.err))
    ffi_c_string_free(witnessResult.err)
    return
  var witness = witnessResult.ok
  echo "  - RLN witness created successfully"

  echo "\nGenerating RLN proof"
  let rlnProofResult = ffi_rln_generate_proof(addr rlnInstance, addr witness)
  if rlnProofResult.ok.isNil:
    stderr.writeLine("Proof generation error: " & asString(rlnProofResult.err))
    ffi_c_string_free(rlnProofResult.err)
    return
  var rlnProof = rlnProofResult.ok
  echo "  - proof generated successfully"

  echo "\nGetting RLN proof values"
  var proofValues = ffi_rln_proof_get_values(addr rlnProof)
  let yResult = ffi_rln_proof_values_get_y(addr proofValues)
  if yResult.ok.isNil:
    stderr.writeLine("Get y error: " & asString(yResult.err))
    ffi_c_string_free(yResult.err)
    return
  printCfr("y", yResult.ok)
  ffi_cfr_free(yResult.ok)
  let nullifierResult = ffi_rln_proof_values_get_nullifier(addr proofValues)
  if nullifierResult.ok.isNil:
    stderr.writeLine("Get nullifier error: " & asString(nullifierResult.err))
    ffi_c_string_free(nullifierResult.err)
    return
  printCfr("nullifier", nullifierResult.ok)
  ffi_cfr_free(nullifierResult.ok)
  let proofValuesRoot = ffi_rln_proof_values_get_root(addr proofValues)
  printCfr("root", proofValuesRoot)
  ffi_cfr_free(proofValuesRoot)
  let proofValuesX = ffi_rln_proof_values_get_x(addr proofValues)
  printCfr("x", proofValuesX)
  ffi_cfr_free(proofValuesX)
  let proofValuesExternalNullifier =
    ffi_rln_proof_values_get_external_nullifier(addr proofValues)
  printCfr("external nullifier", proofValuesExternalNullifier)
  ffi_cfr_free(proofValuesExternalNullifier)

  echo "\nVerifying proof"
  let verifyResult = ffi_rln_verify_with_roots(addr rlnInstance,
      addr rlnProof, addr roots, x)
  if verifyResult.err.dataPtr != nil:
    stderr.writeLine("Proof verification error: " & asString(verifyResult.err))
    ffi_c_string_free(verifyResult.err)
    return
  if verifyResult.ok:
    echo "  - proof verified successfully"
  else:
    echo "Proof verification failed"
    return

  ffi_rln_proof_values_free(proofValues)
  ffi_rln_proof_free(rlnProof)
  ffi_rln_witness_input_free(witness)
  ffi_cfr_free(messageId)
  ffi_cfr_free(x)
  ffi_cfr_free(externalNullifier)
  ffi_vec_cfr_free(roots)
  ffi_cfr_free(computedRoot)
  ffi_vec_cfr_free(pathElements)
  for i in 0 ..< treeDepth - 1:
    ffi_cfr_free(defaultHashes[i])
  ffi_cfr_free(defaultLeaf)
  memberFree(member)
  ffi_rln_free(rlnInstance)

main()
