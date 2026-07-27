include "common"

proc main() =
  var rlnInstance = initRLNStateless()
  if rlnInstance.isNil:
    return

  var member = createMember()

  echo "\nComputing Merkle path for stateless mode"
  let defaultLeaf = ffi_fr_zero()
  var defaultHashes: array[treeDepth - 1, ptr Fr]
  defaultHashes[0] = ffi_poseidon_hash_pair(defaultLeaf, defaultLeaf)
  for i in 1 ..< treeDepth - 1:
    defaultHashes[i] = ffi_poseidon_hash_pair(defaultHashes[i - 1],
        defaultHashes[i - 1])
  var pathElements = ffi_vec_fr_new(csize_t(treeDepth))
  ffi_vec_fr_push(addr pathElements, defaultLeaf)
  for i in 1 ..< treeDepth:
    ffi_vec_fr_push(addr pathElements, defaultHashes[i - 1])
  var pathIndexData: array[treeDepth, uint8]
  var pathIndex = Vec_uint8(dataPtr: addr pathIndexData[0],
      len: csize_t(treeDepth), cap: csize_t(treeDepth))

  echo "\nComputing Merkle root for stateless mode"
  echo "  - computing root for index 0 with rate commitment"
  var computedRoot = ffi_poseidon_hash_pair(member.rateCommitment, defaultLeaf)
  for i in 1 ..< treeDepth:
    let nextRoot = ffi_poseidon_hash_pair(computedRoot, defaultHashes[i - 1])
    ffi_fr_free(computedRoot)
    computedRoot = nextRoot
  printFr("computed root", computedRoot)
  var roots = ffi_vec_fr_new(csize_t(1))
  ffi_vec_fr_push(addr roots, computedRoot)

  let externalNullifier = computeExternalNullifier()

  echo "\nHashing signal"
  var signal: array[32, uint8] = [1'u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
  let x = hashSignal(signal)
  printFr("x", x)

  echo "\nCreating message id"
  let messageId = ffi_uint_to_fr(0'u32)
  printFr("message id", messageId)

  echo "\nCreating RLN witness"
  let merkleProof = ffi_rln_merkle_proof_new(addr pathElements, addr pathIndex)
  let witnessResult = ffi_rln_witness_input_new_single(member.identitySecret,
      member.userMessageLimit, messageId, merkleProof, x, externalNullifier)
  if witnessResult.ok.isNil:
    stderr.writeLine("Witness creation error: " & asString(witnessResult.err))
    ffi_c_string_free(witnessResult.err)
    return
  var witness = witnessResult.ok
  echo "  - RLN witness created successfully"

  echo "\nGenerating RLN proof"
  let rlnProofResult = ffi_rln_generate_proof(rlnInstance, witness)
  if rlnProofResult.ok.isNil:
    stderr.writeLine("Proof generation error: " & asString(rlnProofResult.err))
    ffi_c_string_free(rlnProofResult.err)
    return
  var rlnProof = rlnProofResult.ok
  echo "  - proof generated successfully"

  echo "\nGetting RLN proof values"
  var proofValues = ffi_rln_proof_get_values(rlnProof)
  let yResult = ffi_rln_proof_values_get_y(proofValues)
  if yResult.ok.isNil:
    stderr.writeLine("Get y error: " & asString(yResult.err))
    ffi_c_string_free(yResult.err)
    return
  printFr("y", yResult.ok)
  ffi_fr_free(yResult.ok)
  let nullifierResult = ffi_rln_proof_values_get_nullifier(proofValues)
  if nullifierResult.ok.isNil:
    stderr.writeLine("Get nullifier error: " & asString(nullifierResult.err))
    ffi_c_string_free(nullifierResult.err)
    return
  printFr("nullifier", nullifierResult.ok)
  ffi_fr_free(nullifierResult.ok)
  let proofValuesRoot = ffi_rln_proof_values_get_root(proofValues)
  printFr("root", proofValuesRoot)
  ffi_fr_free(proofValuesRoot)
  let proofValuesX = ffi_rln_proof_values_get_x(proofValues)
  printFr("x", proofValuesX)
  ffi_fr_free(proofValuesX)
  let proofValuesExternalNullifier =
    ffi_rln_proof_values_get_external_nullifier(proofValues)
  printFr("external nullifier", proofValuesExternalNullifier)
  ffi_fr_free(proofValuesExternalNullifier)

  echo "\nVerifying proof"
  let verifyResult = ffi_rln_verify_with_roots(rlnInstance,
      rlnProof, addr roots, x)
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
  ffi_rln_merkle_proof_free(merkleProof)
  ffi_fr_free(messageId)
  ffi_fr_free(x)
  ffi_fr_free(externalNullifier)
  ffi_vec_fr_free(roots)
  ffi_fr_free(computedRoot)
  ffi_vec_fr_free(pathElements)
  for i in 0 ..< treeDepth - 1:
    ffi_fr_free(defaultHashes[i])
  ffi_fr_free(defaultLeaf)
  memberFree(member)
  ffi_rln_free(rlnInstance)

main()
