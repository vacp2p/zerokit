include "common"

proc createMessageIds(ids: array[maxOut, uint32]): Vec_CFr =
  result = ffi_vec_cfr_new(csize_t(maxOut))
  for id in ids:
    let tmp = ffi_uint_to_cfr(id)
    ffi_vec_cfr_push(addr result, tmp)
    ffi_cfr_free(tmp)

proc createMultiWitness(member: Member,
    merkleProof: ptr FFI_RLNV3MerkleProof, messageIds: ptr Vec_CFr,
    selectorUsed: var array[maxOut, bool], x: ptr CFr,
    externalNullifier: ptr CFr): CResultWitnessInputPtr =
  var selectorVec = Vec_bool(dataPtr: addr selectorUsed[0],
      len: csize_t(maxOut), cap: csize_t(maxOut))
  ffi_rln_v3_witness_input_new_multi(member.identitySecret,
      member.userMessageLimit, messageIds, addr merkleProof.path_elements,
      addr merkleProof.path_index, x, externalNullifier, addr selectorVec)

proc main() =
  var rlnInstance = initRLN(true)
  if rlnInstance.isNil:
    return

  var member = createMember()

  let merkleProof = registerMember(rlnInstance, member.rateCommitment)
  if merkleProof.isNil:
    return

  let externalNullifier = computeExternalNullifier()

  echo "\nHashing first signal"
  var signal1: array[32, uint8] = [1'u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
  let x1 = hashSignal(signal1)
  printCfr("x1", x1)

  echo "\nCreating first message ids and selector used"
  echo "  - using 2 out of " & $maxOut & " slots"
  var messageIds1 = createMessageIds([0'u32, 1, 0, 0])
  var selectorUsed1 = [true, true, false, false]
  printVecCfr("message ids", addr messageIds1)

  echo "\nCreating first RLN witness"
  let witness1Result = createMultiWitness(member, merkleProof,
      addr messageIds1, selectorUsed1, x1, externalNullifier)
  if witness1Result.ok.isNil:
    stderr.writeLine("First witness creation error: " & asString(
        witness1Result.err))
    ffi_c_string_free(witness1Result.err)
    return
  var witness1 = witness1Result.ok
  echo "  - first RLN witness created successfully"

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
  let ys1Result = ffi_rln_v3_proof_values_get_ys(addr proofValues1)
  if ys1Result.err.dataPtr != nil:
    stderr.writeLine("Get ys error: " & asString(ys1Result.err))
    ffi_c_string_free(ys1Result.err)
    return
  var ys1 = ys1Result.ok
  printVecCfr("ys", addr ys1)
  ffi_vec_cfr_free(ys1)
  let nullifiers1Result = ffi_rln_v3_proof_values_get_nullifiers(addr proofValues1)
  if nullifiers1Result.err.dataPtr != nil:
    stderr.writeLine("Get nullifiers error: " & asString(nullifiers1Result.err))
    ffi_c_string_free(nullifiers1Result.err)
    return
  var nullifiers1 = nullifiers1Result.ok
  printVecCfr("nullifiers", addr nullifiers1)
  ffi_vec_cfr_free(nullifiers1)
  let proofValues1Root = ffi_rln_v3_proof_values_get_root(addr proofValues1)
  printCfr("root", proofValues1Root)
  ffi_cfr_free(proofValues1Root)
  let proofValues1X = ffi_rln_v3_proof_values_get_x(addr proofValues1)
  printCfr("x", proofValues1X)
  ffi_cfr_free(proofValues1X)
  let proofValues1ExternalNullifier =
    ffi_rln_v3_proof_values_get_external_nullifier(addr proofValues1)
  printCfr("external nullifier", proofValues1ExternalNullifier)
  ffi_cfr_free(proofValues1ExternalNullifier)

  echo "\nVerifying first proof"
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
  let x2 = hashSignal(signal2)
  printCfr("x2", x2)

  echo "\nCreating second message ids and selector used"
  echo "  - using 2 out of " & $maxOut & " slots"
  echo "  - duplicated slot id 1"
  var messageIds2 = createMessageIds([1'u32, 0, 3, 0])
  var selectorUsed2 = [true, false, true, false]
  printVecCfr("message ids", addr messageIds2)

  echo "\nCreating second RLN witness"
  let witness2Result = createMultiWitness(member, merkleProof,
      addr messageIds2, selectorUsed2, x2, externalNullifier)
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
  var proofValues2 = ffi_rln_v3_proof_get_values(addr rlnProof2)
  echo "  - second proof generated successfully"

  echo "\nVerifying second proof"
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
    printCfr("recovered secret", recoveredSecret)
    printCfr("identity secret", member.identitySecret)
    echo "  - identity recovered successfully"
    ffi_cfr_free(recoveredSecret)
  else:
    echo "Second proof verification failed"

  ffi_rln_v3_proof_values_free(proofValues2)
  ffi_rln_v3_proof_free(rlnProof2)
  ffi_rln_v3_witness_input_free(witness2)
  ffi_vec_cfr_free(messageIds2)
  ffi_cfr_free(x2)
  ffi_rln_v3_proof_values_free(proofValues1)
  ffi_rln_v3_proof_free(rlnProof1)
  ffi_rln_v3_witness_input_free(witness1)
  ffi_vec_cfr_free(messageIds1)
  ffi_cfr_free(x1)
  ffi_cfr_free(externalNullifier)
  ffi_rln_v3_merkle_proof_free(merkleProof)
  memberFree(member)
  ffi_rln_v3_free(rlnInstance)

main()
