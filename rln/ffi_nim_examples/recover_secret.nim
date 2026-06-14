include "common"

proc main() =
  var rlnInstance = initRLN(false)
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

  echo "\nCreating first message id"
  let messageId1 = ffi_uint_to_cfr(0'u32)
  printCfr("message id", messageId1)

  echo "\nCreating first RLN witness"
  let witness1Result = createWitness(member, merkleProof, messageId1, x1,
      externalNullifier)
  if witness1Result.ok.isNil:
    stderr.writeLine("First witness creation error: " & asString(
        witness1Result.err))
    ffi_c_string_free(witness1Result.err)
    return
  var witness1 = witness1Result.ok
  echo "  - first RLN witness created successfully"

  echo "\nGenerating first RLN proof"
  let rlnProof1Result = ffi_rln_generate_proof(addr rlnInstance, addr witness1)
  if rlnProof1Result.ok.isNil:
    stderr.writeLine("Proof generation error: " & asString(rlnProof1Result.err))
    ffi_c_string_free(rlnProof1Result.err)
    return
  var rlnProof1 = rlnProof1Result.ok
  var proofValues1 = ffi_rln_proof_get_values(addr rlnProof1)
  echo "  - first proof generated successfully"

  echo "\nVerifying first proof"
  let verify1Result = verifyStatefulProof(rlnInstance, rlnProof1, x1)
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

  echo "\nCreating second message with the same id"
  let messageId2 = ffi_uint_to_cfr(0'u32)
  printCfr("message id", messageId2)

  echo "\nCreating second RLN witness"
  let witness2Result = createWitness(member, merkleProof, messageId2, x2,
      externalNullifier)
  if witness2Result.ok.isNil:
    stderr.writeLine("Second witness creation error: " & asString(
        witness2Result.err))
    ffi_c_string_free(witness2Result.err)
    return
  var witness2 = witness2Result.ok
  echo "  - second RLN witness created successfully"

  echo "\nGenerating second RLN proof"
  let rlnProof2Result = ffi_rln_generate_proof(addr rlnInstance, addr witness2)
  if rlnProof2Result.ok.isNil:
    stderr.writeLine("Second proof generation error: " & asString(
        rlnProof2Result.err))
    ffi_c_string_free(rlnProof2Result.err)
    return
  var rlnProof2 = rlnProof2Result.ok
  var proofValues2 = ffi_rln_proof_get_values(addr rlnProof2)
  echo "  - second proof generated successfully"

  echo "\nVerifying second proof"
  let verify2Result = verifyStatefulProof(rlnInstance, rlnProof2, x2)
  if verify2Result.err.dataPtr != nil:
    stderr.writeLine("Proof verification error: " & asString(verify2Result.err))
    ffi_c_string_free(verify2Result.err)
    return
  if verify2Result.ok:
    echo "  - second proof verified successfully"

    echo "\nRecovering identity secret"
    let recoverResult = ffi_rln_recover_id_secret(addr proofValues1,
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

  ffi_rln_proof_values_free(proofValues2)
  ffi_rln_proof_free(rlnProof2)
  ffi_rln_witness_input_free(witness2)
  ffi_cfr_free(messageId2)
  ffi_cfr_free(x2)
  ffi_rln_proof_values_free(proofValues1)
  ffi_rln_proof_free(rlnProof1)
  ffi_rln_witness_input_free(witness1)
  ffi_cfr_free(messageId1)
  ffi_cfr_free(x1)
  ffi_cfr_free(externalNullifier)
  ffi_rln_merkle_proof_free(merkleProof)
  memberFree(member)
  ffi_rln_free(rlnInstance)

main()
