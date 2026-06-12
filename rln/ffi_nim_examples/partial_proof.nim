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

  echo "\nHashing signal"
  var signal: array[32, uint8] = [1'u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
  let x = hashSignal(signal)
  printCfr("x", x)

  echo "\nCreating message id"
  let messageId = ffi_uint_to_cfr(0'u32)
  printCfr("message id", messageId)

  echo "\nCreating RLN witness"
  let witnessResult = createWitness(member, merkleProof, messageId, x,
      externalNullifier)
  if witnessResult.ok.isNil:
    stderr.writeLine("Witness creation error: " & asString(witnessResult.err))
    ffi_c_string_free(witnessResult.err)
    return
  var witness = witnessResult.ok
  echo "  - RLN witness created successfully"

  echo "\nCreating partial witness from witness fields"
  let witnessIdentitySecret = ffi_rln_v3_witness_input_get_identity_secret(addr witness)
  let witnessUserMessageLimit = ffi_rln_v3_witness_input_get_user_message_limit(addr witness)
  var witnessPathElements = ffi_rln_v3_witness_input_get_path_elements(addr witness)
  var witnessPathIndex = ffi_rln_v3_witness_input_get_identity_path_index(addr witness)
  let partialWitnessResult = ffi_rln_v3_partial_witness_input_new(
      witnessIdentitySecret, witnessUserMessageLimit, addr witnessPathElements,
      addr witnessPathIndex)
  ffi_cfr_free(witnessIdentitySecret)
  ffi_cfr_free(witnessUserMessageLimit)
  ffi_vec_cfr_free(witnessPathElements)
  ffi_vec_u8_free(witnessPathIndex)
  if partialWitnessResult.ok.isNil:
    stderr.writeLine("Partial witness creation error: " & asString(
        partialWitnessResult.err))
    ffi_c_string_free(partialWitnessResult.err)
    return
  var partialWitness = partialWitnessResult.ok
  echo "  - partial witness created successfully"

  echo "\nGenerating partial ZK proof"
  let partialProofResult = ffi_rln_v3_generate_partial_proof(addr rlnInstance,
      addr partialWitness)
  if partialProofResult.ok.isNil:
    stderr.writeLine("Partial proof generation error: " & asString(
        partialProofResult.err))
    ffi_c_string_free(partialProofResult.err)
    return
  var partialProof = partialProofResult.ok
  echo "  - partial proof generated successfully"

  echo "\nFinishing proof with full witness"
  let fullProofResult = ffi_rln_v3_finish_proof(addr rlnInstance,
      addr partialProof, addr witness)
  if fullProofResult.ok.isNil:
    stderr.writeLine("Finish proof error: " & asString(fullProofResult.err))
    ffi_c_string_free(fullProofResult.err)
    return
  var fullProof = fullProofResult.ok
  echo "  - partial proof finished successfully"

  echo "\nVerifying full proof"
  let verifyFullResult = ffi_rln_v3_verify(addr rlnInstance, addr fullProof, x)
  if verifyFullResult.err.dataPtr != nil:
    stderr.writeLine("Full proof verification error: " & asString(
        verifyFullResult.err))
    ffi_c_string_free(verifyFullResult.err)
    return
  if verifyFullResult.ok:
    echo "  - full proof verified successfully"
  else:
    echo "Full proof verification failed"
    return

  ffi_rln_v3_proof_free(fullProof)
  ffi_rln_v3_partial_proof_free(partialProof)
  ffi_rln_v3_partial_witness_input_free(partialWitness)
  ffi_rln_v3_witness_input_free(witness)
  ffi_cfr_free(messageId)
  ffi_cfr_free(x)
  ffi_cfr_free(externalNullifier)
  ffi_rln_v3_merkle_proof_free(merkleProof)
  memberFree(member)
  ffi_rln_v3_free(rlnInstance)

main()
