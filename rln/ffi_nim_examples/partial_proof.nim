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
  printFr("x", x)

  echo "\nCreating message id"
  let messageId = ffi_uint_to_fr(0'u32)
  printFr("message id", messageId)

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
  let witnessIdentitySecret = ffi_rln_witness_input_get_identity_secret(witness)
  let witnessUserMessageLimit = ffi_rln_witness_input_get_user_message_limit(witness)
  let witnessMerkleProof = ffi_rln_witness_input_get_merkle_proof(witness)
  let partialWitnessResult = ffi_rln_partial_witness_input_new(
      witnessIdentitySecret, witnessUserMessageLimit, witnessMerkleProof)
  ffi_secret_fr_free(witnessIdentitySecret)
  ffi_fr_free(witnessUserMessageLimit)
  ffi_rln_merkle_proof_free(witnessMerkleProof)
  if partialWitnessResult.ok.isNil:
    stderr.writeLine("Partial witness creation error: " & asString(
        partialWitnessResult.err))
    ffi_c_string_free(partialWitnessResult.err)
    return
  var partialWitness = partialWitnessResult.ok
  echo "  - partial witness created successfully"

  echo "\nGenerating partial ZK proof"
  let partialProofResult = ffi_rln_generate_partial_proof(rlnInstance,
      partialWitness)
  if partialProofResult.ok.isNil:
    stderr.writeLine("Partial proof generation error: " & asString(
        partialProofResult.err))
    ffi_c_string_free(partialProofResult.err)
    return
  var partialProof = partialProofResult.ok
  echo "  - partial proof generated successfully"

  echo "\nFinishing proof with full witness"
  let fullProofResult = ffi_rln_finish_proof(rlnInstance,
      partialProof, witness)
  if fullProofResult.ok.isNil:
    stderr.writeLine("Finish proof error: " & asString(fullProofResult.err))
    ffi_c_string_free(fullProofResult.err)
    return
  var fullProof = fullProofResult.ok
  echo "  - partial proof finished successfully"

  echo "\nVerifying full proof"
  let verifyFullResult = verifyStatefulProof(rlnInstance, fullProof, x)
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

  ffi_rln_proof_free(fullProof)
  ffi_rln_partial_proof_free(partialProof)
  ffi_rln_partial_witness_input_free(partialWitness)
  ffi_rln_witness_input_free(witness)
  ffi_fr_free(messageId)
  ffi_fr_free(x)
  ffi_fr_free(externalNullifier)
  ffi_rln_merkle_proof_free(merkleProof)
  memberFree(member)
  ffi_rln_free(rlnInstance)

main()
