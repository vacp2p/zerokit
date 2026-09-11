include "common"

proc main() =
  var rlnInstance = initRLNPoseidon2()
  if rlnInstance.isNil:
    return

  var member = createMemberPoseidon2()

  let merkleProof = registerMember(rlnInstance, member.rateCommitment)
  if merkleProof.isNil:
    return

  let externalNullifier = computeExternalNullifierPoseidon2()

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

  echo "\nGenerating RLN proof"
  let rlnProofResult = ffi_rln_generate_proof(rlnInstance, witness)
  if rlnProofResult.ok.isNil:
    stderr.writeLine("Proof generation error: " & asString(rlnProofResult.err))
    ffi_c_string_free(rlnProofResult.err)
    return
  var rlnProof = rlnProofResult.ok
  echo "  - proof generated successfully"

  echo "\nVerifying proof"
  let verifyResult = verifyStatefulProof(rlnInstance, rlnProof, x)
  if verifyResult.err.dataPtr != nil:
    stderr.writeLine("Proof verification error: " & asString(verifyResult.err))
    ffi_c_string_free(verifyResult.err)
    return
  if verifyResult.ok:
    echo "  - proof verified successfully"
  else:
    echo "Proof verification failed"
    return

  ffi_rln_proof_free(rlnProof)
  ffi_rln_witness_input_free(witness)
  ffi_fr_free(messageId)
  ffi_fr_free(x)
  ffi_fr_free(externalNullifier)
  ffi_rln_merkle_proof_free(merkleProof)
  memberFree(member)
  ffi_rln_free(rlnInstance)

main()
