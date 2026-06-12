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
  let verifyResult = ffi_rln_verify(addr rlnInstance, addr rlnProof, x)
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
  ffi_rln_merkle_proof_free(merkleProof)
  memberFree(member)
  ffi_rln_free(rlnInstance)

main()
