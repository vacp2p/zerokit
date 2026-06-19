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

  echo "\nRLNWitnessInput serialization: RLNWitnessInput <-> bytes"
  let serWitnessResult = ffi_rln_witness_to_bytes_le(addr witness)
  if serWitnessResult.err.dataPtr != nil:
    stderr.writeLine("Witness serialization error: " & asString(
        serWitnessResult.err))
    ffi_c_string_free(serWitnessResult.err)
    return
  var serWitness = serWitnessResult.ok
  printVecU8("serialized witness", addr serWitness)
  let deserWitnessResult = ffi_bytes_le_to_rln_witness(addr serWitness)
  if deserWitnessResult.ok.isNil:
    stderr.writeLine("Witness deserialization error: " & asString(
        deserWitnessResult.err))
    ffi_c_string_free(deserWitnessResult.err)
    return
  var deserWitness = deserWitnessResult.ok
  echo "  - witness deserialized successfully"

  echo "\nGenerating RLN proof from the deserialized witness"
  let rlnProofResult = ffi_rln_generate_proof(addr rlnInstance,
      addr deserWitness)
  if rlnProofResult.ok.isNil:
    stderr.writeLine("Proof generation error: " & asString(rlnProofResult.err))
    ffi_c_string_free(rlnProofResult.err)
    return
  var rlnProof = rlnProofResult.ok
  echo "  - proof generated successfully"

  echo "\nRLNProof serialization: RLNProof <-> bytes"
  let serProofResult = ffi_rln_proof_to_bytes_le(addr rlnProof)
  if serProofResult.err.dataPtr != nil:
    stderr.writeLine("Proof serialization error: " & asString(
        serProofResult.err))
    ffi_c_string_free(serProofResult.err)
    return
  var serProof = serProofResult.ok
  printVecU8("serialized proof", addr serProof)
  let deserProofResult = ffi_bytes_le_to_rln_proof(addr serProof)
  if deserProofResult.ok.isNil:
    stderr.writeLine("Proof deserialization error: " & asString(
        deserProofResult.err))
    ffi_c_string_free(deserProofResult.err)
    return
  var deserProof = deserProofResult.ok
  echo "  - proof deserialized successfully"

  echo "\nVerifying the deserialized proof"
  let verifyResult = verifyStatefulProof(rlnInstance, deserProof, x)
  if verifyResult.err.dataPtr != nil:
    stderr.writeLine("Proof verification error: " & asString(verifyResult.err))
    ffi_c_string_free(verifyResult.err)
    return
  if verifyResult.ok:
    echo "  - deserialized proof verified successfully"
  else:
    echo "Deserialized proof verification failed"
    return

  ffi_rln_proof_free(deserProof)
  ffi_vec_u8_free(serProof)
  ffi_rln_proof_free(rlnProof)
  ffi_rln_witness_input_free(deserWitness)
  ffi_vec_u8_free(serWitness)
  ffi_rln_witness_input_free(witness)
  ffi_cfr_free(messageId)
  ffi_cfr_free(x)
  ffi_cfr_free(externalNullifier)
  ffi_rln_merkle_proof_free(merkleProof)
  memberFree(member)
  ffi_rln_free(rlnInstance)

main()
