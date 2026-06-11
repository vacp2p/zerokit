include "rln"

const treeDepth = 20
const maxOut = 4

type Member = object
  keys: Vec_CFr
  identitySecret: ptr CFr
  idCommitment: ptr CFr
  userMessageLimit: ptr CFr
  rateCommitment: ptr CFr

proc printCfr(label: string, value: ptr CFr) =
  let debug = ffi_cfr_debug(value)
  echo "  - " & label & " = " & asString(debug)
  ffi_c_string_free(debug)

proc printVecCfr(label: string, value: ptr Vec_CFr) =
  let debug = ffi_vec_cfr_debug(value)
  echo "  - " & label & " = " & asString(debug)
  ffi_c_string_free(debug)

proc printVecU8(label: string, value: ptr Vec_uint8) =
  let debug = ffi_vec_u8_debug(value)
  echo "  - " & label & " = " & asString(debug)
  ffi_c_string_free(debug)

proc loadResources(enableMultiMessageId: bool): (seq[uint8], seq[uint8]) =
  let zkeyPath =
    if enableMultiMessageId:
      "../resources/tree_depth_20/multi_message_id/max_out_4/rln_final.arkzkey"
    else:
      "../resources/tree_depth_20/rln_final.arkzkey"
  let graphPath =
    if enableMultiMessageId:
      "../resources/tree_depth_20/multi_message_id/max_out_4/graph.bin"
    else:
      "../resources/tree_depth_20/graph.bin"
  (fileToBytes(zkeyPath), fileToBytes(graphPath))

proc initRLN(enableMultiMessageId: bool): ptr FFI_RLNV3 =
  echo "Creating RLN instance"
  var (zkeyBytes, graphBytes) = loadResources(enableMultiMessageId)
  var zkeyData = asVecU8(zkeyBytes)
  var graphData = asVecU8(graphBytes)
  let rlnInstanceResult = ffi_rln_v3_new_with_pm_tree(csize_t(treeDepth),
      addr zkeyData, addr graphData, "")
  if rlnInstanceResult.ok.isNil:
    stderr.writeLine("RLN instance creation error: " & asString(
        rlnInstanceResult.err))
    ffi_c_string_free(rlnInstanceResult.err)
    return nil
  echo "  - RLN instance created successfully"
  echo "  - circuit tree depth = " & $treeDepth
  if enableMultiMessageId:
    echo "  - circuit max out = " & $maxOut
  rlnInstanceResult.ok

proc initRLNStateless(): ptr FFI_RLNV3 =
  echo "Creating RLN instance"
  var (zkeyBytes, graphBytes) = loadResources(false)
  var zkeyData = asVecU8(zkeyBytes)
  var graphData = asVecU8(graphBytes)
  let rlnInstanceResult = ffi_rln_v3_new_stateless(addr zkeyData,
      addr graphData)
  if rlnInstanceResult.ok.isNil:
    stderr.writeLine("RLN instance creation error: " & asString(
        rlnInstanceResult.err))
    ffi_c_string_free(rlnInstanceResult.err)
    return nil
  echo "  - RLN instance created successfully"
  echo "  - circuit tree depth = " & $treeDepth
  rlnInstanceResult.ok

proc createMember(): Member =
  echo "\nGenerating identity keys"
  result.keys = ffi_key_gen()
  result.identitySecret = ffi_vec_cfr_get(addr result.keys, csize_t(0))
  result.idCommitment = ffi_vec_cfr_get(addr result.keys, csize_t(1))
  echo "  - identity generated successfully"
  printCfr("identity secret", result.identitySecret)
  printCfr("id commitment", result.idCommitment)

  echo "\nCreating message limit"
  result.userMessageLimit = ffi_uint_to_cfr(10'u32)
  printCfr("user message limit", result.userMessageLimit)

  echo "\nComputing rate commitment"
  result.rateCommitment = ffi_poseidon_hash_pair(result.idCommitment,
      result.userMessageLimit)
  printCfr("rate commitment", result.rateCommitment)

proc memberFree(member: var Member) =
  ffi_cfr_free(member.rateCommitment)
  ffi_cfr_free(member.userMessageLimit)
  ffi_vec_cfr_free(member.keys)

proc registerMember(rlnInstance: var ptr FFI_RLNV3,
    rateCommitment: ptr CFr): ptr FFI_RLNV3MerkleProof =
  echo "\nAdding rate commitment to tree"
  let setLeafResult = ffi_rln_v3_set_next_leaf(addr rlnInstance, rateCommitment)
  if not setLeafResult.ok:
    stderr.writeLine("Adding rate commitment error: " & asString(
        setLeafResult.err))
    ffi_c_string_free(setLeafResult.err)
    return nil
  echo "  - rate commitment added at leaf 0"

  echo "\nGetting Merkle proof"
  let merkleProofResult = ffi_rln_v3_get_merkle_proof(addr rlnInstance,
      csize_t(0))
  if merkleProofResult.ok.isNil:
    stderr.writeLine("Merkle proof error: " & asString(merkleProofResult.err))
    ffi_c_string_free(merkleProofResult.err)
    return nil
  echo "  - merkle proof obtained"
  merkleProofResult.ok

proc hashSignal(signal: var array[32, uint8]): ptr CFr =
  var signalVec = Vec_uint8(dataPtr: addr signal[0], len: csize_t(32),
      cap: csize_t(32))
  ffi_hash_to_field_le(addr signalVec)

proc computeExternalNullifier(): ptr CFr =
  echo "\nHashing epoch"
  let epochStr = "test-epoch"
  var epochBuf = strToBytes(epochStr)
  var epochVec = asVecU8(epochBuf)
  let epoch = ffi_hash_to_field_le(addr epochVec)
  printCfr("epoch", epoch)

  echo "\nHashing RLN identifier"
  let rlnIdStr = "test-rln-identifier"
  var rlnIdBuf = strToBytes(rlnIdStr)
  var rlnIdVec = asVecU8(rlnIdBuf)
  let rlnIdentifier = ffi_hash_to_field_le(addr rlnIdVec)
  printCfr("RLN identifier", rlnIdentifier)

  echo "\nComputing Poseidon hash for external nullifier"
  let externalNullifier = ffi_poseidon_hash_pair(epoch, rlnIdentifier)
  printCfr("external nullifier", externalNullifier)

  ffi_cfr_free(rlnIdentifier)
  ffi_cfr_free(epoch)
  externalNullifier

proc createWitness(member: Member,
    merkleProof: ptr FFI_RLNV3MerkleProof, messageId: ptr CFr, x: ptr CFr,
    externalNullifier: ptr CFr): CResultWitnessInputPtr =
  ffi_rln_v3_witness_input_new_single(member.identitySecret,
      member.userMessageLimit, messageId, addr merkleProof.path_elements,
      addr merkleProof.path_index, x, externalNullifier)
