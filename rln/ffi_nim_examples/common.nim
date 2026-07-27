include "rln"

const treeDepth = 20
const maxOut = 4

type Member = object
  identitySecret: ptr SecretFr
  idCommitment: ptr Fr
  userMessageLimit: ptr Fr
  rateCommitment: ptr Fr

proc printFr(label: string, value: ptr Fr) =
  let debug = ffi_fr_debug(value)
  echo "  - " & label & " = " & asString(debug)
  ffi_c_string_free(debug)

proc printSecretFr(label: string, value: ptr SecretFr) =
  let debug = ffi_secret_fr_debug(value)
  echo "  - " & label & " = " & asString(debug)
  ffi_c_string_free(debug)

proc printVecFr(label: string, value: ptr Vec_Fr) =
  let debug = ffi_vec_fr_debug(value)
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

proc initRLN(enableMultiMessageId: bool): ptr RLN =
  echo "Creating RLN instance"
  var (zkeyBytes, graphBytes) = loadResources(enableMultiMessageId)
  var zkeyData = asVecU8(zkeyBytes)
  var graphData = asVecU8(graphBytes)
  let rlnInstanceResult = ffi_rln_new_with_pm_tree(csize_t(treeDepth),
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

proc initRLNStateless(): ptr RLN =
  echo "Creating RLN instance"
  var (zkeyBytes, graphBytes) = loadResources(false)
  var zkeyData = asVecU8(zkeyBytes)
  var graphData = asVecU8(graphBytes)
  let rlnInstanceResult = ffi_rln_new_stateless(addr zkeyData,
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
  let keys = ffi_identity_keys_generate()
  result.identitySecret = ffi_identity_keys_get_secret(keys)
  result.idCommitment = ffi_identity_keys_get_commitment(keys)
  ffi_identity_keys_free(keys)
  echo "  - identity generated successfully"
  printSecretFr("identity secret", result.identitySecret)
  printFr("id commitment", result.idCommitment)

  echo "\nCreating message limit"
  result.userMessageLimit = ffi_uint_to_fr(10'u32)
  printFr("user message limit", result.userMessageLimit)

  echo "\nComputing rate commitment"
  result.rateCommitment = ffi_poseidon_hash_pair(result.idCommitment,
      result.userMessageLimit)
  printFr("rate commitment", result.rateCommitment)

proc memberFree(member: var Member) =
  ffi_fr_free(member.rateCommitment)
  ffi_fr_free(member.userMessageLimit)
  ffi_secret_fr_free(member.identitySecret)
  ffi_fr_free(member.idCommitment)

proc registerMember(rlnInstance: var ptr RLN,
    rateCommitment: ptr Fr): ptr MerkleProof =
  echo "\nAdding rate commitment to tree"
  let setLeafResult = ffi_rln_set_next_leaf(rlnInstance, rateCommitment)
  if not setLeafResult.ok:
    stderr.writeLine("Adding rate commitment error: " & asString(
        setLeafResult.err))
    ffi_c_string_free(setLeafResult.err)
    return nil
  echo "  - rate commitment added at leaf 0"

  echo "\nGetting Merkle proof"
  let merkleProofResult = ffi_rln_get_merkle_proof(rlnInstance,
      csize_t(0))
  if merkleProofResult.ok.isNil:
    stderr.writeLine("Merkle proof error: " & asString(merkleProofResult.err))
    ffi_c_string_free(merkleProofResult.err)
    return nil
  echo "  - merkle proof obtained"
  merkleProofResult.ok

proc hashSignal(signal: var array[32, uint8]): ptr Fr =
  var signalVec = Vec_uint8(dataPtr: addr signal[0], len: csize_t(32),
      cap: csize_t(32))
  ffi_hash_to_field_le(addr signalVec)

proc computeExternalNullifier(): ptr Fr =
  echo "\nHashing epoch"
  let epochStr = "test-epoch"
  var epochBuf = strToBytes(epochStr)
  var epochVec = asVecU8(epochBuf)
  let epoch = ffi_hash_to_field_le(addr epochVec)
  printFr("epoch", epoch)

  echo "\nHashing RLN identifier"
  let rlnIdStr = "test-rln-identifier"
  var rlnIdBuf = strToBytes(rlnIdStr)
  var rlnIdVec = asVecU8(rlnIdBuf)
  let rlnIdentifier = ffi_hash_to_field_le(addr rlnIdVec)
  printFr("RLN identifier", rlnIdentifier)

  echo "\nComputing Poseidon hash for external nullifier"
  let externalNullifier = ffi_poseidon_hash_pair(epoch, rlnIdentifier)
  printFr("external nullifier", externalNullifier)

  ffi_fr_free(rlnIdentifier)
  ffi_fr_free(epoch)
  externalNullifier

proc createWitness(member: Member,
    merkleProof: ptr MerkleProof, messageId: ptr Fr, x: ptr Fr,
    externalNullifier: ptr Fr): WitnessResult =
  ffi_rln_witness_input_new_single(member.identitySecret,
      member.userMessageLimit, messageId, merkleProof, x, externalNullifier)

proc verifyStatefulProof(rlnInstance: var ptr RLN, rlnProof: var ptr Proof,
    x: ptr Fr): CBoolResult =
  let rootResult = ffi_rln_get_root(rlnInstance)
  if rootResult.ok == nil:
    return CBoolResult(ok: false, err: rootResult.err)
  let root = rootResult.ok
  var roots = ffi_vec_fr_from_fr(root)
  result = ffi_rln_verify_with_roots(rlnInstance, rlnProof,
      addr roots, x)
  ffi_vec_fr_free(roots)
  ffi_fr_free(root)
