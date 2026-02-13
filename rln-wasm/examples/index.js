import { readFileSync } from "fs";
import { fileURLToPath } from "url";
import { dirname, join } from "path";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const MULTI_MESSAGE_ID = false;

function debugUint8Array(uint8Array) {
  return Array.from(uint8Array, (byte) =>
    byte.toString(16).padStart(2, "0"),
  ).join(", ");
}

async function calculateWitness(circomPath, inputs, witnessCalculatorFile) {
  const wasmFile = readFileSync(circomPath);
  const wasmFileBuffer = wasmFile.buffer.slice(
    wasmFile.byteOffset,
    wasmFile.byteOffset + wasmFile.byteLength,
  );
  const witnessCalculator = await witnessCalculatorFile(wasmFileBuffer);
  const calculatedWitness = await witnessCalculator.calculateWitness(
    inputs,
    false,
  );
  return calculatedWitness;
}

async function main() {
  const rlnWasm = await import("../pkg/rln_wasm.js");
  const wasmPath = join(__dirname, "../pkg/rln_wasm_bg.wasm");
  const wasmBytes = readFileSync(wasmPath);
  rlnWasm.initSync({ module: wasmBytes });

  const zkeyPath = MULTI_MESSAGE_ID
    ? join(
        __dirname,
        "../../rln/resources/tree_depth_20/multi_message_id/rln_final.arkzkey",
      )
    : join(__dirname, "../../rln/resources/tree_depth_20/rln_final.arkzkey");

  const circomPath = MULTI_MESSAGE_ID
    ? join(
        __dirname,
        "../../rln/resources/tree_depth_20/multi_message_id/rln.wasm",
      )
    : join(__dirname, "../../rln/resources/tree_depth_20/rln.wasm");

  const witnessCalculatorPath = join(
    __dirname,
    "../resources/witness_calculator.js",
  );
  const { builder: witnessCalculatorFile } = await import(
    witnessCalculatorPath
  );

  console.log("Creating RLN instance");
  const zkeyData = readFileSync(zkeyPath);
  let rlnInstance;
  try {
    rlnInstance = new rlnWasm.WasmRLN(new Uint8Array(zkeyData));
  } catch (error) {
    console.error("Initial RLN instance creation error:", error);
    return;
  }
  console.log("RLN instance created successfully");

  console.log("\nGenerating identity keys");
  let identity;
  try {
    identity = rlnWasm.Identity.generate();
  } catch (error) {
    console.error("Key generation error:", error);
    return;
  }
  const identitySecret = identity.getSecretHash();
  const idCommitment = identity.getCommitment();
  console.log("Identity generated");
  console.log("  - identity_secret = " + identitySecret.debug());
  console.log("  - id_commitment = " + idCommitment.debug());

  console.log("\nCreating message limit");
  const userMessageLimit = rlnWasm.WasmFr.fromUint(10);
  console.log("  - user_message_limit = " + userMessageLimit.debug());

  console.log("\nComputing rate commitment");
  let rateCommitment;
  try {
    rateCommitment = rlnWasm.Hasher.poseidonHashPair(
      idCommitment,
      userMessageLimit,
    );
  } catch (error) {
    console.error("Rate commitment hash error:", error);
    return;
  }
  console.log("  - rate_commitment = " + rateCommitment.debug());

  console.log("\nWasmFr serialization: WasmFr <-> bytes");
  const serRateCommitment = rateCommitment.toBytesLE();
  console.log(
    "  - serialized rate_commitment = [" +
      debugUint8Array(serRateCommitment) +
      "]",
  );

  let deserRateCommitment;
  try {
    deserRateCommitment = rlnWasm.WasmFr.fromBytesLE(serRateCommitment);
  } catch (error) {
    console.error("Rate commitment deserialization error:", error);
    return;
  }
  console.log(
    "  - deserialized rate_commitment = " + deserRateCommitment.debug(),
  );

  console.log("\nIdentity serialization: Identity <-> bytes");
  const serIdentity = identity.toBytesLE();
  console.log(
    "  - serialized identity = [" + debugUint8Array(serIdentity) + "]",
  );

  let deserIdentity;
  try {
    deserIdentity = rlnWasm.Identity.fromBytesLE(serIdentity);
  } catch (error) {
    console.error("Identity deserialization error:", error);
    return;
  }
  const deserIdentitySecret = deserIdentity.getSecretHash();
  const deserIdCommitment = deserIdentity.getCommitment();
  console.log(
    "  - deserialized identity = [" +
      deserIdentitySecret.debug() +
      ", " +
      deserIdCommitment.debug() +
      "]",
  );

  console.log("\nBuilding Merkle path for stateless mode");
  const treeDepth = 20;
  const defaultLeaf = rlnWasm.WasmFr.zero();

  const defaultHashes = [];
  try {
    defaultHashes[0] = rlnWasm.Hasher.poseidonHashPair(
      defaultLeaf,
      defaultLeaf,
    );
    for (let i = 1; i < treeDepth - 1; i++) {
      defaultHashes[i] = rlnWasm.Hasher.poseidonHashPair(
        defaultHashes[i - 1],
        defaultHashes[i - 1],
      );
    }
  } catch (error) {
    console.error("Poseidon hash error:", error);
    return;
  }

  const pathElements = new rlnWasm.VecWasmFr();
  pathElements.push(defaultLeaf);
  for (let i = 1; i < treeDepth; i++) {
    pathElements.push(defaultHashes[i - 1]);
  }
  const identityPathIndex = new Uint8Array(treeDepth);

  console.log("\nVecWasmFr serialization: VecWasmFr <-> bytes");
  const serPathElements = pathElements.toBytesLE();
  console.log(
    "  - serialized path_elements = [" + debugUint8Array(serPathElements) + "]",
  );

  let deserPathElements;
  try {
    deserPathElements = rlnWasm.VecWasmFr.fromBytesLE(serPathElements);
  } catch (error) {
    console.error("Path elements deserialization error:", error);
    return;
  }
  console.log("  - deserialized path_elements = ", deserPathElements.debug());

  console.log("\nUint8Array serialization: Uint8Array <-> bytes");
  const serPathIndex = rlnWasm.Uint8ArrayUtils.toBytesLE(identityPathIndex);
  console.log(
    "  - serialized path_index = [" + debugUint8Array(serPathIndex) + "]",
  );

  let deserPathIndex;
  try {
    deserPathIndex = rlnWasm.Uint8ArrayUtils.fromBytesLE(serPathIndex);
  } catch (error) {
    console.error("Path index deserialization error:", error);
    return;
  }
  console.log("  - deserialized path_index =", deserPathIndex);

  console.log("\nComputing Merkle root for stateless mode");
  console.log("  - computing root for index 0 with rate_commitment");

  let computedRoot;
  try {
    computedRoot = rlnWasm.Hasher.poseidonHashPair(rateCommitment, defaultLeaf);
    for (let i = 1; i < treeDepth; i++) {
      computedRoot = rlnWasm.Hasher.poseidonHashPair(
        computedRoot,
        defaultHashes[i - 1],
      );
    }
  } catch (error) {
    console.error("Poseidon hash error:", error);
    return;
  }
  console.log("  - computed_root = " + computedRoot.debug());

  console.log("\nHashing signal");
  const signal = new Uint8Array([
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0,
  ]);
  let x;
  try {
    x = rlnWasm.Hasher.hashToFieldLE(signal);
  } catch (error) {
    console.error("Hash signal error:", error);
    return;
  }
  console.log("  - x = " + x.debug());

  console.log("\nHashing epoch");
  const epochStr = "test-epoch";
  let epoch;
  try {
    epoch = rlnWasm.Hasher.hashToFieldLE(new TextEncoder().encode(epochStr));
  } catch (error) {
    console.error("Hash epoch error:", error);
    return;
  }
  console.log("  - epoch = " + epoch.debug());

  console.log("\nHashing RLN identifier");
  const rlnIdStr = "test-rln-identifier";
  let rlnIdentifier;
  try {
    rlnIdentifier = rlnWasm.Hasher.hashToFieldLE(
      new TextEncoder().encode(rlnIdStr),
    );
  } catch (error) {
    console.error("Hash RLN identifier error:", error);
    return;
  }
  console.log("  - rln_identifier = " + rlnIdentifier.debug());

  console.log("\nComputing Poseidon hash for external nullifier");
  let externalNullifier;
  try {
    externalNullifier = rlnWasm.Hasher.poseidonHashPair(epoch, rlnIdentifier);
  } catch (error) {
    console.error("External nullifier hash error:", error);
    return;
  }
  console.log("  - external_nullifier = " + externalNullifier.debug());

  if (MULTI_MESSAGE_ID) {
    console.log("\nCreating default message_id");
  } else {
    console.log("\nCreating message_id");
  }
  const messageId = rlnWasm.WasmFr.fromUint(0);
  console.log("  - message_id = " + messageId.debug());

  let messageIds, selectorUsed;
  if (MULTI_MESSAGE_ID) {
    console.log(
      "\nCreating message_ids and selector_used (multi-message-id mode)",
    );
    console.log("  - using 2 out of 4 slots");

    messageIds = new rlnWasm.VecWasmFr();
    messageIds.push(rlnWasm.WasmFr.fromUint(0));
    messageIds.push(rlnWasm.WasmFr.fromUint(1));
    messageIds.push(rlnWasm.WasmFr.zero());
    messageIds.push(rlnWasm.WasmFr.zero());

    selectorUsed = Uint8Array.from([true, true, false, false], (b) =>
      b ? 1 : 0,
    );

    console.log("  - message_ids = " + messageIds.debug());
  }

  console.log("\nCreating RLN Witness");
  let witness;
  if (MULTI_MESSAGE_ID) {
    witness = new rlnWasm.WasmRLNWitnessInput(
      identitySecret,
      userMessageLimit,
      null,
      messageIds,
      pathElements,
      identityPathIndex,
      x,
      externalNullifier,
      selectorUsed,
    );
  } else {
    witness = new rlnWasm.WasmRLNWitnessInput(
      identitySecret,
      userMessageLimit,
      messageId,
      pathElements,
      identityPathIndex,
      x,
      externalNullifier,
    );
  }
  console.log("RLN Witness created successfully");

  console.log(
    "\nWasmRLNWitnessInput serialization: WasmRLNWitnessInput <-> bytes",
  );
  let serWitness;
  try {
    serWitness = witness.toBytesLE();
  } catch (error) {
    console.error("Witness serialization error:", error);
    return;
  }
  console.log(
    "  - serialized witness = [" + debugUint8Array(serWitness) + " ]",
  );

  let deserWitness;
  try {
    deserWitness = rlnWasm.WasmRLNWitnessInput.fromBytesLE(serWitness);
  } catch (error) {
    console.error("Witness deserialization error:", error);
    return;
  }
  console.log("  - witness deserialized successfully");

  console.log("\nCalculating witness");
  let witnessJson;
  try {
    witnessJson = witness.toBigIntJson();
  } catch (error) {
    console.error("Witness to BigInt JSON error:", error);
    return;
  }
  const calculatedWitness = await calculateWitness(
    circomPath,
    witnessJson,
    witnessCalculatorFile,
  );
  console.log("Witness calculated successfully");

  console.log("\nGenerating RLN Proof");
  let rln_proof;
  try {
    rln_proof = rlnInstance.generateRLNProofWithWitness(
      calculatedWitness,
      witness,
    );
  } catch (error) {
    console.error("Proof generation error:", error);
    return;
  }
  console.log("Proof generated successfully");

  console.log("\nGetting proof values");
  const proofValues = rln_proof.getValues();

  if (MULTI_MESSAGE_ID) {
    try {
      const ys = proofValues.ys();
      console.log("  - ys = " + ys.debug());
    } catch (error) {
      console.error("Error getting ys:", error);
    }

    try {
      const nullifiers = proofValues.nullifiers();
      console.log("  - nullifiers = " + nullifiers.debug());
    } catch (error) {
      console.error("Error getting nullifiers:", error);
    }
  } else {
    console.log("  - y = " + proofValues.y.debug());
    console.log("  - nullifier = " + proofValues.nullifier.debug());
  }

  console.log("  - root = " + proofValues.root.debug());
  console.log("  - x = " + proofValues.x.debug());
  console.log(
    "  - external_nullifier = " + proofValues.externalNullifier.debug(),
  );

  console.log("\nRLNProof serialization: RLNProof <-> bytes");
  let serProof;
  try {
    serProof = rln_proof.toBytesLE();
  } catch (error) {
    console.error("Proof serialization error:", error);
    return;
  }
  console.log("  - serialized proof = [" + debugUint8Array(serProof) + " ]");

  let deserProof;
  try {
    deserProof = rlnWasm.WasmRLNProof.fromBytesLE(serProof);
  } catch (error) {
    console.error("Proof deserialization error:", error);
    return;
  }
  console.log("  - proof deserialized successfully");

  console.log("\nRLNProofValues serialization: RLNProofValues <-> bytes");
  const serProofValues = proofValues.toBytesLE();
  console.log(
    "  - serialized proof_values = [" + debugUint8Array(serProofValues) + " ]",
  );

  let deserProofValues2;
  try {
    deserProofValues2 = rlnWasm.WasmRLNProofValues.fromBytesLE(serProofValues);
  } catch (error) {
    console.error("Proof values deserialization error:", error);
    return;
  }
  console.log("  - proof_values deserialized successfully");
  console.log(
    "  - deserialized external_nullifier = " +
      deserProofValues2.externalNullifier.debug(),
  );

  console.log("\nVerifying Proof");
  const roots = new rlnWasm.VecWasmFr();
  roots.push(computedRoot);
  let isValid;
  try {
    isValid = rlnInstance.verifyWithRoots(rln_proof, roots, x);
  } catch (error) {
    console.error("Proof verification error:", error);
    return;
  }
  if (isValid) {
    console.log("Proof verified successfully");
  } else {
    console.log("Proof verification failed");
    return;
  }

  console.log(
    "\nSimulating double-signaling attack (same epoch, different message)",
  );

  console.log("\nHashing second signal");
  const signal2 = new Uint8Array([
    11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  ]);
  let x2;
  try {
    x2 = rlnWasm.Hasher.hashToFieldLE(signal2);
  } catch (error) {
    console.error("Hash second signal error:", error);
    return;
  }
  console.log("  - x2 = " + x2.debug());

  if (MULTI_MESSAGE_ID) {
    console.log("\nCreating default message_id2");
  } else {
    console.log("\nCreating second message with the same id");
  }
  const messageId2 = rlnWasm.WasmFr.fromUint(0);
  console.log("  - message_id2 = " + messageId2.debug());

  let messageIds2, selectorUsed2;
  if (MULTI_MESSAGE_ID) {
    console.log(
      "\nCreating message_ids2 and selector_used2 (multi-message-id mode)",
    );
    console.log("  - using 2 out of 4 slots");
    console.log("  - duplicated slot id 1");

    messageIds2 = new rlnWasm.VecWasmFr();
    messageIds2.push(rlnWasm.WasmFr.fromUint(1));
    messageIds2.push(rlnWasm.WasmFr.zero());
    messageIds2.push(rlnWasm.WasmFr.fromUint(3));
    messageIds2.push(rlnWasm.WasmFr.zero());

    selectorUsed2 = Uint8Array.from([true, false, true, false], (b) =>
      b ? 1 : 0,
    );

    console.log("  - message_ids2 = " + messageIds2.debug());
  }

  console.log("\nCreating second RLN Witness");
  let witness2;
  if (MULTI_MESSAGE_ID) {
    witness2 = new rlnWasm.WasmRLNWitnessInput(
      identitySecret,
      userMessageLimit,
      null,
      messageIds2,
      pathElements,
      identityPathIndex,
      x2,
      externalNullifier,
      selectorUsed2,
    );
  } else {
    witness2 = new rlnWasm.WasmRLNWitnessInput(
      identitySecret,
      userMessageLimit,
      messageId2,
      pathElements,
      identityPathIndex,
      x2,
      externalNullifier,
    );
  }
  console.log("Second RLN Witness created successfully");

  console.log("\nCalculating second witness");
  let witnessJson2;
  try {
    witnessJson2 = witness2.toBigIntJson();
  } catch (error) {
    console.error("Second witness to BigInt JSON error:", error);
    return;
  }
  const calculatedWitness2 = await calculateWitness(
    circomPath,
    witnessJson2,
    witnessCalculatorFile,
  );
  console.log("Second witness calculated successfully");

  console.log("\nGenerating second RLN Proof");
  let rln_proof2;
  try {
    rln_proof2 = rlnInstance.generateRLNProofWithWitness(
      calculatedWitness2,
      witness2,
    );
  } catch (error) {
    console.error("Second proof generation error:", error);
    return;
  }
  console.log("Second proof generated successfully");

  console.log("\nVerifying second proof");
  let isValid2;
  try {
    isValid2 = rlnInstance.verifyWithRoots(rln_proof2, roots, x2);
  } catch (error) {
    console.error("Proof verification error:", error);
    return;
  }
  if (isValid2) {
    console.log("Second proof verified successfully");

    console.log("\nRecovering identity secret");
    const proofValues1 = rln_proof.getValues();
    const proofValues2 = rln_proof2.getValues();
    let recoveredSecret;
    try {
      recoveredSecret = rlnWasm.WasmRLNProofValues.recoverIdSecret(
        proofValues1,
        proofValues2,
      );
    } catch (error) {
      console.error("Identity recovery error:", error);
      return;
    }
    console.log("  - recovered_secret = " + recoveredSecret.debug());
    console.log("  - original_secret  = " + identitySecret.debug());
    console.log("Slashing successful: Identity is recovered!");
  } else {
    console.log("Second proof verification failed");
  }
}

main().catch(console.error);
