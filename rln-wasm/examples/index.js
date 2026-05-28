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

async function main() {
  const rlnWasm = await import("../pkg/rln_wasm.js");
  const wasmPath = join(__dirname, "../pkg/rln_wasm_bg.wasm");
  const wasmBytes = readFileSync(wasmPath);
  rlnWasm.initSync({ module: wasmBytes });

  const zkeyPath = MULTI_MESSAGE_ID
    ? join(
        __dirname,
        "../../rln/resources/tree_depth_20/multi_message_id/max_out_4/rln_final.arkzkey",
      )
    : join(__dirname, "../../rln/resources/tree_depth_20/rln_final.arkzkey");

  const graphPath = MULTI_MESSAGE_ID
    ? join(
        __dirname,
        "../../rln/resources/tree_depth_20/multi_message_id/max_out_4/graph.bin",
      )
    : join(__dirname, "../../rln/resources/tree_depth_20/graph.bin");

  console.log("Creating RLN instance");
  const zkeyData = readFileSync(zkeyPath);
  const graphData = readFileSync(graphPath);
  let rlnInstance;
  try {
    rlnInstance = rlnWasm.WasmRLN.newWithParams(zkeyData, graphData);
  } catch (error) {
    console.error("Initial RLN instance creation error:", error);
    return;
  }
  console.log("  - RLN instance created successfully");

  const treeDepth = 20;
  console.log("  - circuit tree depth = " + treeDepth);
  const maxOut = 4;
  if (MULTI_MESSAGE_ID) {
    console.log("  - circuit max out = " + maxOut);
  }

  console.log("\nGenerating identity keys");
  let identity = rlnWasm.Identity.generate();
  const identitySecret = identity.getSecretHash();
  const idCommitment = identity.getCommitment();
  console.log("  - identity generated successfully");
  console.log("  - identity secret = " + identitySecret.debug());
  console.log("  - id commitment = " + idCommitment.debug());

  console.log("\nCreating message limit");
  const userMessageLimit = rlnWasm.WasmFr.fromUint(10);
  console.log("  - user message limit = " + userMessageLimit.debug());

  console.log("\nComputing rate commitment");
  let rateCommitment = rlnWasm.Hasher.poseidonHashPair(
    idCommitment,
    userMessageLimit,
  );
  console.log("  - rate commitment = " + rateCommitment.debug());

  console.log("\nWasmFr serialization: WasmFr <-> bytes");
  const serRateCommitment = rateCommitment.toBytesLE();
  console.log(
    "  - serialized rate commitment = [" +
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
    "  - deserialized rate commitment = " + deserRateCommitment.debug(),
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
  const defaultLeaf = rlnWasm.WasmFr.zero();

  const defaultHashes = [];
  defaultHashes[0] = rlnWasm.Hasher.poseidonHashPair(defaultLeaf, defaultLeaf);
  for (let i = 1; i < treeDepth - 1; i++) {
    defaultHashes[i] = rlnWasm.Hasher.poseidonHashPair(
      defaultHashes[i - 1],
      defaultHashes[i - 1],
    );
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
    "  - serialized path elements = [" + debugUint8Array(serPathElements) + "]",
  );

  let deserPathElements;
  try {
    deserPathElements = rlnWasm.VecWasmFr.fromBytesLE(serPathElements);
  } catch (error) {
    console.error("Path elements deserialization error:", error);
    return;
  }
  console.log("  - deserialized path elements = ", deserPathElements.debug());

  console.log("\nUint8Array serialization: Uint8Array <-> bytes");
  const serPathIndex = rlnWasm.Uint8ArrayUtils.toBytesLE(identityPathIndex);
  console.log(
    "  - serialized path index = [" + debugUint8Array(serPathIndex) + "]",
  );

  let deserPathIndex;
  try {
    deserPathIndex = rlnWasm.Uint8ArrayUtils.fromBytesLE(serPathIndex);
  } catch (error) {
    console.error("Path index deserialization error:", error);
    return;
  }
  console.log("  - deserialized path index =", deserPathIndex);

  console.log("\nComputing Merkle root for stateless mode");
  console.log("  - computing root for index 0 with rate commitment");

  let computedRoot = rlnWasm.Hasher.poseidonHashPair(
    rateCommitment,
    defaultLeaf,
  );
  for (let i = 1; i < treeDepth; i++) {
    computedRoot = rlnWasm.Hasher.poseidonHashPair(
      computedRoot,
      defaultHashes[i - 1],
    );
  }
  console.log("  - computed root = " + computedRoot.debug());

  console.log("\nHashing first signal");
  const signal1 = new Uint8Array([
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0,
  ]);
  let x1;
  try {
    x1 = rlnWasm.Hasher.hashToFieldLE(signal1);
  } catch (error) {
    console.error("Hash signal error:", error);
    return;
  }
  console.log("  - x1 = " + x1.debug());

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
  console.log("  - RLN identifier = " + rlnIdentifier.debug());

  console.log("\nComputing Poseidon hash for external nullifier");
  let externalNullifier = rlnWasm.Hasher.poseidonHashPair(epoch, rlnIdentifier);
  console.log("  - external nullifier = " + externalNullifier.debug());

  console.log("\nCreating first message id");
  const messageId1 = rlnWasm.WasmFr.fromUint(0);
  console.log("  - message id = " + messageId1.debug());

  let messageIds1, selectorUsed1;
  if (MULTI_MESSAGE_ID) {
    console.log(
      "\nCreating first message ids and selector used (Multi message-id mode)",
    );
    console.log("  - using 2 out of " + maxOut + " slots");

    messageIds1 = new rlnWasm.VecWasmFr();
    messageIds1.push(rlnWasm.WasmFr.fromUint(0));
    messageIds1.push(rlnWasm.WasmFr.fromUint(1));
    messageIds1.push(rlnWasm.WasmFr.zero());
    messageIds1.push(rlnWasm.WasmFr.zero());

    selectorUsed1 = Uint8Array.from([true, true, false, false], (b) =>
      b ? 1 : 0,
    );

    console.log("  - message ids = " + messageIds1.debug());
  }

  console.log("\nCreating first RLN witness");
  let witness1;
  if (MULTI_MESSAGE_ID) {
    witness1 = rlnWasm.WasmRLNWitnessInput.newMulti(
      identitySecret,
      userMessageLimit,
      messageIds1,
      pathElements,
      identityPathIndex,
      x1,
      externalNullifier,
      selectorUsed1,
    );
  } else {
    witness1 = rlnWasm.WasmRLNWitnessInput.newSingle(
      identitySecret,
      userMessageLimit,
      messageId1,
      pathElements,
      identityPathIndex,
      x1,
      externalNullifier,
    );
  }
  console.log("  - first RLN witness created successfully");

  console.log(
    "\nWasmRLNWitnessInput serialization: WasmRLNWitnessInput <-> bytes",
  );
  let serWitness1;
  try {
    serWitness1 = witness1.toBytesLE();
  } catch (error) {
    console.error("Witness serialization error:", error);
    return;
  }
  console.log(
    "  - serialized witness = [" + debugUint8Array(serWitness1) + " ]",
  );

  let deserWitness1;
  try {
    deserWitness1 = rlnWasm.WasmRLNWitnessInput.fromBytesLE(serWitness1);
  } catch (error) {
    console.error("Witness deserialization error:", error);
    return;
  }
  console.log("  - witness deserialized successfully");

  console.log("\nGenerating first RLN proof");
  let rlnProof1;
  try {
    rlnProof1 = rlnInstance.generateProof(witness1);
  } catch (error) {
    console.error("Proof generation error:", error);
    return;
  }
  console.log("  - proof generated successfully");

  console.log("\nGetting first RLN proof values");
  const proofValues1 = rlnProof1.getValues();
  console.log("  - proof values extracted successfully");

  if (MULTI_MESSAGE_ID) {
    try {
      const ys = proofValues1.ys();
      console.log("  - ys = " + ys.debug());
    } catch (error) {
      console.error("Error getting ys:", error);
    }

    try {
      const nullifiers = proofValues1.nullifiers();
      console.log("  - nullifiers = " + nullifiers.debug());
    } catch (error) {
      console.error("Error getting nullifiers:", error);
    }
  } else {
    console.log("  - y = " + proofValues1.y.debug());
    console.log("  - nullifier = " + proofValues1.nullifier.debug());
  }

  console.log("  - root = " + proofValues1.root.debug());
  console.log("  - x = " + proofValues1.x.debug());
  console.log(
    "  - external nullifier = " + proofValues1.externalNullifier.debug(),
  );

  console.log("\nWasmRLNProof serialization: WasmRLNProof <-> bytes");
  let serProof1;
  try {
    serProof1 = rlnProof1.toBytesLE();
  } catch (error) {
    console.error("Proof serialization error:", error);
    return;
  }
  console.log("  - serialized proof = [" + debugUint8Array(serProof1) + " ]");

  let deserProof1;
  try {
    deserProof1 = rlnWasm.WasmRLNProof.fromBytesLE(serProof1);
  } catch (error) {
    console.error("Proof deserialization error:", error);
    return;
  }
  console.log("  - proof deserialized successfully");

  console.log(
    "\nWasmRLNProofValues serialization: WasmRLNProofValues <-> bytes",
  );
  const serProofValues1 = proofValues1.toBytesLE();
  console.log(
    "  - serialized proof values = [" + debugUint8Array(serProofValues1) + " ]",
  );

  let deserProofValues1;
  try {
    deserProofValues1 = rlnWasm.WasmRLNProofValues.fromBytesLE(serProofValues1);
  } catch (error) {
    console.error("RLN proof values deserialization error:", error);
    return;
  }
  console.log("  - proof values deserialized successfully");
  console.log(
    "  - deserialized external nullifier = " +
      deserProofValues1.externalNullifier.debug(),
  );

  console.log("\nVerifying first proof");
  const roots = new rlnWasm.VecWasmFr();
  roots.push(computedRoot);
  let isValid1;
  try {
    isValid1 = rlnInstance.verifyWithRoots(rlnProof1, roots, x1);
  } catch (error) {
    console.error("Proof verification error:", error);
    return;
  }
  if (isValid1) {
    console.log("  - first proof verified successfully");
  } else {
    console.log("First proof verification failed");
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
    console.log("\nCreating second message id");
  } else {
    console.log("\nCreating second message with the same id");
  }
  const messageId2 = rlnWasm.WasmFr.fromUint(0);
  console.log("  - message id = " + messageId2.debug());

  let messageIds2, selectorUsed2;
  if (MULTI_MESSAGE_ID) {
    console.log(
      "\nCreating second message ids and selector used (Multi message-id mode)",
    );
    console.log("  - using 2 out of " + maxOut + " slots");
    console.log("  - duplicated slot id 1");

    messageIds2 = new rlnWasm.VecWasmFr();
    messageIds2.push(rlnWasm.WasmFr.fromUint(1));
    messageIds2.push(rlnWasm.WasmFr.zero());
    messageIds2.push(rlnWasm.WasmFr.fromUint(3));
    messageIds2.push(rlnWasm.WasmFr.zero());

    selectorUsed2 = Uint8Array.from([true, false, true, false], (b) =>
      b ? 1 : 0,
    );

    console.log("  - message ids = " + messageIds2.debug());
  }

  console.log("\nCreating second RLN witness");
  let witness2;
  if (MULTI_MESSAGE_ID) {
    witness2 = rlnWasm.WasmRLNWitnessInput.newMulti(
      identitySecret,
      userMessageLimit,
      messageIds2,
      pathElements,
      identityPathIndex,
      x2,
      externalNullifier,
      selectorUsed2,
    );
  } else {
    witness2 = rlnWasm.WasmRLNWitnessInput.newSingle(
      identitySecret,
      userMessageLimit,
      messageId2,
      pathElements,
      identityPathIndex,
      x2,
      externalNullifier,
    );
  }
  console.log("  - second RLN witness created successfully");

  console.log("\nGenerating second RLN proof");
  let rlnProof2;
  try {
    rlnProof2 = rlnInstance.generateProof(witness2);
  } catch (error) {
    console.error("Second proof generation error:", error);
    return;
  }
  console.log("  - second proof generated successfully");

  console.log("\nGetting second RLN proof values");
  const proofValues2 = rlnProof2.getValues();
  console.log("  - second proof values extracted successfully");

  console.log("\nVerifying second proof");
  let isValid2;
  try {
    isValid2 = rlnInstance.verifyWithRoots(rlnProof2, roots, x2);
  } catch (error) {
    console.error("Proof verification error:", error);
    return;
  }
  if (isValid2) {
    console.log("  - second proof verified successfully");

    console.log("\nRecovering identity secret");
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
    console.log("  - recovered secret = " + recoveredSecret.debug());
    console.log("  - identity secret = " + identitySecret.debug());
    console.log("  - identity recovered successfully");
  } else {
    console.log("Second proof verification failed");
  }

  console.log("\nGenerating partial proof from partial witness");
  let partialWitness;
  try {
    partialWitness = rlnWasm.WasmRLNPartialWitnessInput.fromWitness(witness1);
  } catch (error) {
    console.error("Partial witness creation error:", error);
    return;
  }
  console.log("  - partial witness created successfully");

  console.log(
    "\nWasmRLNPartialWitnessInput serialization: WasmRLNPartialWitnessInput <-> bytes",
  );
  let serPartialWitness;
  try {
    serPartialWitness = partialWitness.toBytesLE();
  } catch (error) {
    console.error("Partial witness serialization error:", error);
    return;
  }
  console.log(
    "  - serialized partial witness = [" +
      debugUint8Array(serPartialWitness) +
      " ]",
  );

  let deserPartialWitness;
  try {
    deserPartialWitness =
      rlnWasm.WasmRLNPartialWitnessInput.fromBytesLE(serPartialWitness);
  } catch (error) {
    console.error("Partial witness deserialization error:", error);
    return;
  }
  console.log("  - partial witness deserialized successfully");

  console.log("\nGenerating partial ZK proof");
  let partialProof;
  try {
    partialProof = rlnInstance.generatePartialProof(deserPartialWitness);
  } catch (error) {
    console.error("Partial proof generation error:", error);
    return;
  }
  console.log("  - partial proof generated successfully");

  console.log(
    "\nWasmRLNPartialProof serialization: WasmRLNPartialProof <-> bytes",
  );
  let serPartialProof;
  try {
    serPartialProof = partialProof.toBytesLE();
  } catch (error) {
    console.error("Partial proof serialization error:", error);
    return;
  }
  console.log(
    "  - serialized partial proof = [" +
      debugUint8Array(serPartialProof) +
      " ]",
  );

  let deserPartialProof;
  try {
    deserPartialProof =
      rlnWasm.WasmRLNPartialProof.fromBytesLE(serPartialProof);
  } catch (error) {
    console.error("Partial proof deserialization error:", error);
    return;
  }
  console.log("  - partial proof deserialized successfully");

  console.log("\nFinishing proof with full witness");
  let fullProof;
  try {
    fullProof = rlnInstance.finishProof(deserPartialProof, witness1);
  } catch (error) {
    console.error("Finish proof error:", error);
    return;
  }
  console.log("  - partial proof finished successfully");

  console.log("\nVerifying full proof");
  let isFullProofValid;
  try {
    isFullProofValid = rlnInstance.verifyWithRoots(
      fullProof,
      roots,
      x1,
    );
  } catch (error) {
    console.error("Full proof verification error:", error);
    return;
  }
  if (isFullProofValid) {
    console.log("  - full proof verified successfully");
  } else {
    console.log("Full proof verification failed");
  }
}

main().catch(console.error);
