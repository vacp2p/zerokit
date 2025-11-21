import { readFileSync } from "fs";
import { fileURLToPath } from "url";
import { dirname, join } from "path";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

async function calculateWitness(circomPath, inputs, witnessCalculatorFile) {
  const wasmFile = readFileSync(circomPath);
  const wasmFileBuffer = wasmFile.slice(
    wasmFile.byteOffset,
    wasmFile.byteOffset + wasmFile.byteLength
  );
  const witnessCalculator = await witnessCalculatorFile(wasmFileBuffer);
  const calculatedWitness = await witnessCalculator.calculateWitness(
    inputs,
    false
  );
  return calculatedWitness;
}

async function main() {
  const rlnWasm = await import("../pkg/rln_wasm.js");
  const wasmPath = join(__dirname, "../pkg/rln_wasm_bg.wasm");
  const wasmBytes = readFileSync(wasmPath);
  rlnWasm.initSync({ module: wasmBytes });

  const zkeyPath = join(
    __dirname,
    "../../rln/resources/tree_depth_20/rln_final.arkzkey"
  );
  const circomPath = join(
    __dirname,
    "../../rln/resources/tree_depth_20/rln.wasm"
  );
  const witnessCalculatorPath = join(
    __dirname,
    "../resources/witness_calculator.js"
  );
  const { builder: witnessCalculatorFile } = await import(
    witnessCalculatorPath
  );

  console.log("Creating RLN instance");
  const zkeyData = readFileSync(zkeyPath);
  const rlnInstance = new rlnWasm.WasmRLN(new Uint8Array(zkeyData));
  console.log("RLN instance created successfully");

  console.log("\nGenerating identity keys");
  const identity = rlnWasm.Identity.generate();
  const identitySecret = identity.getSecretHash();
  const idCommitment = identity.getCommitment();
  console.log("Identity generated");
  console.log("  - identity_secret = " + identitySecret.debug());
  console.log("  - id_commitment = " + idCommitment.debug());

  console.log("\nCreating message limit");
  const userMessageLimit = rlnWasm.WasmFr.fromUint(1);
  console.log("  - user_message_limit = " + userMessageLimit.debug());

  console.log("\nComputing rate commitment");
  const rateCommitment = rlnWasm.Hasher.poseidonHashPair(
    idCommitment,
    userMessageLimit
  );
  console.log("  - rate_commitment = " + rateCommitment.debug());

  console.log("\nWasmFr serialization: WasmFr <-> bytes");
  const serRateCommitment = rateCommitment.toBytesLE();
  console.log("  - serialized rate_commitment =", serRateCommitment);

  const deserRateCommitment = rlnWasm.WasmFr.fromBytesLE(serRateCommitment);
  console.log(
    "  - deserialized rate_commitment = " + deserRateCommitment.debug()
  );

  console.log("\nBuilding Merkle path for stateless mode");
  const treeDepth = 20;
  const defaultLeaf = rlnWasm.WasmFr.zero();

  const defaultHashes = [];
  defaultHashes[0] = rlnWasm.Hasher.poseidonHashPair(defaultLeaf, defaultLeaf);
  for (let i = 1; i < treeDepth - 1; i++) {
    defaultHashes[i] = rlnWasm.Hasher.poseidonHashPair(
      defaultHashes[i - 1],
      defaultHashes[i - 1]
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
  console.log("  - serialized path_elements = ", serPathElements);

  const deserPathElements = rlnWasm.VecWasmFr.fromBytesLE(serPathElements);
  console.log("  - deserialized path_elements = ", deserPathElements.debug());

  // console.log("\nIdentity path index serialization: Uint8Array <-> bytes");

  console.log("\nComputing Merkle root for stateless mode");
  console.log("  - computing root for index 0 with rate_commitment");

  let computedRoot = rlnWasm.Hasher.poseidonHashPair(
    rateCommitment,
    defaultLeaf
  );
  for (let i = 1; i < treeDepth; i++) {
    computedRoot = rlnWasm.Hasher.poseidonHashPair(
      computedRoot,
      defaultHashes[i - 1]
    );
  }
  console.log("  - computed_root = " + computedRoot.debug());

  console.log("\nHashing signal");
  const signal = new Uint8Array([
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0,
  ]);
  const x = rlnWasm.Hasher.hashToFieldLE(signal);
  console.log("  - x = " + x.debug());

  console.log("\nHashing epoch");
  const epochStr = "test-epoch";
  const epoch = rlnWasm.Hasher.hashToFieldLE(
    new TextEncoder().encode(epochStr)
  );
  console.log("  - epoch = " + epoch.debug());

  console.log("\nHashing RLN identifier");
  const rlnIdStr = "test-rln-identifier";
  const rlnIdentifier = rlnWasm.Hasher.hashToFieldLE(
    new TextEncoder().encode(rlnIdStr)
  );
  console.log("  - rln_identifier = " + rlnIdentifier.debug());

  console.log("\nComputing Poseidon hash for external nullifier");
  const externalNullifier = rlnWasm.Hasher.poseidonHashPair(
    epoch,
    rlnIdentifier
  );
  console.log("  - external_nullifier = " + externalNullifier.debug());

  console.log("\nCreating message_id");
  const messageId = rlnWasm.WasmFr.fromUint(0);
  console.log("  - message_id = " + messageId.debug());

  console.log("\nGenerating RLN Proof");
  const witness = new rlnWasm.WasmRLNWitnessInput(
    identitySecret,
    userMessageLimit,
    messageId,
    pathElements,
    identityPathIndex,
    x,
    externalNullifier
  );
  const witnessJson = witness.toBigIntJson();
  const calculatedWitness = await calculateWitness(
    circomPath,
    witnessJson,
    witnessCalculatorFile
  );
  const proof = rlnInstance.generateProofWithWitness(
    calculatedWitness,
    witness
  );
  console.log("Proof generated successfully");

  console.log("\nVerifying Proof");
  const roots = new rlnWasm.VecWasmFr();
  roots.push(computedRoot);
  const isValid = rlnInstance.verifyWithRoots(proof, roots, x);
  if (isValid) {
    console.log("Proof verified successfully");
  } else {
    console.log("Proof verification failed");
    return;
  }

  console.log(
    "\nSimulating double-signaling attack (same epoch, different message)"
  );

  console.log("\nHashing second signal");
  const signal2 = new Uint8Array([
    11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  ]);
  const x2 = rlnWasm.Hasher.hashToFieldLE(signal2);
  console.log("  - x2 = " + x2.debug());

  console.log("\nCreating second message with the same id");
  const messageId2 = rlnWasm.WasmFr.fromUint(0);
  console.log("  - message_id2 = " + messageId2.debug());

  console.log("\nGenerating second RLN Proof");
  const witness2 = new rlnWasm.WasmRLNWitnessInput(
    identitySecret,
    userMessageLimit,
    messageId2,
    pathElements,
    identityPathIndex,
    x2,
    externalNullifier
  );
  const witnessJson2 = witness2.toBigIntJson();
  const calculatedWitness2 = await calculateWitness(
    circomPath,
    witnessJson2,
    witnessCalculatorFile
  );
  const proof2 = rlnInstance.generateProofWithWitness(
    calculatedWitness2,
    witness2
  );
  console.log("Second proof generated successfully");

  console.log("\nVerifying second proof");
  const isValid2 = rlnInstance.verifyWithRoots(proof2, roots, x2);
  if (isValid2) {
    console.log("Second proof verified successfully");

    console.log("\nRecovering identity secret");
    const recoveredSecret = rlnWasm.WasmRLNProof.recoverIdSecret(proof, proof2);
    console.log("  - recovered_secret = " + recoveredSecret.debug());
    console.log("  - original_secret  = " + identitySecret.debug());
    console.log("Slashing successful: Identity is recovered!");
  } else {
    console.log("Second proof verification failed");
  }
}

main().catch(console.error);
