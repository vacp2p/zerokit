import { readFileSync } from "fs";
import { fileURLToPath } from "url";
import { dirname, join } from "path";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

export const TREE_DEPTH = 20;
export const MAX_OUT = 4;

export function debugUint8Array(uint8Array) {
  return Array.from(uint8Array, (byte) =>
    byte.toString(16).padStart(2, "0"),
  ).join(", ");
}

export async function initRLN(
  enableMultiMessageId = false,
  usePoseidon2 = false,
) {
  const rlnWasm = await import("../pkg/rln_wasm.js");
  const wasmPath = join(__dirname, "../pkg/rln_wasm_bg.wasm");
  const wasmBytes = readFileSync(wasmPath);
  rlnWasm.initSync({ module: wasmBytes });

  const resourceDir = usePoseidon2
    ? "../../rln/resources/tree_depth_20/rln_poseidon2_single"
    : enableMultiMessageId
      ? "../../rln/resources/tree_depth_20/rln_multi"
      : "../../rln/resources/tree_depth_20/rln_single";
  const zkeyPath = join(__dirname, resourceDir, "rln_final.arkzkey");
  const graphPath = join(__dirname, resourceDir, "graph.bin");

  console.log(
    usePoseidon2
      ? "Creating RLN instance (Poseidon2)"
      : "Creating RLN instance",
  );
  const zkeyData = readFileSync(zkeyPath);
  const graphData = readFileSync(graphPath);
  let rlnInstance;
  try {
    rlnInstance = usePoseidon2
      ? rlnWasm.WasmRLNPoseidon2.newWithParams(zkeyData, graphData)
      : rlnWasm.WasmRLN.newWithParams(zkeyData, graphData);
  } catch (error) {
    console.error("RLN instance creation error:", error);
    throw error;
  }
  console.log("  - RLN instance created successfully");
  console.log("  - circuit tree depth = " + TREE_DEPTH);
  if (enableMultiMessageId) {
    console.log("  - circuit max out = " + MAX_OUT);
  }

  return { rlnWasm, rlnInstance };
}

export function createMember(rlnWasm, usePoseidon2 = false) {
  console.log(
    usePoseidon2
      ? "\nGenerating identity keys (Poseidon2)"
      : "\nGenerating identity keys",
  );
  const identity = usePoseidon2
    ? rlnWasm.WasmIdentityKeys.generatePoseidon2()
    : rlnWasm.WasmIdentityKeys.generate();
  const identitySecret = identity.getSecret();
  const idCommitment = identity.getCommitment();
  console.log("  - identity generated successfully");
  console.log("  - identity secret = " + identitySecret.debug());
  console.log("  - id commitment = " + idCommitment.debug());

  console.log("\nCreating message limit");
  const userMessageLimit = rlnWasm.WasmFr.fromUint(10);
  console.log("  - user message limit = " + userMessageLimit.debug());

  console.log("\nComputing rate commitment");
  const hashPair = usePoseidon2
    ? rlnWasm.poseidon2HashPair
    : rlnWasm.poseidonHashPair;
  const rateCommitment = hashPair(idCommitment, userMessageLimit);
  console.log("  - rate commitment = " + rateCommitment.debug());

  return {
    identity,
    identitySecret,
    idCommitment,
    userMessageLimit,
    rateCommitment,
  };
}

export function computeMerkleProof(
  rlnWasm,
  rateCommitment,
  usePoseidon2 = false,
) {
  console.log("\nComputing Merkle path for stateless mode");
  const hashPair = usePoseidon2
    ? rlnWasm.poseidon2HashPair
    : rlnWasm.poseidonHashPair;
  const defaultLeaf = rlnWasm.WasmFr.zero();

  const defaultHashes = [];
  defaultHashes[0] = hashPair(defaultLeaf, defaultLeaf);
  for (let i = 1; i < TREE_DEPTH - 1; i++) {
    defaultHashes[i] = hashPair(defaultHashes[i - 1], defaultHashes[i - 1]);
  }

  const pathElements = rlnWasm.VecWasmFr.new();
  pathElements.push(defaultLeaf);
  for (let i = 1; i < TREE_DEPTH; i++) {
    pathElements.push(defaultHashes[i - 1]);
  }
  const identityPathIndex = new Uint8Array(TREE_DEPTH);
  const merkleProof = rlnWasm.WasmRLNMerkleProof.new(
    pathElements,
    identityPathIndex,
  );

  console.log("\nComputing Merkle root for stateless mode");
  console.log("  - computing root for index 0 with rate commitment");
  let computedRoot = hashPair(rateCommitment, defaultLeaf);
  for (let i = 1; i < TREE_DEPTH; i++) {
    computedRoot = hashPair(computedRoot, defaultHashes[i - 1]);
  }
  console.log("  - computed root = " + computedRoot.debug());

  const roots = rlnWasm.VecWasmFr.new();
  roots.push(computedRoot);

  return { merkleProof, roots };
}

export function hashSignal(rlnWasm, signal) {
  return rlnWasm.hashToFieldLE(signal);
}

export function computeExternalNullifier(
  rlnWasm,
  epochStr = "test-epoch",
  rlnIdStr = "test-rln-identifier",
  usePoseidon2 = false,
) {
  console.log("\nHashing epoch");
  const epoch = rlnWasm.hashToFieldLE(new TextEncoder().encode(epochStr));
  console.log("  - epoch = " + epoch.debug());

  console.log("\nHashing RLN identifier");
  const rlnIdentifier = rlnWasm.hashToFieldLE(
    new TextEncoder().encode(rlnIdStr),
  );
  console.log("  - RLN identifier = " + rlnIdentifier.debug());

  console.log(
    usePoseidon2
      ? "\nComputing Poseidon2 hash for external nullifier"
      : "\nComputing Poseidon hash for external nullifier",
  );
  const externalNullifier = usePoseidon2
    ? rlnWasm.poseidon2HashPair(epoch, rlnIdentifier)
    : rlnWasm.poseidonHashPair(epoch, rlnIdentifier);
  console.log("  - external nullifier = " + externalNullifier.debug());

  return externalNullifier;
}

export function createWitness(
  rlnWasm,
  member,
  merkleProof,
  messageId,
  x,
  externalNullifier,
) {
  return rlnWasm.WasmRLNWitnessInput.newSingle(
    member.identitySecret,
    member.userMessageLimit,
    messageId,
    merkleProof,
    x,
    externalNullifier,
  );
}
