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

export async function initRLN(multiMessageId = false) {
  const rlnWasm = await import("../pkg/rln_wasm.js");
  const wasmPath = join(__dirname, "../pkg/rln_wasm_bg.wasm");
  const wasmBytes = readFileSync(wasmPath);
  rlnWasm.initSync({ module: wasmBytes });

  const resourceDir = multiMessageId
    ? "../../rln/resources/tree_depth_20/multi_message_id/max_out_4"
    : "../../rln/resources/tree_depth_20";
  const zkeyPath = join(__dirname, resourceDir, "rln_final.arkzkey");
  const graphPath = join(__dirname, resourceDir, "graph.bin");

  console.log("Creating RLN instance");
  const zkeyData = readFileSync(zkeyPath);
  const graphData = readFileSync(graphPath);
  let rlnInstance;
  try {
    rlnInstance = rlnWasm.WasmRLN.newWithParams(zkeyData, graphData);
  } catch (error) {
    console.error("RLN instance creation error:", error);
    throw error;
  }
  console.log("  - RLN instance created successfully");
  console.log("  - circuit tree depth = " + TREE_DEPTH);
  if (multiMessageId) {
    console.log("  - circuit max out = " + MAX_OUT);
  }

  return { rlnWasm, rlnInstance, multiMessageId };
}

export function generateIdentity(env) {
  const { rlnWasm } = env;
  console.log("\nGenerating identity keys");
  const identity = rlnWasm.Identity.generate();
  const identitySecret = identity.getSecretHash();
  const idCommitment = identity.getCommitment();
  console.log("  - identity generated successfully");
  console.log("  - identity secret = " + identitySecret.debug());
  console.log("  - id commitment = " + idCommitment.debug());

  console.log("\nCreating message limit");
  const userMessageLimit = rlnWasm.WasmFr.fromUint(10);
  console.log("  - user message limit = " + userMessageLimit.debug());

  console.log("\nComputing rate commitment");
  const rateCommitment = rlnWasm.Hasher.poseidonHashPair(
    idCommitment,
    userMessageLimit,
  );
  console.log("  - rate commitment = " + rateCommitment.debug());

  return {
    identity,
    identitySecret,
    idCommitment,
    userMessageLimit,
    rateCommitment,
  };
}

export function buildMerkleProof(env, rateCommitment) {
  const { rlnWasm } = env;
  console.log("\nBuilding Merkle path for stateless mode");
  const defaultLeaf = rlnWasm.WasmFr.zero();

  const defaultHashes = [];
  defaultHashes[0] = rlnWasm.Hasher.poseidonHashPair(defaultLeaf, defaultLeaf);
  for (let i = 1; i < TREE_DEPTH - 1; i++) {
    defaultHashes[i] = rlnWasm.Hasher.poseidonHashPair(
      defaultHashes[i - 1],
      defaultHashes[i - 1],
    );
  }

  const pathElements = rlnWasm.VecWasmFr.new();
  pathElements.push(defaultLeaf);
  for (let i = 1; i < TREE_DEPTH; i++) {
    pathElements.push(defaultHashes[i - 1]);
  }
  const identityPathIndex = new Uint8Array(TREE_DEPTH);

  console.log("\nComputing Merkle root for stateless mode");
  console.log("  - computing root for index 0 with rate commitment");
  let computedRoot = rlnWasm.Hasher.poseidonHashPair(
    rateCommitment,
    defaultLeaf,
  );
  for (let i = 1; i < TREE_DEPTH; i++) {
    computedRoot = rlnWasm.Hasher.poseidonHashPair(
      computedRoot,
      defaultHashes[i - 1],
    );
  }
  console.log("  - computed root = " + computedRoot.debug());

  const roots = rlnWasm.VecWasmFr.new();
  roots.push(computedRoot);

  return { pathElements, identityPathIndex, computedRoot, roots };
}

export function hashSignal(env, signal) {
  return env.rlnWasm.Hasher.hashToFieldLE(signal);
}

export function computeExternalNullifier(
  env,
  epochStr = "test-epoch",
  rlnIdStr = "test-rln-identifier",
) {
  const { rlnWasm } = env;
  console.log("\nHashing epoch");
  const epoch = rlnWasm.Hasher.hashToFieldLE(
    new TextEncoder().encode(epochStr),
  );
  console.log("  - epoch = " + epoch.debug());

  console.log("\nHashing RLN identifier");
  const rlnIdentifier = rlnWasm.Hasher.hashToFieldLE(
    new TextEncoder().encode(rlnIdStr),
  );
  console.log("  - RLN identifier = " + rlnIdentifier.debug());

  console.log("\nComputing Poseidon hash for external nullifier");
  const externalNullifier = rlnWasm.Hasher.poseidonHashPair(
    epoch,
    rlnIdentifier,
  );
  console.log("  - external nullifier = " + externalNullifier.debug());

  return externalNullifier;
}

export function createWitness(
  env,
  identity,
  merkleProof,
  messageId,
  x,
  externalNullifier,
) {
  return env.rlnWasm.WasmRLNWitnessInput.newSingle(
    identity.identitySecret,
    identity.userMessageLimit,
    messageId,
    merkleProof.pathElements,
    merkleProof.identityPathIndex,
    x,
    externalNullifier,
  );
}
