import {
  initRLN,
  createMember,
  computeMerkleProof,
  computeExternalNullifier,
  hashSignal,
  createWitness,
} from "./common.js";

async function main() {
  const { rlnWasm, rlnInstance } = await initRLN();
  const member = createMember(rlnWasm);
  const merkleProof = computeMerkleProof(rlnWasm, member.rateCommitment);
  const externalNullifier = computeExternalNullifier(rlnWasm);

  console.log("\nHashing signal");
  const signal = new Uint8Array([
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0,
  ]);
  const x = hashSignal(rlnWasm, signal);
  console.log("  - x = " + x.debug());

  console.log("\nCreating message id");
  const messageId = rlnWasm.WasmFr.fromUint(0);
  console.log("  - message id = " + messageId.debug());

  console.log("\nCreating RLN witness");
  let witness;
  try {
    witness = createWitness(
      rlnWasm,
      member,
      merkleProof,
      messageId,
      x,
      externalNullifier,
    );
  } catch (error) {
    console.error("Witness creation error:", error);
    return;
  }
  console.log("  - RLN witness created successfully");

  console.log("\nGenerating RLN proof");
  let rlnProof;
  try {
    rlnProof = rlnInstance.generateProof(witness);
  } catch (error) {
    console.error("Proof generation error:", error);
    return;
  }
  console.log("  - proof generated successfully");

  console.log("\nGetting RLN proof values");
  const proofValues = rlnProof.getValues();
  console.log("  - y = " + proofValues.y().debug());
  console.log("  - nullifier = " + proofValues.nullifier().debug());
  console.log("  - root = " + proofValues.root().debug());
  console.log("  - x = " + proofValues.x().debug());
  console.log(
    "  - external nullifier = " + proofValues.externalNullifier().debug(),
  );

  console.log("\nVerifying proof");
  let isValid;
  try {
    isValid = rlnInstance.verifyWithRoots(rlnProof, merkleProof.roots, x);
  } catch (error) {
    console.error("Proof verification error:", error);
    return;
  }
  if (isValid) {
    console.log("  - proof verified successfully");
  } else {
    console.log("Proof verification failed");
  }
}

main().catch(console.error);
