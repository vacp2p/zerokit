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

  console.log("\nCreating partial witness from witness fields");
  let partialWitness;
  try {
    partialWitness = rlnWasm.WasmRLNPartialWitnessInput.new(
      witness.getIdentitySecret(),
      witness.getUserMessageLimit(),
      witness.getPathElements(),
      witness.getIdentityPathIndex(),
    );
  } catch (error) {
    console.error("Partial witness creation error:", error);
    return;
  }
  console.log("  - partial witness created successfully");

  console.log("\nGenerating partial ZK proof");
  let partialProof;
  try {
    partialProof = rlnInstance.generatePartialProof(partialWitness);
  } catch (error) {
    console.error("Partial proof generation error:", error);
    return;
  }
  console.log("  - partial proof generated successfully");

  console.log("\nFinishing proof with full witness");
  let fullProof;
  try {
    fullProof = rlnInstance.finishProof(partialProof, witness);
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
      merkleProof.roots,
      x,
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
