import {
  initRLN,
  createMember,
  computeMerkleProof,
  computeExternalNullifier,
  hashSignal,
  createWitness,
  debugUint8Array,
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

  console.log("\nWasmRLNWitnessInput serialization: WasmRLNWitnessInput <-> bytes");
  let serWitness;
  try {
    serWitness = witness.toBytesLE();
  } catch (error) {
    console.error("Witness serialization error:", error);
    return;
  }
  console.log("  - serialized witness = [" + debugUint8Array(serWitness) + "]");

  let deserWitness;
  try {
    deserWitness = rlnWasm.WasmRLNWitnessInput.fromBytesLE(serWitness);
  } catch (error) {
    console.error("Witness deserialization error:", error);
    return;
  }
  console.log("  - witness deserialized successfully");

  console.log("\nGenerating RLN proof from the deserialized witness");
  let rlnProof;
  try {
    rlnProof = rlnInstance.generateProof(deserWitness);
  } catch (error) {
    console.error("Proof generation error:", error);
    return;
  }
  console.log("  - proof generated successfully");

  console.log("\nWasmRLNProof serialization: WasmRLNProof <-> bytes");
  let serProof;
  try {
    serProof = rlnProof.toBytesLE();
  } catch (error) {
    console.error("Proof serialization error:", error);
    return;
  }
  console.log("  - serialized proof = [" + debugUint8Array(serProof) + "]");

  let deserProof;
  try {
    deserProof = rlnWasm.WasmRLNProof.fromBytesLE(serProof);
  } catch (error) {
    console.error("Proof deserialization error:", error);
    return;
  }
  console.log("  - proof deserialized successfully");

  console.log("\nVerifying the deserialized proof");
  let isValid;
  try {
    isValid = rlnInstance.verifyWithRoots(deserProof, merkleProof.roots, x);
  } catch (error) {
    console.error("Proof verification error:", error);
    return;
  }
  if (isValid) {
    console.log("  - deserialized proof verified successfully");
  } else {
    console.log("Deserialized proof verification failed");
  }
}

main().catch(console.error);
