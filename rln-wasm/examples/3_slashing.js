import {
  initRLN,
  generateIdentity,
  buildMerkleProof,
  computeExternalNullifier,
  hashSignal,
  createWitness,
} from "./0_common.js";

async function main() {
  const env = await initRLN();
  const identity = generateIdentity(env);
  const merkleProof = buildMerkleProof(env, identity.rateCommitment);
  const externalNullifier = computeExternalNullifier(env);

  console.log("\nHashing first signal");
  const signal1 = new Uint8Array([
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0,
  ]);
  const x1 = hashSignal(env, signal1);
  console.log("  - x1 = " + x1.debug());

  console.log("\nCreating first message id");
  const messageId1 = env.rlnWasm.WasmFr.fromUint(0);
  console.log("  - message id = " + messageId1.debug());

  console.log("\nCreating first RLN witness");
  let witness1;
  try {
    witness1 = createWitness(
      env,
      identity,
      merkleProof,
      messageId1,
      x1,
      externalNullifier,
    );
  } catch (error) {
    console.error("First witness creation error:", error);
    return;
  }
  console.log("  - first RLN witness created successfully");

  console.log("\nGenerating first RLN proof");
  let rlnProof1;
  try {
    rlnProof1 = env.rlnInstance.generateProof(witness1);
  } catch (error) {
    console.error("Proof generation error:", error);
    return;
  }
  const proofValues1 = rlnProof1.getValues();
  console.log("  - first proof generated successfully");

  console.log("\nVerifying first proof");
  let isValid1;
  try {
    isValid1 = env.rlnInstance.verifyWithRoots(
      rlnProof1,
      merkleProof.roots,
      x1,
    );
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
  const x2 = hashSignal(env, signal2);
  console.log("  - x2 = " + x2.debug());

  console.log("\nCreating second message with the same id");
  const messageId2 = env.rlnWasm.WasmFr.fromUint(0);
  console.log("  - message id = " + messageId2.debug());

  console.log("\nCreating second RLN witness");
  let witness2;
  try {
    witness2 = createWitness(
      env,
      identity,
      merkleProof,
      messageId2,
      x2,
      externalNullifier,
    );
  } catch (error) {
    console.error("Second witness creation error:", error);
    return;
  }
  console.log("  - second RLN witness created successfully");

  console.log("\nGenerating second RLN proof");
  let rlnProof2;
  try {
    rlnProof2 = env.rlnInstance.generateProof(witness2);
  } catch (error) {
    console.error("Second proof generation error:", error);
    return;
  }
  const proofValues2 = rlnProof2.getValues();
  console.log("  - second proof generated successfully");

  console.log("\nVerifying second proof");
  let isValid2;
  try {
    isValid2 = env.rlnInstance.verifyWithRoots(
      rlnProof2,
      merkleProof.roots,
      x2,
    );
  } catch (error) {
    console.error("Proof verification error:", error);
    return;
  }
  if (isValid2) {
    console.log("  - second proof verified successfully");

    console.log("\nRecovering identity secret");
    let recoveredSecret;
    try {
      recoveredSecret = env.rlnWasm.WasmRLNProofValues.recoverIdSecret(
        proofValues1,
        proofValues2,
      );
    } catch (error) {
      console.error("Identity recovery error:", error);
      return;
    }
    console.log("  - recovered secret = " + recoveredSecret.debug());
    console.log("  - identity secret = " + identity.identitySecret.debug());
    console.log("  - identity recovered successfully");
  } else {
    console.log("Second proof verification failed");
  }
}

main().catch(console.error);
