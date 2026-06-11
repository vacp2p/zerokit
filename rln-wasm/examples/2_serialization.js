import {
  initRLN,
  createMember,
  buildMerkleProof,
  computeExternalNullifier,
  hashSignal,
  createWitness,
  debugUint8Array,
} from "./0_common.js";

function roundtrip(typeName, subject, value, fromBytesLE, show) {
  const errorSubject = subject.charAt(0).toUpperCase() + subject.slice(1);
  console.log("\n" + typeName + " serialization: " + typeName + " <-> bytes");
  let serialized;
  try {
    serialized = value.toBytesLE();
  } catch (error) {
    console.error(errorSubject + " serialization error:", error);
    return null;
  }
  console.log(
    "  - serialized " + subject + " = [" + debugUint8Array(serialized) + "]",
  );
  let deserialized;
  try {
    deserialized = fromBytesLE(serialized);
  } catch (error) {
    console.error(errorSubject + " deserialization error:", error);
    return null;
  }
  console.log("  - " + show(deserialized));
  return deserialized;
}

async function main() {
  const env = await initRLN();
  const { rlnWasm, rlnInstance } = env;
  const member = createMember(env);
  const merkleProof = buildMerkleProof(env, member.rateCommitment);
  const externalNullifier = computeExternalNullifier(env);

  console.log("\nHashing signal");
  const signal = new Uint8Array([
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0,
  ]);
  const x = hashSignal(env, signal);
  console.log("  - x = " + x.debug());

  console.log("\nCreating message id");
  const messageId = rlnWasm.WasmFr.fromUint(0);
  console.log("  - message id = " + messageId.debug());

  console.log("\nCreating RLN witness");
  let witness;
  try {
    witness = createWitness(
      env,
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
  const proofValues = rlnProof.getValues();
  console.log("  - proof generated successfully");

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

  roundtrip(
    "WasmFr",
    "rate commitment",
    member.rateCommitment,
    rlnWasm.WasmFr.fromBytesLE,
    (value) => "deserialized rate commitment = " + value.debug(),
  );

  roundtrip(
    "Identity",
    "identity",
    member.identity,
    rlnWasm.Identity.fromBytesLE,
    (value) =>
      "deserialized identity = [" +
      value.getSecretHash().debug() +
      ", " +
      value.getCommitment().debug() +
      "]",
  );

  roundtrip(
    "VecWasmFr",
    "path elements",
    merkleProof.pathElements,
    rlnWasm.VecWasmFr.fromBytesLE,
    (value) => "deserialized path elements = " + value.debug(),
  );

  console.log("\nUint8Array serialization: Uint8Array <-> bytes");
  let serPathIndex;
  try {
    serPathIndex = rlnWasm.Uint8ArrayUtils.toBytesLE(
      merkleProof.identityPathIndex,
    );
  } catch (error) {
    console.error("Path index serialization error:", error);
    return;
  }
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

  roundtrip(
    "WasmRLNWitnessInput",
    "witness",
    witness,
    rlnWasm.WasmRLNWitnessInput.fromBytesLE,
    () => "witness deserialized successfully",
  );

  roundtrip(
    "WasmRLNProof",
    "proof",
    rlnProof,
    rlnWasm.WasmRLNProof.fromBytesLE,
    () => "proof deserialized successfully",
  );

  const deserProofValues = roundtrip(
    "WasmRLNProofValues",
    "proof values",
    proofValues,
    rlnWasm.WasmRLNProofValues.fromBytesLE,
    () => "proof values deserialized successfully",
  );
  if (deserProofValues) {
    console.log(
      "  - deserialized external nullifier = " +
        deserProofValues.externalNullifier().debug(),
    );
  }

  roundtrip(
    "WasmRLNPartialWitnessInput",
    "partial witness",
    partialWitness,
    rlnWasm.WasmRLNPartialWitnessInput.fromBytesLE,
    () => "partial witness deserialized successfully",
  );

  roundtrip(
    "WasmRLNPartialProof",
    "partial proof",
    partialProof,
    rlnWasm.WasmRLNPartialProof.fromBytesLE,
    () => "partial proof deserialized successfully",
  );
}

main().catch(console.error);
