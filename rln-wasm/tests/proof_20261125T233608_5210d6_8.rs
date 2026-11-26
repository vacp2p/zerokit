// Proof for finding 20261125T233608-5210d6/8
//
// Spec (Proof Generation): "`finish_proof(partial_proof, witness)` - Second
// step: completes the partial proof with the full witness and returns
// `(proof, proof_values)`." and "`generate_proof(witness)` ... Fails with
// `GenerateProofError` on witness/graph inconsistency or backend fault."
// Spec (WASM-Specific Notes): "Two-step proving: `generatePartialProof()` /
// `finishProof()` with `WasmRLNPartialWitnessInput` and `WasmRLNPartialProof`".
//
// The spec does not say what `finishProof()` does when the partial proof was
// precomputed from other inputs (another identity, message limit or Merkle
// path) than the full witness carries. The code does not compare them: the
// call returns successfully with the proof values of the witness and a Groth16
// proof that no verifier accepts. Nothing tells the caller that the returned
// proof is useless.
//
// These calls do not trap. The test fails on the comparison of what
// `finishProof()` returned with the two outcomes a caller can act on: an error
// string, or a proof that verifies.

#![cfg(target_arch = "wasm32")]
#![cfg(not(feature = "utils"))]

use js_sys::{Function, Uint8Array};
use rln_wasm::{
    wasm_hash_to_field_le, wasm_poseidon_hash_pair, VecWasmFr, WasmFr, WasmIdentityKeys, WasmRLN,
    WasmRLNMerkleProof, WasmRLNPartialWitnessInput, WasmRLNWitnessInput,
};
use wasm_bindgen::prelude::*;
use wasm_bindgen_test::wasm_bindgen_test;

const ZKEY_SINGLE: &[u8] =
    include_bytes!("../../rln/resources/tree_depth_20/rln_single/rln_final.arkzkey");
const GRAPH_SINGLE: &[u8] =
    include_bytes!("../../rln/resources/tree_depth_20/rln_single/graph.bin");

fn u8a(bytes: &[u8]) -> Uint8Array {
    Uint8Array::from(bytes)
}

fn merkle_proof() -> WasmRLNMerkleProof {
    let mut path_elements = VecWasmFr::new();
    for _ in 0..20 {
        path_elements.push(&WasmFr::zero());
    }
    WasmRLNMerkleProof::new(&path_elements, &u8a(&[0u8; 20]))
}

fn witness(seed: &[u8], user_message_limit: u32) -> WasmRLNWitnessInput {
    let identity = WasmIdentityKeys::generate_seeded(&u8a(seed));
    let x = wasm_hash_to_field_le(&u8a(b"signal"));
    let external_nullifier = wasm_poseidon_hash_pair(&WasmFr::from_uint(1), &WasmFr::from_uint(2));
    WasmRLNWitnessInput::new_single(
        &identity.get_secret(),
        &WasmFr::from_uint(user_message_limit),
        &WasmFr::zero(),
        &merkle_proof(),
        &x,
        &external_nullifier,
    )
    .expect("the witness is structurally valid")
}

fn instance() -> WasmRLN {
    WasmRLN::new_with_params(&u8a(ZKEY_SINGLE), &u8a(GRAPH_SINGLE)).unwrap()
}

/// What `finishProof(partial_of(partial_from), full)` gives the caller.
fn finish(partial_from: &WasmRLNWitnessInput, full: &WasmRLNWitnessInput) -> String {
    let rln = instance();
    let partial_proof = rln
        .generate_partial_proof(&WasmRLNPartialWitnessInput::from_witness(partial_from))
        .expect("the partial proof is generated");
    match rln.finish_proof(&partial_proof, full) {
        Err(err) => format!("error string: {err}"),
        Ok(proof) => format!(
            "returned a proof; verify() of it = {:?}",
            rln.verify(&proof)
        ),
    }
}

/// A caller can act on an error, or on a proof that verifies. A returned proof
/// that verifies as false is neither.
fn assert_error_or_valid(case: &str, got: String) -> Result<(), JsValue> {
    // Only the stack frames of the failing test are dropped from the output.
    let _ = Function::new_no_args("Error.stackTraceLimit = 0;").call0(&JsValue::NULL);
    if got.starts_with("error string: ") || got == "returned a proof; verify() of it = Ok(true)" {
        return Ok(());
    }
    Err(JsValue::from_str(&format!(
        "assertion `left == right` failed: WasmRLN.finishProof with a partial proof precomputed \
         for {case} must fail with an error string or return a proof that verifies, not \
         silently return an invalid proof\n  left: \"{got}\"\n right: \"error string: <message>\""
    )))
}

#[wasm_bindgen_test]
fn finish_proof_with_partial_proof_of_another_identity() -> Result<(), JsValue> {
    let got = finish(&witness(b"identity A", 10), &witness(b"identity B", 10));
    assert_error_or_valid("another identity", got)
}

#[wasm_bindgen_test]
fn finish_proof_with_partial_proof_of_another_message_limit() -> Result<(), JsValue> {
    let got = finish(&witness(b"identity A", 10), &witness(b"identity A", 20));
    assert_error_or_valid("another user_message_limit", got)
}

/// Control: the partial proof of the same inputs is completed into a proof
/// that verifies.
#[wasm_bindgen_test]
fn control_finish_proof_with_matching_partial_proof() -> Result<(), JsValue> {
    let got = finish(&witness(b"identity A", 10), &witness(b"identity A", 10));
    assert_eq!(got, "returned a proof; verify() of it = Ok(true)");
    Ok(())
}
