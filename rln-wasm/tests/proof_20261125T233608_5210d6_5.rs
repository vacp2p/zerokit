// Proof for finding 20261125T233608-5210d6/5
//
// Spec (Proof Verification): "All verification methods return `Result<bool>`.
// The `Ok(bool)` value is the zkSNARK verification verdict: an invalid proof
// is reported as `Ok(false)`, not as an error. `Err` is reserved for
// caller-input mismatch (`InvalidSignal`, `InvalidRoot`) and backend faults."
// "The FFI and WASM boundaries preserve this shape: [...] a WASM `false`
// return [is a] real "proof invalid" verdict, not [an error]."
//
// A proof of the other circuit mode is an invalid proof for this instance. It
// arrives as bytes from a peer, deserializes cleanly, and then `verify()`,
// `verifyWithSignal()` and `verifyWithRoots()` do not return `false`: they
// throw the string `Synthesis error: malformed verifying key`.
//
// These calls do not trap; each test fails on the comparison of the returned
// value with the `Ok(false)` verdict the spec names.

#![cfg(target_arch = "wasm32")]
#![cfg(not(feature = "utils"))]

use js_sys::{Function, Uint8Array};
use rln_wasm::{
    wasm_hash_to_field_le, wasm_poseidon_hash_pair, VecWasmFr, WasmFr, WasmIdentityKeys, WasmRLN,
    WasmRLNMerkleProof, WasmRLNProof, WasmRLNWitnessInput,
};
use wasm_bindgen::prelude::*;
use wasm_bindgen_test::wasm_bindgen_test;

const ZKEY_SINGLE: &[u8] =
    include_bytes!("../../rln/resources/tree_depth_20/rln_single/rln_final.arkzkey");
const GRAPH_SINGLE: &[u8] =
    include_bytes!("../../rln/resources/tree_depth_20/rln_single/graph.bin");
const ZKEY_MULTI: &[u8] =
    include_bytes!("../../rln/resources/tree_depth_20/rln_multi/rln_final.arkzkey");
const GRAPH_MULTI: &[u8] = include_bytes!("../../rln/resources/tree_depth_20/rln_multi/graph.bin");

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

fn signal() -> WasmFr {
    wasm_hash_to_field_le(&u8a(b"signal"))
}

fn single_instance() -> WasmRLN {
    WasmRLN::new_with_params(&u8a(ZKEY_SINGLE), &u8a(GRAPH_SINGLE)).unwrap()
}

fn multi_instance() -> WasmRLN {
    WasmRLN::new_with_params(&u8a(ZKEY_MULTI), &u8a(GRAPH_MULTI)).unwrap()
}

/// A valid Single-mode proof, as the bytes a peer would send.
fn single_proof_bytes() -> Uint8Array {
    let identity = WasmIdentityKeys::generate_seeded(&u8a(b"seed"));
    let external_nullifier = wasm_poseidon_hash_pair(&WasmFr::from_uint(1), &WasmFr::from_uint(2));
    let witness = WasmRLNWitnessInput::new_single(
        &identity.get_secret(),
        &WasmFr::from_uint(10),
        &WasmFr::zero(),
        &merkle_proof(),
        &signal(),
        &external_nullifier,
    )
    .unwrap();
    let rln = single_instance();
    let proof = rln.generate_proof(&witness).unwrap();
    assert_eq!(rln.verify(&proof), Ok(true), "the Single proof is valid on its own circuit");
    proof.to_bytes_le().unwrap()
}

/// A valid Multi-mode proof, as the bytes a peer would send.
fn multi_proof_bytes() -> Uint8Array {
    let identity = WasmIdentityKeys::generate_seeded(&u8a(b"seed"));
    let external_nullifier = wasm_poseidon_hash_pair(&WasmFr::from_uint(1), &WasmFr::from_uint(2));
    let mut message_ids = VecWasmFr::new();
    for i in 0..4 {
        message_ids.push(&WasmFr::from_uint(i));
    }
    let witness = WasmRLNWitnessInput::new_multi(
        &identity.get_secret(),
        &WasmFr::from_uint(10),
        &message_ids,
        &merkle_proof(),
        &signal(),
        &external_nullifier,
        &u8a(&[1, 1, 0, 0]),
    )
    .unwrap();
    let rln = multi_instance();
    let proof = rln.generate_proof(&witness).unwrap();
    assert_eq!(rln.verify(&proof), Ok(true), "the Multi proof is valid on its own circuit");
    proof.to_bytes_le().unwrap()
}

/// The spec sentence under test: an invalid proof is `Ok(false)`, not an error.
fn assert_invalid_verdict(call: &str, got: Result<bool, String>) -> Result<(), JsValue> {
    // Only the stack frames of the failing test are dropped from the output.
    let _ = Function::new_no_args("Error.stackTraceLimit = 0;").call0(&JsValue::NULL);
    if got == Ok(false) {
        return Ok(());
    }
    Err(JsValue::from_str(&format!(
        "assertion `left == right` failed: {call} on a proof of the other circuit mode must \
         return the verdict false (spec: \"an invalid proof is reported as `Ok(false)`, not \
         as an error\")\n  left: {got:?}\n right: Ok(false)"
    )))
}

#[wasm_bindgen_test]
fn verify_multi_proof_on_single_instance_is_false() -> Result<(), JsValue> {
    let proof = WasmRLNProof::from_bytes_le(&multi_proof_bytes())
        .expect("the peer's Multi proof deserializes");
    let got = single_instance().verify(&proof);
    assert_invalid_verdict("WasmRLN.verify", got)
}

#[wasm_bindgen_test]
fn verify_with_signal_multi_proof_on_single_instance_is_false() -> Result<(), JsValue> {
    let proof = WasmRLNProof::from_bytes_le(&multi_proof_bytes())
        .expect("the peer's Multi proof deserializes");
    let got = single_instance().verify_with_signal(&proof, &signal());
    assert_invalid_verdict("WasmRLN.verifyWithSignal", got)
}

#[wasm_bindgen_test]
fn verify_with_roots_multi_proof_on_single_instance_is_false() -> Result<(), JsValue> {
    let proof = WasmRLNProof::from_bytes_le(&multi_proof_bytes())
        .expect("the peer's Multi proof deserializes");
    let mut roots = VecWasmFr::new();
    roots.push(&proof.get_values().root());
    let got = single_instance().verify_with_roots(&proof, &roots, &signal());
    assert_invalid_verdict("WasmRLN.verifyWithRoots", got)
}

#[wasm_bindgen_test]
fn verify_single_proof_on_multi_instance_is_false() -> Result<(), JsValue> {
    let proof = WasmRLNProof::from_bytes_le(&single_proof_bytes())
        .expect("the peer's Single proof deserializes");
    let got = multi_instance().verify(&proof);
    assert_invalid_verdict("WasmRLN.verify", got)
}

/// Control: a proof of the right mode whose values were altered is reported
/// as the verdict false, as the spec says.
#[wasm_bindgen_test]
fn control_tampered_proof_is_false() -> Result<(), JsValue> {
    let mut bytes = single_proof_bytes().to_vec();
    let len = bytes.len();
    bytes[len - 40] ^= 1;
    let proof = WasmRLNProof::from_bytes_le(&u8a(&bytes)).expect("still a canonical encoding");
    let got = single_instance().verify(&proof);
    assert_invalid_verdict("control: WasmRLN.verify (tampered values)", got)
}
