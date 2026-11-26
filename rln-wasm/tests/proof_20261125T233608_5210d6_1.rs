// Proof for finding 20261125T233608-5210d6/1 (canonical F-b9d0b87f)
//
// Spec (WASM-Specific Notes): "Errors are returned as JavaScript strings that
// can be caught via try-catch blocks."
// Spec (Serialization): "Deserialization enforces the same structural
// invariants as construction and returns typed validation errors through
// `SerializationError`."
//
// A `fromBytes*` call on a short buffer whose vector length prefix is forged
// (2^26 elements) does not return an error string. The deserializer panics
// with `capacity overflow`, the wasm module TRAPS, and the JavaScript caller
// catches a `WebAssembly.RuntimeError: unreachable` object.
//
// One test per trapping call. Each call is made from JavaScript inside
// try/catch, as a JS consumer would make it. A test fails by returning an
// `Err` whose text states the assertion, so the failure line is not buried
// under the stack trace of the trap.

#![cfg(target_arch = "wasm32")]
#![cfg(not(feature = "utils"))]

use js_sys::{Function, Uint8Array};
use rln_wasm::{
    wasm_hash_to_field_le, wasm_poseidon_hash_pair, VecWasmFr, WasmFr, WasmIdentityKeys, WasmRLN,
    WasmRLNMerkleProof, WasmRLNPartialWitnessInput, WasmRLNProof, WasmRLNProofValues,
    WasmRLNWitnessInput, WasmUint8ArrayUtils,
};
use wasm_bindgen::prelude::*;
use wasm_bindgen_test::wasm_bindgen_test;

const ZKEY_SINGLE: &[u8] =
    include_bytes!("../../rln/resources/tree_depth_20/rln_single/rln_final.arkzkey");
const GRAPH_SINGLE: &[u8] =
    include_bytes!("../../rln/resources/tree_depth_20/rln_single/graph.bin");

/// 2^26 elements of 32 bytes is 2^31 bytes: more than a wasm32 allocation can hold.
const FORGED_LEN: u64 = 1 << 26;

/// Calls `f` from JavaScript inside try/catch. Returns "ok" when it returned,
/// otherwise "<typeof thrown value>: <thrown value as text>".
fn call_from_js(f: impl FnMut() -> Result<JsValue, JsValue> + 'static) -> String {
    // Stack frames of the trap and of the failing test add some 5 kB per test
    // and push the assertion line out of the tail of the output. Only the
    // frames are dropped; the panic message and the assertion stay.
    let _ = Function::new_no_args("Error.stackTraceLimit = 0;").call0(&JsValue::NULL);
    let helper = Function::new_with_args(
        "f",
        "try { f(); return 'ok'; } catch (e) { return typeof e + ': ' + String(e); }",
    );
    let cb = Closure::<dyn FnMut() -> Result<JsValue, JsValue>>::new(f);
    helper
        .call1(&JsValue::NULL, cb.as_ref())
        .expect("helper itself must not throw")
        .as_string()
        .expect("helper returns a string")
}

fn to_js<T>(result: Result<T, String>) -> Result<JsValue, JsValue> {
    result.map(|_| JsValue::NULL).map_err(JsValue::from)
}

/// The spec sentence under test: a malformed buffer is an error, and a WASM
/// error is a JavaScript string.
fn assert_string_error(call: &str, outcome: String) -> Result<(), JsValue> {
    if outcome.starts_with("string: ") {
        return Ok(());
    }
    Err(JsValue::from_str(&format!(
        "assertion `left == right` failed: {call} on a buffer with a forged length prefix \
         must throw a JavaScript string (spec: \"Errors are returned as JavaScript \
         strings\"), but the call trapped\n  left: \"{outcome}\"\n right: \"string: <error \
         message>\""
    )))
}

fn u8a(bytes: &[u8]) -> Uint8Array {
    Uint8Array::from(bytes)
}

/// Replaces the first occurrence of `needle` in `bytes`.
fn replace_first(bytes: &[u8], needle: &[u8], with: &[u8]) -> Vec<u8> {
    let pos = bytes
        .windows(needle.len())
        .position(|window| window == needle)
        .expect("the serialized value carries the length prefix 20");
    let mut out = bytes.to_vec();
    out[pos..pos + needle.len()].copy_from_slice(with);
    out
}

fn forge_le(valid: &[u8]) -> Vec<u8> {
    replace_first(valid, &20u64.to_le_bytes(), &FORGED_LEN.to_le_bytes())
}

fn forge_be(valid: &[u8]) -> Vec<u8> {
    replace_first(valid, &20u64.to_be_bytes(), &FORGED_LEN.to_be_bytes())
}

/// A depth-20 Merkle proof: its serialization starts with the length prefix 20.
fn merkle_proof() -> WasmRLNMerkleProof {
    let mut path_elements = VecWasmFr::new();
    for _ in 0..20 {
        path_elements.push(&WasmFr::zero());
    }
    WasmRLNMerkleProof::new(&path_elements, &u8a(&[0u8; 20]))
}

fn witness() -> WasmRLNWitnessInput {
    let identity = WasmIdentityKeys::generate_seeded(&u8a(b"seed"));
    let x = wasm_hash_to_field_le(&u8a(b"signal"));
    let external_nullifier = wasm_poseidon_hash_pair(&WasmFr::from_uint(1), &WasmFr::from_uint(2));
    WasmRLNWitnessInput::new_single(
        &identity.get_secret(),
        &WasmFr::from_uint(10),
        &WasmFr::zero(),
        &merkle_proof(),
        &x,
        &external_nullifier,
    )
    .expect("the witness is structurally valid")
}

/// Multi-mode proof values: mode tag 1, then the forged length prefix of the
/// first vector and one element.
fn forged_multi_values(len_prefix: [u8; 8]) -> Vec<u8> {
    let mut bytes = vec![1u8];
    bytes.extend_from_slice(&len_prefix);
    bytes.extend_from_slice(&[0u8; 32]);
    bytes
}

/// The 128 bytes of a real Groth16 proof, followed by forged Multi proof values.
fn forged_rln_proof(len_prefix: [u8; 8]) -> Vec<u8> {
    let rln = WasmRLN::new_with_params(&u8a(ZKEY_SINGLE), &u8a(GRAPH_SINGLE)).unwrap();
    let proof = rln.generate_proof(&witness()).unwrap();
    let proof_bytes = proof.to_bytes_le().unwrap().to_vec();
    let values_len = proof.get_values().to_bytes_le().unwrap().to_vec().len();
    let mut bytes = proof_bytes[..proof_bytes.len() - values_len].to_vec();
    bytes.extend_from_slice(&forged_multi_values(len_prefix));
    bytes
}

// VecWasmFr

#[wasm_bindgen_test]
fn vec_wasm_fr_from_bytes_le_traps() -> Result<(), JsValue> {
    let mut bytes = FORGED_LEN.to_le_bytes().to_vec();
    bytes.extend_from_slice(&[0u8; 32]);
    let outcome = call_from_js(move || to_js(VecWasmFr::from_bytes_le(&u8a(&bytes))));
    assert_string_error("VecWasmFr.fromBytesLE", outcome)
}

#[wasm_bindgen_test]
fn vec_wasm_fr_from_bytes_be_traps() -> Result<(), JsValue> {
    let mut bytes = FORGED_LEN.to_be_bytes().to_vec();
    bytes.extend_from_slice(&[0u8; 32]);
    let outcome = call_from_js(move || to_js(VecWasmFr::from_bytes_be(&u8a(&bytes))));
    assert_string_error("VecWasmFr.fromBytesBE", outcome)
}

// WasmUint8ArrayUtils

#[wasm_bindgen_test]
fn uint8array_utils_from_bytes_le_traps() -> Result<(), JsValue> {
    let mut bytes = (1u64 << 31).to_le_bytes().to_vec();
    bytes.extend_from_slice(&[0u8; 4]);
    let outcome = call_from_js(move || to_js(WasmUint8ArrayUtils::from_bytes_le(&u8a(&bytes))));
    assert_string_error("WasmUint8ArrayUtils.fromBytesLE", outcome)
}

#[wasm_bindgen_test]
fn uint8array_utils_from_bytes_be_traps() -> Result<(), JsValue> {
    let mut bytes = (1u64 << 31).to_be_bytes().to_vec();
    bytes.extend_from_slice(&[0u8; 4]);
    let outcome = call_from_js(move || to_js(WasmUint8ArrayUtils::from_bytes_be(&u8a(&bytes))));
    assert_string_error("WasmUint8ArrayUtils.fromBytesBE", outcome)
}

// WasmRLNMerkleProof

#[wasm_bindgen_test]
fn merkle_proof_from_bytes_le_traps() -> Result<(), JsValue> {
    let bytes = forge_le(&merkle_proof().to_bytes_le().unwrap().to_vec());
    let outcome = call_from_js(move || to_js(WasmRLNMerkleProof::from_bytes_le(&u8a(&bytes))));
    assert_string_error("WasmRLNMerkleProof.fromBytesLE", outcome)
}

#[wasm_bindgen_test]
fn merkle_proof_from_bytes_be_traps() -> Result<(), JsValue> {
    let bytes = forge_be(&merkle_proof().to_bytes_be().unwrap().to_vec());
    let outcome = call_from_js(move || to_js(WasmRLNMerkleProof::from_bytes_be(&u8a(&bytes))));
    assert_string_error("WasmRLNMerkleProof.fromBytesBE", outcome)
}

// WasmRLNWitnessInput

#[wasm_bindgen_test]
fn witness_input_from_bytes_le_traps() -> Result<(), JsValue> {
    let bytes = forge_le(&witness().to_bytes_le().unwrap().to_vec());
    let outcome = call_from_js(move || to_js(WasmRLNWitnessInput::from_bytes_le(&u8a(&bytes))));
    assert_string_error("WasmRLNWitnessInput.fromBytesLE", outcome)
}

#[wasm_bindgen_test]
fn witness_input_from_bytes_be_traps() -> Result<(), JsValue> {
    let bytes = forge_be(&witness().to_bytes_be().unwrap().to_vec());
    let outcome = call_from_js(move || to_js(WasmRLNWitnessInput::from_bytes_be(&u8a(&bytes))));
    assert_string_error("WasmRLNWitnessInput.fromBytesBE", outcome)
}

// WasmRLNPartialWitnessInput

#[wasm_bindgen_test]
fn partial_witness_input_from_bytes_le_traps() -> Result<(), JsValue> {
    let partial = WasmRLNPartialWitnessInput::from_witness(&witness());
    let bytes = forge_le(&partial.to_bytes_le().unwrap().to_vec());
    let outcome =
        call_from_js(move || to_js(WasmRLNPartialWitnessInput::from_bytes_le(&u8a(&bytes))));
    assert_string_error("WasmRLNPartialWitnessInput.fromBytesLE", outcome)
}

#[wasm_bindgen_test]
fn partial_witness_input_from_bytes_be_traps() -> Result<(), JsValue> {
    let partial = WasmRLNPartialWitnessInput::from_witness(&witness());
    let bytes = forge_be(&partial.to_bytes_be().unwrap().to_vec());
    let outcome =
        call_from_js(move || to_js(WasmRLNPartialWitnessInput::from_bytes_be(&u8a(&bytes))));
    assert_string_error("WasmRLNPartialWitnessInput.fromBytesBE", outcome)
}

// WasmRLNProofValues (the payload a verifier receives from a peer)

#[wasm_bindgen_test]
fn proof_values_from_bytes_le_traps() -> Result<(), JsValue> {
    let bytes = forged_multi_values(FORGED_LEN.to_le_bytes());
    let outcome = call_from_js(move || to_js(WasmRLNProofValues::from_bytes_le(&u8a(&bytes))));
    assert_string_error("WasmRLNProofValues.fromBytesLE", outcome)
}

#[wasm_bindgen_test]
fn proof_values_from_bytes_be_traps() -> Result<(), JsValue> {
    let bytes = forged_multi_values(FORGED_LEN.to_be_bytes());
    let outcome = call_from_js(move || to_js(WasmRLNProofValues::from_bytes_be(&u8a(&bytes))));
    assert_string_error("WasmRLNProofValues.fromBytesBE", outcome)
}

// WasmRLNProof (the payload a verifier receives from a peer)

#[wasm_bindgen_test]
fn rln_proof_from_bytes_le_traps() -> Result<(), JsValue> {
    let bytes = forged_rln_proof(FORGED_LEN.to_le_bytes());
    let outcome = call_from_js(move || to_js(WasmRLNProof::from_bytes_le(&u8a(&bytes))));
    assert_string_error("WasmRLNProof.fromBytesLE", outcome)
}

#[wasm_bindgen_test]
fn rln_proof_from_bytes_mixed_traps() -> Result<(), JsValue> {
    let bytes = forged_rln_proof(FORGED_LEN.to_be_bytes());
    let outcome = call_from_js(move || to_js(WasmRLNProof::from_bytes_mixed(&u8a(&bytes))));
    assert_string_error("WasmRLNProof.fromBytesMixed", outcome)
}

/// Control: an ordinary malformed buffer (truncated) does follow the spec, so
/// the harness above can tell a string error from a trap.
#[wasm_bindgen_test]
fn control_truncated_buffer_is_a_string_error() -> Result<(), JsValue> {
    let outcome = call_from_js(|| to_js(VecWasmFr::from_bytes_le(&u8a(&[1u8, 0, 0]))));
    assert_string_error("control: VecWasmFr.fromBytesLE (truncated)", outcome)
}
