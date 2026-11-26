// Proof for finding 20261125T233608-5210d6/2 (canonical F-17e8e7d1)
//
// Spec (Proof Generation): "Fails with `GenerateProofError` on witness/graph
// inconsistency or backend fault."
// Spec (WASM-Specific Notes): "Errors are returned as JavaScript strings that
// can be caught via try-catch blocks."
//
// `newWithParams(zkey, graph)` accepts a zkey and a graph that belong to two
// different circuits (Multi zkey, Single graph). `generateProof()` and
// `finishProof()` on that instance then do not fail with an error string: the
// Groth16 prover indexes out of bounds, the wasm module TRAPS, and JavaScript
// catches a `WebAssembly.RuntimeError: unreachable` object.
//
// One test per trapping call. A test fails by returning an `Err` whose text
// states the assertion.

#![cfg(target_arch = "wasm32")]
#![cfg(not(feature = "utils"))]

use js_sys::{Function, Uint8Array};
use rln_wasm::{
    wasm_hash_to_field_le, wasm_poseidon_hash_pair, VecWasmFr, WasmFr, WasmIdentityKeys, WasmRLN,
    WasmRLNMerkleProof, WasmRLNPartialWitnessInput, WasmRLNPoseidon2, WasmRLNWitnessInput,
};
use wasm_bindgen::prelude::*;
use wasm_bindgen_test::wasm_bindgen_test;

const ZKEY_SINGLE: &[u8] =
    include_bytes!("../../rln/resources/tree_depth_20/rln_single/rln_final.arkzkey");
const GRAPH_SINGLE: &[u8] =
    include_bytes!("../../rln/resources/tree_depth_20/rln_single/graph.bin");
const ZKEY_MULTI: &[u8] =
    include_bytes!("../../rln/resources/tree_depth_20/rln_multi/rln_final.arkzkey");
const ZKEY_POSEIDON2_MULTI: &[u8] =
    include_bytes!("../../rln/resources/tree_depth_20/rln_poseidon2_multi/rln_final.arkzkey");
const GRAPH_POSEIDON2_SINGLE: &[u8] =
    include_bytes!("../../rln/resources/tree_depth_20/rln_poseidon2_single/graph.bin");

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

fn assert_string_error(call: &str, outcome: String) -> Result<(), JsValue> {
    if outcome.starts_with("string: ") {
        return Ok(());
    }
    Err(JsValue::from_str(&format!(
        "assertion `left == right` failed: {call} on an instance whose zkey and graph come \
         from different circuits must fail with a JavaScript string error (spec: \"Fails \
         with `GenerateProofError` on witness/graph inconsistency or backend fault\"), but \
         the call trapped\n  left: \"{outcome}\"\n right: \"string: <error message>\""
    )))
}

fn u8a(bytes: &[u8]) -> Uint8Array {
    Uint8Array::from(bytes)
}

/// A structurally valid Single witness with a depth-20 Merkle path.
fn single_witness() -> WasmRLNWitnessInput {
    let identity = WasmIdentityKeys::generate_seeded(&u8a(b"seed"));
    let mut path_elements = VecWasmFr::new();
    for _ in 0..20 {
        path_elements.push(&WasmFr::zero());
    }
    let merkle_proof = WasmRLNMerkleProof::new(&path_elements, &u8a(&[0u8; 20]));
    let x = wasm_hash_to_field_le(&u8a(b"signal"));
    let external_nullifier = wasm_poseidon_hash_pair(&WasmFr::from_uint(1), &WasmFr::from_uint(2));
    WasmRLNWitnessInput::new_single(
        &identity.get_secret(),
        &WasmFr::from_uint(10),
        &WasmFr::zero(),
        &merkle_proof,
        &x,
        &external_nullifier,
    )
    .expect("the witness is structurally valid")
}

#[wasm_bindgen_test]
fn wasm_rln_generate_proof_traps_on_zkey_graph_mismatch() -> Result<(), JsValue> {
    let rln = WasmRLN::new_with_params(&u8a(ZKEY_MULTI), &u8a(GRAPH_SINGLE))
        .expect("newWithParams accepts a zkey and a graph of different circuits");
    let witness = single_witness();
    let outcome = call_from_js(move || to_js(rln.generate_proof(&witness)));
    assert_string_error("WasmRLN.generateProof", outcome)
}

#[wasm_bindgen_test]
fn wasm_rln_finish_proof_traps_on_zkey_graph_mismatch() -> Result<(), JsValue> {
    // A valid partial proof, made by a consistent Single instance.
    let good = WasmRLN::new_with_params(&u8a(ZKEY_SINGLE), &u8a(GRAPH_SINGLE)).unwrap();
    let witness = single_witness();
    let partial = good
        .generate_partial_proof(&WasmRLNPartialWitnessInput::from_witness(&witness))
        .expect("the consistent instance makes a partial proof");

    let rln = WasmRLN::new_with_params(&u8a(ZKEY_MULTI), &u8a(GRAPH_SINGLE))
        .expect("newWithParams accepts a zkey and a graph of different circuits");
    let outcome = call_from_js(move || to_js(rln.finish_proof(&partial, &witness)));
    assert_string_error("WasmRLN.finishProof", outcome)
}

#[wasm_bindgen_test]
fn wasm_rln_poseidon2_generate_proof_traps_on_zkey_graph_mismatch() -> Result<(), JsValue> {
    let rln =
        WasmRLNPoseidon2::new_with_params(&u8a(ZKEY_POSEIDON2_MULTI), &u8a(GRAPH_POSEIDON2_SINGLE))
            .expect("newWithParams accepts a zkey and a graph of different circuits");
    let witness = single_witness();
    let outcome = call_from_js(move || to_js(rln.generate_proof(&witness)));
    assert_string_error("WasmRLNPoseidon2.generateProof", outcome)
}

/// Control: a witness/graph inconsistency the core does check (tree depth 10
/// on a depth-20 circuit) is reported as a string, as the spec says.
#[wasm_bindgen_test]
fn control_wrong_tree_depth_is_a_string_error() -> Result<(), JsValue> {
    let rln = WasmRLN::new_with_params(&u8a(ZKEY_SINGLE), &u8a(GRAPH_SINGLE)).unwrap();
    let identity = WasmIdentityKeys::generate_seeded(&u8a(b"seed"));
    let mut path_elements = VecWasmFr::new();
    for _ in 0..10 {
        path_elements.push(&WasmFr::zero());
    }
    let merkle_proof = WasmRLNMerkleProof::new(&path_elements, &u8a(&[0u8; 10]));
    let witness = WasmRLNWitnessInput::new_single(
        &identity.get_secret(),
        &WasmFr::from_uint(10),
        &WasmFr::zero(),
        &merkle_proof,
        &WasmFr::one(),
        &WasmFr::one(),
    )
    .unwrap();
    let outcome = call_from_js(move || to_js(rln.generate_proof(&witness)));
    assert_string_error("control: WasmRLN.generateProof (wrong depth)", outcome)
}
