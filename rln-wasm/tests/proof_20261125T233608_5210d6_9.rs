// Proof for finding 20261125T233608-5210d6/9
//
// Spec (Proof Modes): "`message_ids` and `selector_used` MUST match it in
// length, with the boolean `selector_used` vector marking the active slots."
// Spec (Serialization): "Deserialization enforces the same structural
// invariants as construction".
// Spec (WASM-Specific Notes): "Witness input uses
// `WasmRLNWitnessInput.newSingle()` / `newMulti()`". The spec does not say how
// the boolean vector crosses the WASM boundary.
//
// `newMulti()` takes `selector_used` as a `Uint8Array` and turns every
// non-zero byte into `true`. A byte that is not a boolean (2, 255) is accepted
// silently, while the deserializers of the same witness refuse it. The two
// ways of building one witness therefore disagree on what a selector is.
//
// These calls do not trap. The first test fails on the comparison of the
// result of `newMulti()` with an error.

#![cfg(target_arch = "wasm32")]
#![cfg(not(feature = "utils"))]

use js_sys::{Function, Uint8Array};
use rln_wasm::{
    wasm_hash_to_field_le, wasm_poseidon_hash_pair, VecWasmFr, WasmFr, WasmIdentityKeys,
    WasmRLNMerkleProof, WasmRLNWitnessInput,
};
use wasm_bindgen::prelude::*;
use wasm_bindgen_test::wasm_bindgen_test;

fn u8a(bytes: &[u8]) -> Uint8Array {
    Uint8Array::from(bytes)
}

fn new_multi(selector_used: &[u8]) -> Result<WasmRLNWitnessInput, String> {
    let identity = WasmIdentityKeys::generate_seeded(&u8a(b"seed"));
    let mut path_elements = VecWasmFr::new();
    for _ in 0..20 {
        path_elements.push(&WasmFr::zero());
    }
    let merkle_proof = WasmRLNMerkleProof::new(&path_elements, &u8a(&[0u8; 20]));
    let mut message_ids = VecWasmFr::new();
    for i in 0..4 {
        message_ids.push(&WasmFr::from_uint(i));
    }
    WasmRLNWitnessInput::new_multi(
        &identity.get_secret(),
        &WasmFr::from_uint(10),
        &message_ids,
        &merkle_proof,
        &wasm_hash_to_field_le(&u8a(b"signal")),
        &wasm_poseidon_hash_pair(&WasmFr::from_uint(1), &WasmFr::from_uint(2)),
        &u8a(selector_used),
    )
}

fn describe(result: Result<WasmRLNWitnessInput, String>) -> String {
    match result {
        Err(err) => format!("error string: {err}"),
        Ok(witness) => format!(
            "accepted; getSelectorUsed() = {:?}",
            witness.get_selector_used().map(|bytes| bytes.to_vec())
        ),
    }
}

#[wasm_bindgen_test]
fn new_multi_refuses_a_selector_byte_that_is_not_a_boolean() -> Result<(), JsValue> {
    // Only the stack frames of the failing test are dropped from the output.
    let _ = Function::new_no_args("Error.stackTraceLimit = 0;").call0(&JsValue::NULL);
    let got = describe(new_multi(&[2, 255, 0, 0]));
    if got.starts_with("error string: ") {
        return Ok(());
    }
    Err(JsValue::from_str(&format!(
        "assertion `left == right` failed: WasmRLNWitnessInput.newMulti with selector_used = \
         [2, 255, 0, 0] must refuse the bytes that are not booleans, as the deserializers of \
         the same witness do, not silently read them as true\n  left: \"{got}\"\n right: \
         \"error string: <message>\""
    )))
}

/// Control 1: 0 / 1 bytes are accepted and read back unchanged.
/// Control 2: the deserializers refuse the byte 2 in the same position, in
/// both encodings, so construction is the looser of the two paths.
#[wasm_bindgen_test]
fn control_deserializers_refuse_the_same_byte() -> Result<(), JsValue> {
    let witness = new_multi(&[1, 1, 0, 0]).expect("boolean bytes are accepted");
    assert_eq!(
        witness.get_selector_used().map(|bytes| bytes.to_vec()),
        Some(vec![1, 1, 0, 0])
    );

    // `selector_used` is the last field of the Multi witness: its four bytes
    // end the serialization in both encodings.
    let mut le = witness.to_bytes_le().unwrap().to_vec();
    assert_eq!(&le[le.len() - 4..], &[1, 1, 0, 0], "proof setup: LE layout");
    let last = le.len() - 1;
    le[last] = 2;
    let le_result = WasmRLNWitnessInput::from_bytes_le(&u8a(&le)).map(|_| ());
    assert!(
        le_result.is_err(),
        "fromBytesLE must refuse the selector byte 2, got {le_result:?}"
    );

    let mut be = witness.to_bytes_be().unwrap().to_vec();
    assert_eq!(&be[be.len() - 4..], &[1, 1, 0, 0], "proof setup: BE layout");
    let last = be.len() - 1;
    be[last] = 2;
    let be_result = WasmRLNWitnessInput::from_bytes_be(&u8a(&be)).map(|_| ());
    assert!(
        be_result.is_err(),
        "fromBytesBE must refuse the selector byte 2, got {be_result:?}"
    );
    Ok(())
}
