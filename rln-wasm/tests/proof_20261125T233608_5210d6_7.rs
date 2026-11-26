// Proof for finding 20261125T233608-5210d6/7 (same mechanism as F-b9d0b87f, calls
// that finding does not list and one it states does not trap)
//
// Spec (WASM-Specific Notes): "Errors are returned as JavaScript strings that
// can be caught via try-catch blocks."
// Spec (Error Handling): "For WASM and FFI bindings, errors are returned as
// human-readable string messages."
//
// `WasmRLNPartialProof.fromBytesLE`, `WasmRLN.newWithParams` and
// `WasmRLNPoseidon2.newWithParams` do not return an error string for a buffer
// whose vector length prefix is forged. The deserializer panics with
// `capacity overflow`, the wasm module TRAPS, and the JavaScript caller catches
// a `WebAssembly.RuntimeError: unreachable` object.
//
// One test per trapping call. Each call is made from JavaScript inside
// try/catch. A test fails by returning an `Err` whose text states the
// assertion; stack frames are switched off so the assertion line is printed.

#![cfg(target_arch = "wasm32")]
#![cfg(not(feature = "utils"))]

use js_sys::{Function, Uint8Array};
use rln_wasm::{WasmRLN, WasmRLNPartialProof, WasmRLNPoseidon2};
use wasm_bindgen::prelude::*;
use wasm_bindgen_test::wasm_bindgen_test;

const ZKEY_SINGLE: &[u8] =
    include_bytes!("../../rln/resources/tree_depth_20/rln_single/rln_final.arkzkey");
const GRAPH_SINGLE: &[u8] =
    include_bytes!("../../rln/resources/tree_depth_20/rln_single/graph.bin");
const ZKEY_POSEIDON2_SINGLE: &[u8] =
    include_bytes!("../../rln/resources/tree_depth_20/rln_poseidon2_single/rln_final.arkzkey");
const GRAPH_POSEIDON2_SINGLE: &[u8] =
    include_bytes!("../../rln/resources/tree_depth_20/rln_poseidon2_single/graph.bin");

/// Offset of the first vector length prefix of an `.arkzkey`: the verifying
/// key starts with alpha_g1 (64 bytes) and beta_g2, gamma_g2, delta_g2 (128
/// bytes each), all uncompressed, and is followed by the `gamma_abc_g1` vector.
const ZKEY_FIRST_LEN_OFFSET: usize = 64 + 3 * 128;

/// Calls `f` from JavaScript inside try/catch. Returns "ok" when it returned,
/// otherwise "<typeof thrown value>: <thrown value as text>".
fn call_from_js(f: impl FnMut() -> Result<JsValue, JsValue> + 'static) -> String {
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
        "assertion `left == right` failed: {call} on a buffer with a forged length prefix \
         must throw a JavaScript string (spec: \"Errors are returned as JavaScript \
         strings\"), but the call trapped\n  left: \"{outcome}\"\n right: \"string: <error \
         message>\""
    )))
}

fn u8a(bytes: &[u8]) -> Uint8Array {
    Uint8Array::from(bytes)
}

/// The zkey with the element count of its first vector replaced by 2^26
/// (2^26 uncompressed G1 points is 2^32 bytes).
fn forged_zkey(zkey: &[u8]) -> Vec<u8> {
    let at = ZKEY_FIRST_LEN_OFFSET;
    let original = u64::from_le_bytes(zkey[at..at + 8].try_into().unwrap());
    assert!(
        (2..64).contains(&original),
        "proof setup: offset {at} of the zkey must hold the gamma_abc_g1 count, found {original}"
    );
    let mut out = zkey.to_vec();
    out[at..at + 8].copy_from_slice(&(1u64 << 26).to_le_bytes());
    out
}

// WasmRLNPartialProof: its serialization starts with the length prefix of the
// `mask` vector (one byte per element), so the forged count is 2^31.

#[wasm_bindgen_test]
fn partial_proof_from_bytes_le_traps() -> Result<(), JsValue> {
    let mut bytes = (1u64 << 31).to_le_bytes().to_vec();
    bytes.extend_from_slice(&[0u8; 4]);
    let outcome = call_from_js(move || to_js(WasmRLNPartialProof::from_bytes_le(&u8a(&bytes))));
    assert_string_error("WasmRLNPartialProof.fromBytesLE", outcome)
}

// newWithParams

#[wasm_bindgen_test]
fn wasm_rln_new_with_params_traps_on_forged_zkey() -> Result<(), JsValue> {
    let zkey = forged_zkey(ZKEY_SINGLE);
    let outcome =
        call_from_js(move || to_js(WasmRLN::new_with_params(&u8a(&zkey), &u8a(GRAPH_SINGLE))));
    assert_string_error("WasmRLN.newWithParams", outcome)
}

#[wasm_bindgen_test]
fn wasm_rln_poseidon2_new_with_params_traps_on_forged_zkey() -> Result<(), JsValue> {
    let zkey = forged_zkey(ZKEY_POSEIDON2_SINGLE);
    let outcome = call_from_js(move || {
        to_js(WasmRLNPoseidon2::new_with_params(
            &u8a(&zkey),
            &u8a(GRAPH_POSEIDON2_SINGLE),
        ))
    });
    assert_string_error("WasmRLNPoseidon2.newWithParams", outcome)
}

/// Control: ordinary malformed buffers (truncated) do follow the spec, so the
/// helper above tells a string error from a trap.
#[wasm_bindgen_test]
fn control_truncated_buffers_are_string_errors() -> Result<(), JsValue> {
    let outcome = call_from_js(|| to_js(WasmRLNPartialProof::from_bytes_le(&u8a(&[1u8, 0, 0]))));
    assert_string_error("control: WasmRLNPartialProof.fromBytesLE (truncated)", outcome)?;
    let outcome = call_from_js(|| {
        to_js(WasmRLN::new_with_params(
            &u8a(&ZKEY_SINGLE[..1000]),
            &u8a(GRAPH_SINGLE),
        ))
    });
    assert_string_error("control: WasmRLN.newWithParams (truncated zkey)", outcome)
}
