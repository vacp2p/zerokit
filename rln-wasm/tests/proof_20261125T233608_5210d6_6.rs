// Proof for finding 20261125T233608-5210d6/6
//
// Spec (WASM-Specific Notes): "Field elements are wrapped as `WasmFr`
// (`zero()`, `one()`, `fromUint()`, ...)". The spec does not say which
// unsigned integers `fromUint()` accepts or what it does with the others.
//
// The binding declares the parameter as `u32`. The generated JavaScript glue
// passes the JavaScript number straight to the wasm export, which converts it
// with ToInt32: a value of 2^32 or more is reduced modulo 2^32, a negative
// value becomes a large positive one and a fraction is truncated. No error is
// returned, so `WasmFr.fromUint(Date.now())` or a `user_message_limit` above
// 2^32 silently becomes a different field element.
//
// The call must go through the JavaScript glue, because that is where the
// conversion happens. The test runner loads the glue of this test binary
// (which carries the `rln-wasm` exports) as a CommonJS module; the test looks
// it up through `process.mainModule` and calls `WasmFr.fromUint` on it from
// JavaScript, as a consumer would.

#![cfg(target_arch = "wasm32")]

use js_sys::Function;
use rln_wasm::WasmFr;
use wasm_bindgen::prelude::*;
use wasm_bindgen_test::wasm_bindgen_test;

/// Calls the exported `WasmFr.fromUint(<js_expr>)` from JavaScript and returns
/// `value: <decimal>` or `threw: <error>`.
fn from_uint_in_js(js_expr: &str) -> String {
    // Only the stack frames of the failing test are dropped from the output.
    let _ = Function::new_no_args("Error.stackTraceLimit = 0;").call0(&JsValue::NULL);
    // Keep the export in the test binary.
    let _ = WasmFr::from_uint(0);
    let body = format!(
        "const seen = new Set(); const stack = [process.mainModule]; let glue = null;
         while (stack.length) {{
           const m = stack.pop();
           if (!m || seen.has(m)) continue;
           seen.add(m);
           if (m.exports && m.exports.WasmFr) {{ glue = m.exports; break; }}
           for (const c of (m.children || [])) stack.push(c);
         }}
         if (!glue) return 'glue-not-found';
         try {{ return 'value: ' + glue.WasmFr.fromUint({js_expr}).debug(); }}
         catch (e) {{ return 'threw: ' + String(e); }}"
    );
    let out = Function::new_no_args(&body)
        .call0(&JsValue::NULL)
        .expect("the lookup itself must not throw")
        .as_string()
        .expect("the lookup returns a string");
    assert_ne!(
        out, "glue-not-found",
        "proof setup: the wasm-bindgen glue module was not found through process.mainModule"
    );
    out
}

/// An unsigned integer either becomes that field element or is refused.
fn assert_exact_or_error(js_expr: &str, exact: &str, got: String) -> Result<(), JsValue> {
    if got == format!("value: {exact}") || got.starts_with("threw: ") {
        return Ok(());
    }
    Err(JsValue::from_str(&format!(
        "assertion `left == right` failed: WasmFr.fromUint({js_expr}) must give the field \
         element {exact} or report an error, not silently another value\n  left: \"{got}\"\n \
         right: \"value: {exact}\""
    )))
}

/// An input that is not an unsigned integer is refused.
fn assert_error(js_expr: &str, got: String) -> Result<(), JsValue> {
    if got.starts_with("threw: ") {
        return Ok(());
    }
    Err(JsValue::from_str(&format!(
        "assertion `left == right` failed: WasmFr.fromUint({js_expr}) is not an unsigned \
         integer and must report an error, not silently a value\n  left: \"{got}\"\n right: \
         \"threw: <error>\""
    )))
}

#[wasm_bindgen_test]
fn from_uint_above_u32_is_exact_or_an_error() -> Result<(), JsValue> {
    let got = from_uint_in_js("2**32 + 5");
    assert_exact_or_error("2**32 + 5", "4294967301", got)
}

#[wasm_bindgen_test]
fn from_uint_millisecond_timestamp_is_exact_or_an_error() -> Result<(), JsValue> {
    // 2026-11-25T00:00:00Z in milliseconds, a typical epoch source.
    let got = from_uint_in_js("1795564800000");
    assert_exact_or_error("1795564800000", "1795564800000", got)
}

#[wasm_bindgen_test]
fn from_uint_negative_is_an_error() -> Result<(), JsValue> {
    let got = from_uint_in_js("-1");
    assert_error("-1", got)
}

#[wasm_bindgen_test]
fn from_uint_fraction_is_an_error() -> Result<(), JsValue> {
    let got = from_uint_in_js("1.7");
    assert_error("1.7", got)
}

/// Control: a value inside the u32 range is exact.
#[wasm_bindgen_test]
fn control_from_uint_u32_max_is_exact() -> Result<(), JsValue> {
    let got = from_uint_in_js("4294967295");
    assert_exact_or_error("4294967295", "4294967295", got)
}
