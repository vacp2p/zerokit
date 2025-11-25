#![cfg(target_arch = "wasm32")]

mod wasm_rln;
mod wasm_utils;

#[cfg(not(feature = "utils"))]
pub use wasm_rln::{WasmRLN, WasmRLNProof, WasmRLNProofValues, WasmRLNWitnessInput};

pub use wasm_utils::{ExtendedIdentity, Hasher, Identity, VecWasmFr, WasmFr};

#[cfg(all(feature = "parallel", not(feature = "utils")))]
pub use wasm_bindgen_rayon::init_thread_pool;

#[cfg(feature = "panic_hook")]
#[wasm_bindgen(js_name = initPanicHook)]
pub fn init_panic_hook() {
    console_error_panic_hook::set_once();
}
