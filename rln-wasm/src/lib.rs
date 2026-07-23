#![cfg(target_arch = "wasm32")]

pub mod wasm_rln;
pub mod wasm_utils;

#[cfg(feature = "panic_hook")]
use wasm_bindgen::prelude::wasm_bindgen;
#[cfg(all(feature = "parallel", not(feature = "utils")))]
pub use wasm_bindgen_rayon::init_thread_pool;
#[cfg(not(feature = "utils"))]
pub use wasm_rln::{
    WasmRLN, WasmRLNMerkleProof, WasmRLNPartialProof, WasmRLNPartialWitnessInput, WasmRLNProof,
    WasmRLNProofValues, WasmRLNWitnessInput,
};
pub use wasm_utils::{
    wasm_hash_to_field_be, wasm_hash_to_field_le, wasm_poseidon_hash_pair, VecWasmFr,
    WasmExtendedIdentityKeys, WasmFr, WasmIdentityKeys, WasmSecretFr, WasmUint8ArrayUtils,
};

#[cfg(feature = "panic_hook")]
#[wasm_bindgen(js_name = initPanicHook)]
pub fn init_panic_hook() {
    console_error_panic_hook::set_once();
}
