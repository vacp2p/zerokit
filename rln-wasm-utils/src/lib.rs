#![cfg(target_arch = "wasm32")]

use ark_bn254::Fr;
use js_sys::Uint8Array;
use rln::{
    hashers::{hash_to_field_be, hash_to_field_le, poseidon_hash},
    protocol::{extended_keygen, extended_seeded_keygen, keygen, seeded_keygen},
    utils::{
        bytes_be_to_fr, bytes_be_to_vec_fr, bytes_le_to_fr, bytes_le_to_vec_fr, fr_to_bytes_be,
        fr_to_bytes_le, vec_fr_to_bytes_be, vec_fr_to_bytes_le,
    },
};
use std::ops::Deref;
use wasm_bindgen::prelude::*;

#[cfg(feature = "panic_hook")]
#[wasm_bindgen(js_name = initPanicHook)]
pub fn init_panic_hook() {
    console_error_panic_hook::set_once();
}

// WasmFr

#[wasm_bindgen]
#[derive(Clone, Debug, PartialEq)]
pub struct WasmFr(Fr);

impl From<Fr> for WasmFr {
    fn from(fr: Fr) -> Self {
        Self(fr)
    }
}

impl Deref for WasmFr {
    type Target = Fr;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[wasm_bindgen]
pub fn wasmfr_zero() -> WasmFr {
    WasmFr::from(Fr::from(0u32))
}

#[wasm_bindgen]
pub fn wasmfr_one() -> WasmFr {
    WasmFr::from(Fr::from(1u32))
}

#[wasm_bindgen]
pub fn uint_to_wasmfr(value: u32) -> WasmFr {
    WasmFr::from(Fr::from(value))
}

#[wasm_bindgen]
pub fn bytes_le_to_wasmfr(bytes: &Uint8Array) -> WasmFr {
    let bytes_vec = bytes.to_vec();
    let (fr, _) = bytes_le_to_fr(&bytes_vec);
    WasmFr::from(fr)
}

#[wasm_bindgen]
pub fn bytes_be_to_wasmfr(bytes: &Uint8Array) -> WasmFr {
    let bytes_vec = bytes.to_vec();
    let (fr, _) = bytes_be_to_fr(&bytes_vec);
    WasmFr::from(fr)
}

#[wasm_bindgen]
pub fn wasmfr_to_bytes_le(fr: &WasmFr) -> Uint8Array {
    let bytes = fr_to_bytes_le(&fr.0);
    Uint8Array::from(&bytes[..])
}

#[wasm_bindgen]
pub fn wasmfr_to_bytes_be(fr: &WasmFr) -> Uint8Array {
    let bytes = fr_to_bytes_be(&fr.0);
    Uint8Array::from(&bytes[..])
}

#[wasm_bindgen]
pub fn wasmfr_debug(fr: &WasmFr) -> String {
    format!("{:?}", fr.0)
}

// Vec<WasmFr>

#[wasm_bindgen]
pub fn bytes_le_to_vec_wasmfr(bytes: &Uint8Array) -> Result<Vec<WasmFr>, String> {
    let bytes_vec = bytes.to_vec();
    bytes_le_to_vec_fr(&bytes_vec)
        .map(|(vec_fr, _)| vec_fr.into_iter().map(WasmFr::from).collect())
        .map_err(|e| format!("{:?}", e))
}

#[wasm_bindgen]
pub fn bytes_be_to_vec_wasmfr(bytes: &Uint8Array) -> Result<Vec<WasmFr>, String> {
    let bytes_vec = bytes.to_vec();
    bytes_be_to_vec_fr(&bytes_vec)
        .map(|(vec_fr, _)| vec_fr.into_iter().map(WasmFr::from).collect())
        .map_err(|e| format!("{:?}", e))
}

#[wasm_bindgen]
pub fn vec_wasmfr_to_bytes_le(vec: Vec<WasmFr>) -> Uint8Array {
    let fr_vec: Vec<Fr> = vec.iter().map(|w| w.0).collect();
    let bytes = vec_fr_to_bytes_le(&fr_vec);
    Uint8Array::from(&bytes[..])
}

#[wasm_bindgen]
pub fn vec_wasmfr_to_bytes_be(vec: Vec<WasmFr>) -> Uint8Array {
    let fr_vec: Vec<Fr> = vec.iter().map(|w| w.0).collect();
    let bytes = vec_fr_to_bytes_be(&fr_vec);
    Uint8Array::from(&bytes[..])
}

// Utility APIs

#[wasm_bindgen]
pub fn wasm_hash_to_field_le(input: &Uint8Array) -> WasmFr {
    WasmFr::from(hash_to_field_le(&input.to_vec()))
}

#[wasm_bindgen]
pub fn wasm_hash_to_field_be(input: &Uint8Array) -> WasmFr {
    WasmFr::from(hash_to_field_be(&input.to_vec()))
}

#[wasm_bindgen]
pub fn wasm_poseidon_hash_pair(a: &WasmFr, b: &WasmFr) -> WasmFr {
    WasmFr::from(poseidon_hash(&[a.0, b.0]))
}

#[wasm_bindgen]
pub fn wasm_poseidon_hash(inputs: Vec<WasmFr>) -> WasmFr {
    let fr_vec: Vec<Fr> = inputs.iter().map(|w| w.0).collect();
    WasmFr::from(poseidon_hash(&fr_vec))
}

#[wasm_bindgen]
pub fn wasm_key_gen() -> Vec<WasmFr> {
    let (identity_secret_hash, id_commitment) = keygen();
    vec![
        WasmFr::from(*identity_secret_hash),
        WasmFr::from(id_commitment),
    ]
}

#[wasm_bindgen]
pub fn wasm_seeded_key_gen(seed: &Uint8Array) -> Vec<WasmFr> {
    let seed_vec = seed.to_vec();
    let (identity_secret_hash, id_commitment) = seeded_keygen(&seed_vec);
    vec![
        WasmFr::from(identity_secret_hash),
        WasmFr::from(id_commitment),
    ]
}

#[wasm_bindgen]
pub fn wasm_extended_key_gen() -> Vec<WasmFr> {
    let (identity_trapdoor, identity_nullifier, identity_secret_hash, id_commitment) =
        extended_keygen();
    vec![
        WasmFr::from(identity_trapdoor),
        WasmFr::from(identity_nullifier),
        WasmFr::from(identity_secret_hash),
        WasmFr::from(id_commitment),
    ]
}

#[wasm_bindgen]
pub fn wasm_seeded_extended_key_gen(seed: &Uint8Array) -> Vec<WasmFr> {
    let seed_vec = seed.to_vec();
    let (identity_trapdoor, identity_nullifier, identity_secret_hash, id_commitment) =
        extended_seeded_keygen(&seed_vec);
    vec![
        WasmFr::from(identity_trapdoor),
        WasmFr::from(identity_nullifier),
        WasmFr::from(identity_secret_hash),
        WasmFr::from(id_commitment),
    ]
}
