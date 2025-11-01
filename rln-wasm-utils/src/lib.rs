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

#[wasm_bindgen(js_name = initPanicHook)]
pub fn init_panic_hook() {
    console_error_panic_hook::set_once();
}

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
pub fn wasm_fr_zero() -> WasmFr {
    WasmFr::from(Fr::from(0u32))
}

#[wasm_bindgen]
pub fn wasm_fr_one() -> WasmFr {
    WasmFr::from(Fr::from(1u32))
}

#[wasm_bindgen]
pub fn wasm_fr_from_uint(value: u32) -> WasmFr {
    WasmFr::from(Fr::from(value))
}

#[wasm_bindgen]
pub fn wasm_fr_from_bytes_le(bytes: &Uint8Array) -> WasmFr {
    let bytes_vec = bytes.to_vec();
    let (fr, _) = bytes_le_to_fr(&bytes_vec);
    WasmFr::from(fr)
}

#[wasm_bindgen]
pub fn wasm_fr_from_bytes_be(bytes: &Uint8Array) -> WasmFr {
    let bytes_vec = bytes.to_vec();
    let (fr, _) = bytes_be_to_fr(&bytes_vec);
    WasmFr::from(fr)
}

#[wasm_bindgen]
pub fn wasm_fr_to_bytes_le(fr: &WasmFr) -> Vec<u8> {
    fr_to_bytes_le(&fr.0)
}

#[wasm_bindgen]
pub fn wasm_fr_to_bytes_be(fr: &WasmFr) -> Vec<u8> {
    fr_to_bytes_be(&fr.0)
}

#[wasm_bindgen]
pub fn wasm_fr_debug(fr: &WasmFr) -> String {
    format!("{:?}", fr.0)
}

#[wasm_bindgen]
pub struct WasmVecFr(Vec<Fr>);

#[wasm_bindgen]
pub fn wasm_vec_fr_new() -> WasmVecFr {
    WasmVecFr(Vec::new())
}

#[wasm_bindgen]
pub fn wasm_vec_fr_with_capacity(capacity: usize) -> WasmVecFr {
    WasmVecFr(Vec::with_capacity(capacity))
}

#[wasm_bindgen]
pub fn wasm_vec_fr_from_bytes_le(bytes: &Uint8Array) -> Result<WasmVecFr, String> {
    let bytes_vec = bytes.to_vec();
    bytes_le_to_vec_fr(&bytes_vec)
        .map(|(vec_fr, _)| WasmVecFr(vec_fr))
        .map_err(|e| format!("{:?}", e))
}

#[wasm_bindgen]
pub fn wasm_vec_fr_from_bytes_be(bytes: &Uint8Array) -> Result<WasmVecFr, String> {
    let bytes_vec = bytes.to_vec();
    bytes_be_to_vec_fr(&bytes_vec)
        .map(|(vec_fr, _)| WasmVecFr(vec_fr))
        .map_err(|e| format!("{:?}", e))
}

#[wasm_bindgen]
pub fn wasm_vec_fr_len(vec: &WasmVecFr) -> usize {
    vec.0.len()
}

#[wasm_bindgen]
pub fn wasm_vec_fr_is_empty(vec: &WasmVecFr) -> bool {
    vec.0.is_empty()
}

#[wasm_bindgen]
pub fn wasm_vec_fr_get(vec: &WasmVecFr, index: usize) -> Option<WasmFr> {
    vec.0.get(index).map(|&fr| WasmFr::from(fr))
}

#[wasm_bindgen]
pub fn wasm_vec_fr_push(vec: &mut WasmVecFr, element: &WasmFr) {
    vec.0.push(element.0);
}

#[wasm_bindgen]
pub fn wasm_vec_fr_pop(vec: &mut WasmVecFr) -> Option<WasmFr> {
    vec.0.pop().map(WasmFr::from)
}

#[wasm_bindgen]
pub fn wasm_vec_fr_to_bytes_le(vec: &WasmVecFr) -> Vec<u8> {
    vec_fr_to_bytes_le(&vec.0)
}

#[wasm_bindgen]
pub fn wasm_vec_fr_to_bytes_be(vec: &WasmVecFr) -> Vec<u8> {
    vec_fr_to_bytes_be(&vec.0)
}

#[wasm_bindgen]
pub fn wasm_vec_fr_debug(vec: &WasmVecFr) -> String {
    format!("WasmVecFr(len={})", vec.0.len())
}

#[wasm_bindgen]
pub fn wasm_hash_to_field_le(input: &Uint8Array) -> WasmFr {
    let input_vec = input.to_vec();
    WasmFr::from(hash_to_field_le(&input_vec))
}

#[wasm_bindgen]
pub fn wasm_hash_to_field_be(input: &Uint8Array) -> WasmFr {
    let input_vec = input.to_vec();
    WasmFr::from(hash_to_field_be(&input_vec))
}

#[wasm_bindgen]
pub fn wasm_poseidon_hash_pair(a: &WasmFr, b: &WasmFr) -> WasmFr {
    WasmFr::from(poseidon_hash(&[a.0, b.0]))
}

#[wasm_bindgen]
pub fn wasm_poseidon_hash_vec(inputs: &WasmVecFr) -> WasmFr {
    WasmFr::from(poseidon_hash(&inputs.0))
}

#[wasm_bindgen]
pub fn wasm_key_gen() -> WasmVecFr {
    let (identity_secret_hash, id_commitment) = keygen();
    WasmVecFr(vec![*identity_secret_hash, id_commitment])
}

#[wasm_bindgen]
pub fn wasm_seeded_key_gen(seed: &Uint8Array) -> WasmVecFr {
    let seed_vec = seed.to_vec();
    let (identity_secret_hash, id_commitment) = seeded_keygen(&seed_vec);
    WasmVecFr(vec![identity_secret_hash, id_commitment])
}

#[wasm_bindgen]
pub fn wasm_extended_key_gen() -> WasmVecFr {
    let (identity_trapdoor, identity_nullifier, identity_secret_hash, id_commitment) =
        extended_keygen();
    WasmVecFr(vec![
        identity_trapdoor,
        identity_nullifier,
        identity_secret_hash,
        id_commitment,
    ])
}

#[wasm_bindgen]
pub fn wasm_seeded_extended_key_gen(seed: &Uint8Array) -> WasmVecFr {
    let seed_vec = seed.to_vec();
    let (identity_trapdoor, identity_nullifier, identity_secret_hash, id_commitment) =
        extended_seeded_keygen(&seed_vec);
    WasmVecFr(vec![
        identity_trapdoor,
        identity_nullifier,
        identity_secret_hash,
        id_commitment,
    ])
}
