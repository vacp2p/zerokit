// std
use std::ops::Deref;
// third-party
use ark_bn254::Fr;
use js_sys::{BigInt, Uint8Array};
use wasm_bindgen::prelude::wasm_bindgen;
// internal
use rln::protocol::keygen;

#[wasm_bindgen]
#[derive(Clone, Copy, Debug)]
pub struct WasmFr(Fr);

#[wasm_bindgen]
impl WasmFr {

    pub fn zero() -> Self {
        Self(Fr::from(0))
    }

    pub fn new(value: u64) -> Self {
        Self(Fr::from(value))
    }

    pub fn from_bigint(value: BigInt) -> Self {
        Self::from(value)
    }

    pub fn debug(&self) -> String {
        format!("{:?}", self)
    }
}

// TODO: should we have a try_from impl?
impl From<BigInt> for WasmFr {
    fn from(value: BigInt) -> Self {
        Self::new(value.as_f64().unwrap() as u64)
    }
}

#[wasm_bindgen(js_name = ffi2GenerateMembershipKey)]
pub fn ffi2_wasm_key_gen() -> Result<Vec<WasmFr>, String> {

    let (identity_secret_hash, id_commitment) = keygen();
    Ok(
        vec![
            WasmFr(identity_secret_hash.deref().clone()),
            WasmFr(id_commitment)
        ]
    )
}




