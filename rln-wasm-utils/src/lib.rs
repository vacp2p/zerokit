#![cfg(target_arch = "wasm32")]

use js_sys::Uint8Array;
use rln::public::{
    extended_key_gen, hash, key_gen, poseidon_hash, seeded_extended_key_gen, seeded_key_gen,
};
use std::vec::Vec;
use wasm_bindgen::prelude::*;

pub mod ffi2;

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[wasm_bindgen(js_name = generateMembershipKey)]
pub fn wasm_key_gen(is_little_endian: bool) -> Result<Uint8Array, String> {
    let mut output_data: Vec<u8> = Vec::new();
    if let Err(err) = key_gen(&mut output_data, is_little_endian) {
        std::mem::forget(output_data);
        Err(format!(
            "Msg: could not generate membership keys, Error: {:#?}",
            err
        ))
    } else {
        let result = Uint8Array::from(&output_data[..]);
        std::mem::forget(output_data);
        Ok(result)
    }
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[wasm_bindgen(js_name = generateExtendedMembershipKey)]
pub fn wasm_extended_key_gen(is_little_endian: bool) -> Result<Uint8Array, String> {
    let mut output_data: Vec<u8> = Vec::new();
    if let Err(err) = extended_key_gen(&mut output_data, is_little_endian) {
        std::mem::forget(output_data);
        Err(format!(
            "Msg: could not generate membership keys, Error: {:#?}",
            err
        ))
    } else {
        let result = Uint8Array::from(&output_data[..]);
        std::mem::forget(output_data);
        Ok(result)
    }
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[wasm_bindgen(js_name = generateSeededMembershipKey)]
pub fn wasm_seeded_key_gen(seed: Uint8Array, is_little_endian: bool) -> Result<Uint8Array, String> {
    let mut output_data: Vec<u8> = Vec::new();
    let input_data = &seed.to_vec()[..];
    if let Err(err) = seeded_key_gen(input_data, &mut output_data, is_little_endian) {
        std::mem::forget(output_data);
        Err(format!(
            "Msg: could not generate membership key, Error: {:#?}",
            err
        ))
    } else {
        let result = Uint8Array::from(&output_data[..]);
        std::mem::forget(output_data);
        Ok(result)
    }
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[wasm_bindgen(js_name = generateSeededExtendedMembershipKey)]
pub fn wasm_seeded_extended_key_gen(
    seed: Uint8Array,
    is_little_endian: bool,
) -> Result<Uint8Array, String> {
    let mut output_data: Vec<u8> = Vec::new();
    let input_data = &seed.to_vec()[..];
    if let Err(err) = seeded_extended_key_gen(input_data, &mut output_data, is_little_endian) {
        std::mem::forget(output_data);
        Err(format!(
            "Msg: could not generate membership key, Error: {:#?}",
            err
        ))
    } else {
        let result = Uint8Array::from(&output_data[..]);
        std::mem::forget(output_data);
        Ok(result)
    }
}

#[wasm_bindgen(js_name = hash)]
pub fn wasm_hash(input: Uint8Array, is_little_endian: bool) -> Result<Uint8Array, String> {
    let mut output_data: Vec<u8> = Vec::new();
    let input_data = &input.to_vec()[..];
    if let Err(err) = hash(input_data, &mut output_data, is_little_endian) {
        std::mem::forget(output_data);
        Err(format!("Msg: could not generate hash, Error: {:#?}", err))
    } else {
        let result = Uint8Array::from(&output_data[..]);
        std::mem::forget(output_data);
        Ok(result)
    }
}

#[wasm_bindgen(js_name = poseidonHash)]
pub fn wasm_poseidon_hash(input: Uint8Array, is_little_endian: bool) -> Result<Uint8Array, String> {
    let mut output_data: Vec<u8> = Vec::new();
    let input_data = &input.to_vec()[..];
    if let Err(err) = poseidon_hash(input_data, &mut output_data, is_little_endian) {
        std::mem::forget(output_data);
        Err(format!(
            "Msg: could not generate poseidon hash, Error: {:#?}",
            err
        ))
    } else {
        let result = Uint8Array::from(&output_data[..]);
        std::mem::forget(output_data);
        Ok(result)
    }
}
