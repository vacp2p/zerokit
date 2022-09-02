use rln::public::RLN;
use wasm_bindgen::prelude::*;
extern crate web_sys;

use js_sys::{BigInt as JsBigInt, Object, Uint8Array};
use num_bigint::BigInt;

#[wasm_bindgen]
pub fn init_panic_hook() {
    console_error_panic_hook::set_once();
}

#[wasm_bindgen(js_name = RLN)]
pub struct RLNWrapper {
    // The purpose of this wrapper is to hold a RLN instance with the 'static lifetime
    // because wasm_bindgen does not allow returning elements with lifetimes
    instance: RLN<'static>,
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[wasm_bindgen(js_name = newRLN)]
pub fn wasm_new(tree_height: usize, zkey: Uint8Array, vk: Uint8Array) -> *mut RLNWrapper {
    let instance = RLN::new_with_params(tree_height, zkey.to_vec(), vk.to_vec());
    let wrapper = RLNWrapper { instance };
    Box::into_raw(Box::new(wrapper))
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[wasm_bindgen(js_name = getSerializedRLNWitness)]
pub fn wasm_get_serialized_rln_witness(ctx: *mut RLNWrapper, input: Uint8Array) -> Uint8Array {
    let wrapper = unsafe { &mut *ctx };
    let rln_witness = wrapper
        .instance
        .get_serialized_rln_witness(&input.to_vec()[..]);

    Uint8Array::from(&rln_witness[..])
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[wasm_bindgen(js_name = insertMember)]
pub fn wasm_set_next_leaf(ctx: *mut RLNWrapper, input: Uint8Array) -> Result<(), String> {
    let wrapper = unsafe { &mut *ctx };
    if wrapper.instance.set_next_leaf(&input.to_vec()[..]).is_ok() {
        Ok(())
    } else {
        Err("could not insert member into merkle tree".into())
    }
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[wasm_bindgen(js_name = RLNWitnessToJson)]
pub fn rln_witness_to_json(ctx: *mut RLNWrapper, serialized_witness: Uint8Array) -> Object {
    let wrapper = unsafe { &mut *ctx };
    let inputs = wrapper
        .instance
        .get_rln_witness_json(&serialized_witness.to_vec()[..])
        .unwrap();

    let js_value = serde_wasm_bindgen::to_value(&inputs).unwrap();
    let obj = Object::from_entries(&js_value);
    obj.unwrap()
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[wasm_bindgen]
pub fn generate_rln_proof_with_witness(
    ctx: *mut RLNWrapper,
    calculated_witness: Vec<JsBigInt>,
    serialized_witness: Uint8Array,
) -> Result<Uint8Array, String> {
    let wrapper = unsafe { &mut *ctx };

    let witness_vec: Vec<BigInt> = calculated_witness
        .iter()
        .map(|v| {
            v.to_string(10)
                .unwrap()
                .as_string()
                .unwrap()
                .parse::<BigInt>()
                .unwrap()
        })
        .collect();

    let mut output_data: Vec<u8> = Vec::new();

    if wrapper
        .instance
        .generate_rln_proof_with_witness(witness_vec, serialized_witness.to_vec(), &mut output_data)
        .is_ok()
    {
        let result = Uint8Array::from(&output_data[..]);
        std::mem::forget(output_data);
        Ok(result)
    } else {
        std::mem::forget(output_data);
        Err("could not generate proof".into())
    }
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[wasm_bindgen(js_name = generateMembershipKey)]
pub fn wasm_key_gen(ctx: *const RLNWrapper) -> Result<Uint8Array, String> {
    let wrapper = unsafe { &*ctx };
    let mut output_data: Vec<u8> = Vec::new();
    if wrapper.instance.key_gen(&mut output_data).is_ok() {
        let result = Uint8Array::from(&output_data[..]);
        std::mem::forget(output_data);
        Ok(result)
    } else {
        std::mem::forget(output_data);
        Err("could not generate membership keys".into())
    }
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[wasm_bindgen(js_name = verifyProof)]
pub fn wasm_verify(ctx: *const RLNWrapper, proof: Uint8Array) -> bool {
    let wrapper = unsafe { &*ctx };
    if match wrapper.instance.verify(&proof.to_vec()[..]) {
        Ok(verified) => verified,
        Err(_) => return false,
    } {
        return true;
    }

    false
}
