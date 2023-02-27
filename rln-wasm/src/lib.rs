#![cfg(target_arch = "wasm32")]

extern crate wasm_bindgen;
extern crate web_sys;

use js_sys::{BigInt as JsBigInt, Object, Uint8Array};
use num_bigint::BigInt;
use rln::public::RLN;
use wasm_bindgen::prelude::*;

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
pub fn wasm_new(
    tree_height: usize,
    zkey: Uint8Array,
    vk: Uint8Array,
) -> Result<*mut RLNWrapper, String> {
    let instance = RLN::new_with_params(tree_height, zkey.to_vec(), vk.to_vec())
        .map_err(|err| format!("{:#?}", err))?;
    let wrapper = RLNWrapper { instance };
    Ok(Box::into_raw(Box::new(wrapper)))
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[wasm_bindgen(js_name = getSerializedRLNWitness)]
pub fn wasm_get_serialized_rln_witness(
    ctx: *mut RLNWrapper,
    input: Uint8Array,
) -> Result<Uint8Array, String> {
    let wrapper = unsafe { &mut *ctx };
    let rln_witness = wrapper
        .instance
        .get_serialized_rln_witness(&input.to_vec()[..])
        .map_err(|err| format!("{:#?}", err))?;

    Ok(Uint8Array::from(&rln_witness[..]))
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
#[wasm_bindgen(js_name = setLeavesFrom)]
pub fn wasm_set_leaves_from(
    ctx: *mut RLNWrapper,
    index: usize,
    input: Uint8Array,
) -> Result<(), String> {
    let wrapper = unsafe { &mut *ctx };
    if wrapper
        .instance
        .set_leaves_from(index as usize, &input.to_vec()[..])
        .is_ok()
    {
        Ok(())
    } else {
        Err("could not set multiple leaves".into())
    }
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[wasm_bindgen(js_name = initTreeWithLeaves)]
pub fn wasm_init_tree_with_leaves(ctx: *mut RLNWrapper, input: Uint8Array) -> Result<(), String> {
    let wrapper = unsafe { &mut *ctx };
    if wrapper
        .instance
        .init_tree_with_leaves(&input.to_vec()[..])
        .is_ok()
    {
        Ok(())
    } else {
        Err("could not init merkle tree".into())
    }
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[wasm_bindgen(js_name = RLNWitnessToJson)]
pub fn rln_witness_to_json(
    ctx: *mut RLNWrapper,
    serialized_witness: Uint8Array,
) -> Result<Object, String> {
    let wrapper = unsafe { &mut *ctx };
    let inputs = wrapper
        .instance
        .get_rln_witness_json(&serialized_witness.to_vec()[..])
        .map_err(|err| err.to_string())?;

    let js_value = serde_wasm_bindgen::to_value(&inputs).map_err(|err| err.to_string())?;
    Object::from_entries(&js_value).map_err(|err| format!("{:#?}", err))
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[wasm_bindgen]
pub fn generate_rln_proof_with_witness(
    ctx: *mut RLNWrapper,
    calculated_witness: Vec<JsBigInt>,
    serialized_witness: Uint8Array,
) -> Result<Uint8Array, String> {
    let wrapper = unsafe { &mut *ctx };

    let mut witness_vec: Vec<BigInt> = vec![];

    for v in calculated_witness {
        witness_vec.push(
            v.to_string(10)
                .map_err(|err| format!("{:#?}", err))?
                .as_string()
                .ok_or("not a string error")?
                .parse::<BigInt>()
                .map_err(|err| format!("{:#?}", err))?,
        );
    }

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
#[wasm_bindgen(js_name = generateExtendedMembershipKey)]
pub fn wasm_extended_key_gen(ctx: *const RLNWrapper) -> Result<Uint8Array, String> {
    let wrapper = unsafe { &*ctx };
    let mut output_data: Vec<u8> = Vec::new();
    if wrapper.instance.extended_key_gen(&mut output_data).is_ok() {
        let result = Uint8Array::from(&output_data[..]);
        std::mem::forget(output_data);
        Ok(result)
    } else {
        std::mem::forget(output_data);
        Err("could not generate membership keys".into())
    }
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[wasm_bindgen(js_name = generateSeededMembershipKey)]
pub fn wasm_seeded_key_gen(ctx: *const RLNWrapper, seed: Uint8Array) -> Result<Uint8Array, String> {
    let wrapper = unsafe { &*ctx };
    let mut output_data: Vec<u8> = Vec::new();
    if wrapper
        .instance
        .seeded_key_gen(&seed.to_vec()[..], &mut output_data)
        .is_ok()
    {
        let result = Uint8Array::from(&output_data[..]);
        std::mem::forget(output_data);
        Ok(result)
    } else {
        std::mem::forget(output_data);
        Err("could not generate membership key".into())
    }
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[wasm_bindgen(js_name = generateSeededExtendedMembershipKey)]
pub fn wasm_seeded_extended_key_gen(
    ctx: *const RLNWrapper,
    seed: Uint8Array,
) -> Result<Uint8Array, String> {
    let wrapper = unsafe { &*ctx };
    let mut output_data: Vec<u8> = Vec::new();
    if wrapper
        .instance
        .seeded_extended_key_gen(&seed.to_vec()[..], &mut output_data)
        .is_ok()
    {
        let result = Uint8Array::from(&output_data[..]);
        std::mem::forget(output_data);
        Ok(result)
    } else {
        std::mem::forget(output_data);
        Err("could not generate membership key".into())
    }
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[wasm_bindgen(js_name = recovedIDSecret)]
pub fn wasm_recover_id_secret(
    ctx: *const RLNWrapper,
    input_proof_data_1: Uint8Array,
    input_proof_data_2: Uint8Array,
) -> Result<Uint8Array, String> {
    let wrapper = unsafe { &*ctx };
    let mut output_data: Vec<u8> = Vec::new();
    if wrapper
        .instance
        .recover_id_secret(
            &input_proof_data_1.to_vec()[..],
            &input_proof_data_2.to_vec()[..],
            &mut output_data,
        )
        .is_ok()
    {
        let result = Uint8Array::from(&output_data[..]);
        std::mem::forget(output_data);
        Ok(result)
    } else {
        std::mem::forget(output_data);
        Err("could not recover id secret".into())
    }
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[wasm_bindgen(js_name = verifyRLNProof)]
pub fn wasm_verify_rln_proof(ctx: *const RLNWrapper, proof: Uint8Array) -> Result<bool, String> {
    let wrapper = unsafe { &*ctx };
    if match wrapper.instance.verify_rln_proof(&proof.to_vec()[..]) {
        Ok(verified) => verified,
        Err(_) => return Err("error while verifying rln proof".into()),
    } {
        return Ok(true);
    }

    Ok(false)
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[wasm_bindgen(js_name = verifyWithRoots)]
pub fn wasm_verify_with_roots(
    ctx: *const RLNWrapper,
    proof: Uint8Array,
    roots: Uint8Array,
) -> Result<bool, String> {
    let wrapper = unsafe { &*ctx };
    if match wrapper
        .instance
        .verify_with_roots(&proof.to_vec()[..], &roots.to_vec()[..])
    {
        Ok(verified) => verified,
        Err(_) => return Err("error while verifying proof with roots".into()),
    } {
        return Ok(true);
    }

    Ok(false)
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[wasm_bindgen(js_name = getRoot)]
pub fn wasm_get_root(ctx: *const RLNWrapper) -> Result<Uint8Array, String> {
    let wrapper = unsafe { &*ctx };
    let mut output_data: Vec<u8> = Vec::new();
    if wrapper.instance.get_root(&mut output_data).is_ok() {
        let result = Uint8Array::from(&output_data[..]);
        std::mem::forget(output_data);
        Ok(result)
    } else {
        std::mem::forget(output_data);
        Err("could not obtain root".into())
    }
}
