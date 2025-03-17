#![cfg(target_arch = "wasm32")]

extern crate wasm_bindgen;
extern crate web_sys;

use std::vec::Vec;

use js_sys::{BigInt as JsBigInt, Object, Uint8Array};
use num_bigint::BigInt;
use rln::public::{hash, poseidon_hash, RLN};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn init_panic_hook() {
    console_error_panic_hook::set_once();
}

#[wasm_bindgen(js_name = RLN)]
pub struct RLNWrapper {
    // The purpose of this wrapper is to hold a RLN instance with the 'static lifetime
    // because wasm_bindgen does not allow returning elements with lifetimes
    instance: RLN,
}

// Macro to call methods with arbitrary amount of arguments,
// which have the last argument is output buffer pointer
// First argument to the macro is context,
// second is the actual method on `RLN`
// third is the aforementioned output buffer argument
// rest are all other arguments to the method
macro_rules! call_with_output_and_error_msg {
    // this variant is needed for the case when
    // there are zero other arguments
    ($instance:expr, $method:ident, $error_msg:expr) => {
        {
            let mut output_data: Vec<u8> = Vec::new();
            let new_instance = $instance.process();
            if let Err(err) = new_instance.instance.$method(&mut output_data) {
                std::mem::forget(output_data);
                Err(format!("Msg: {:#?}, Error: {:#?}", $error_msg, err))
            } else {
                let result = Uint8Array::from(&output_data[..]);
                std::mem::forget(output_data);
                Ok(result)
            }
        }
    };
    ($instance:expr, $method:ident, $error_msg:expr, $( $arg:expr ),* ) => {
        {
            let mut output_data: Vec<u8> = Vec::new();
            let new_instance = $instance.process();
            if let Err(err) = new_instance.instance.$method($($arg.process()),*, &mut output_data) {
                std::mem::forget(output_data);
                Err(format!("Msg: {:#?}, Error: {:#?}", $error_msg, err))
            } else {
                let result = Uint8Array::from(&output_data[..]);
                std::mem::forget(output_data);
                Ok(result)
            }
        }
    };
}

macro_rules! call {
    ($instance:expr, $method:ident $(, $arg:expr)*) => {
        {
            let new_instance: &mut RLNWrapper = $instance.process();
            new_instance.instance.$method($($arg.process()),*)
        }
    }
}

macro_rules! call_bool_method_with_error_msg {
    ($instance:expr, $method:ident, $error_msg:expr $(, $arg:expr)*) => {
        {
            let new_instance: &RLNWrapper = $instance.process();
            new_instance.instance.$method($($arg.process()),*).map_err(|err| format!("Msg: {:#?}, Error: {:#?}", $error_msg, err))
        }
    }
}

// Macro to execute a function with arbitrary amount of arguments,
// First argument is the function to execute
// Rest are all other arguments to the method
macro_rules! fn_call_with_output_and_error_msg {
    // this variant is needed for the case when
    // there are zero other arguments
    ($func:ident, $error_msg:expr) => {
        {
            let mut output_data: Vec<u8> = Vec::new();
            if let Err(err) = $func(&mut output_data) {
                std::mem::forget(output_data);
                Err(format!("Msg: {:#?}, Error: {:#?}", $error_msg, err))
            } else {
                let result = Uint8Array::from(&output_data[..]);
                std::mem::forget(output_data);
                Ok(result)
            }
        }
    };
    ($func:ident, $error_msg:expr, $( $arg:expr ),* ) => {
        {
            let mut output_data: Vec<u8> = Vec::new();
            if let Err(err) = $func($($arg.process()),*, &mut output_data) {
                std::mem::forget(output_data);
                Err(format!("Msg: {:#?}, Error: {:#?}", $error_msg, err))
            } else {
                let result = Uint8Array::from(&output_data[..]);
                std::mem::forget(output_data);
                Ok(result)
            }
        }
    };
}

trait ProcessArg {
    type ReturnType;
    fn process(self) -> Self::ReturnType;
}

impl ProcessArg for usize {
    type ReturnType = usize;
    fn process(self) -> Self::ReturnType {
        self
    }
}

impl<T> ProcessArg for Vec<T> {
    type ReturnType = Vec<T>;
    fn process(self) -> Self::ReturnType {
        self
    }
}

impl ProcessArg for *const RLN {
    type ReturnType = &'static RLN;
    fn process(self) -> Self::ReturnType {
        unsafe { &*self }
    }
}

impl ProcessArg for *const RLNWrapper {
    type ReturnType = &'static RLNWrapper;
    fn process(self) -> Self::ReturnType {
        unsafe { &*self }
    }
}

impl ProcessArg for *mut RLNWrapper {
    type ReturnType = &'static mut RLNWrapper;
    fn process(self) -> Self::ReturnType {
        unsafe { &mut *self }
    }
}

impl<'a> ProcessArg for &'a [u8] {
    type ReturnType = &'a [u8];

    fn process(self) -> Self::ReturnType {
        self
    }
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[wasm_bindgen(js_name = newRLN)]
pub fn wasm_new(
    zkey: Uint8Array,
) -> Result<*mut RLNWrapper, String> {
    let instance = RLN::new_with_params(zkey.to_vec())
        .map_err(|err| format!("{:#?}", err))?;
    let wrapper = RLNWrapper { instance };
    Ok(Box::into_raw(Box::new(wrapper)))
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[wasm_bindgen(js_name = RLNWitnessToJson)]
pub fn rln_witness_to_json(
    ctx: *mut RLNWrapper,
    serialized_witness: Uint8Array,
) -> Result<Object, String> {
    let inputs = call!(
        ctx,
        get_rln_witness_bigint_json,
        &serialized_witness.to_vec()[..]
    )
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

    call_with_output_and_error_msg!(
        ctx,
        generate_rln_proof_with_witness,
        "could not generate proof",
        witness_vec,
        serialized_witness.to_vec()
    )
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[wasm_bindgen(js_name = generateMembershipKey)]
pub fn wasm_key_gen(ctx: *const RLNWrapper) -> Result<Uint8Array, String> {
    call_with_output_and_error_msg!(ctx, key_gen, "could not generate membership keys")
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[wasm_bindgen(js_name = generateExtendedMembershipKey)]
pub fn wasm_extended_key_gen(ctx: *const RLNWrapper) -> Result<Uint8Array, String> {
    call_with_output_and_error_msg!(ctx, extended_key_gen, "could not generate membership keys")
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[wasm_bindgen(js_name = generateSeededMembershipKey)]
pub fn wasm_seeded_key_gen(ctx: *const RLNWrapper, seed: Uint8Array) -> Result<Uint8Array, String> {
    call_with_output_and_error_msg!(
        ctx,
        seeded_key_gen,
        "could not generate membership key",
        &seed.to_vec()[..]
    )
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[wasm_bindgen(js_name = generateSeededExtendedMembershipKey)]
pub fn wasm_seeded_extended_key_gen(
    ctx: *const RLNWrapper,
    seed: Uint8Array,
) -> Result<Uint8Array, String> {
    call_with_output_and_error_msg!(
        ctx,
        seeded_extended_key_gen,
        "could not generate membership key",
        &seed.to_vec()[..]
    )
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[wasm_bindgen(js_name = recovedIDSecret)]
pub fn wasm_recover_id_secret(
    ctx: *const RLNWrapper,
    input_proof_data_1: Uint8Array,
    input_proof_data_2: Uint8Array,
) -> Result<Uint8Array, String> {
    call_with_output_and_error_msg!(
        ctx,
        recover_id_secret,
        "could not recover id secret",
        &input_proof_data_1.to_vec()[..],
        &input_proof_data_2.to_vec()[..]
    )
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[wasm_bindgen(js_name = verifyWithRoots)]
pub fn wasm_verify_with_roots(
    ctx: *const RLNWrapper,
    proof: Uint8Array,
    roots: Uint8Array,
) -> Result<bool, String> {
    call_bool_method_with_error_msg!(
        ctx,
        verify_with_roots,
        "error while verifying proof with roots".to_string(),
        &proof.to_vec()[..],
        &roots.to_vec()[..]
    )
}

#[wasm_bindgen(js_name = hash)]
pub fn wasm_hash(input: Uint8Array) -> Result<Uint8Array, String> {
    fn_call_with_output_and_error_msg!(hash, "could not generate hash", &input.to_vec()[..])
}

#[wasm_bindgen(js_name = poseidonHash)]
pub fn wasm_poseidon_hash(input: Uint8Array) -> Result<Uint8Array, String> {
    fn_call_with_output_and_error_msg!(
        poseidon_hash,
        "could not generate poseidon hash",
        &input.to_vec()[..]
    )
}
