// This crate implements the public Foreign Function Interface (FFI) for the RLN module

use std::slice;

use crate::public::RLN;

/// Buffer struct is taken from
/// <https://github.com/celo-org/celo-threshold-bls-rs/blob/master/crates/threshold-bls-ffi/src/ffi.rs>
///
/// Also heavily inspired by <https://github.com/kilic/rln/blob/master/src/ffi.rs>

#[repr(C)]
#[derive(Clone, Debug, PartialEq)]
pub struct Buffer {
    pub ptr: *const u8,
    pub len: usize,
}

impl From<&[u8]> for Buffer {
    fn from(src: &[u8]) -> Self {
        Self {
            ptr: src.as_ptr(),
            len: src.len(),
        }
    }
}

impl<'a> From<&Buffer> for &'a [u8] {
    fn from(src: &Buffer) -> &'a [u8] {
        unsafe { slice::from_raw_parts(src.ptr, src.len) }
    }
}

// TODO: check if there are security implications by using this clippy
// #[allow(clippy::not_unsafe_ptr_arg_deref)]

////////////////////////////////////////////////////////
// RLN APIs
////////////////////////////////////////////////////////

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[no_mangle]
pub extern "C" fn new(tree_height: usize, input_buffer: *const Buffer, ctx: *mut *mut RLN) -> bool {
    let input_data = <&[u8]>::from(unsafe { &*input_buffer });
    let rln = RLN::new(tree_height, input_data);
    unsafe { *ctx = Box::into_raw(Box::new(rln)) };
    true
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[no_mangle]
pub extern "C" fn new_with_params(
    tree_height: usize,
    circom_buffer: *const Buffer,
    zkey_buffer: *const Buffer,
    vk_buffer: *const Buffer,
    ctx: *mut *mut RLN,
) -> bool {
    let circom_data = <&[u8]>::from(unsafe { &*circom_buffer });
    let zkey_data = <&[u8]>::from(unsafe { &*zkey_buffer });
    let vk_data = <&[u8]>::from(unsafe { &*vk_buffer });
    let rln = RLN::new_with_params(
        tree_height,
        circom_data.to_vec(),
        zkey_data.to_vec(),
        vk_data.to_vec(),
    );
    unsafe { *ctx = Box::into_raw(Box::new(rln)) };
    true
}

////////////////////////////////////////////////////////
// Merkle tree APIs
////////////////////////////////////////////////////////
#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[no_mangle]
pub extern "C" fn set_tree(ctx: *mut RLN, tree_height: usize) -> bool {
    let rln = unsafe { &mut *ctx };
    rln.set_tree(tree_height).is_ok()
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[no_mangle]
pub extern "C" fn delete_leaf(ctx: *mut RLN, index: usize) -> bool {
    let rln = unsafe { &mut *ctx };
    rln.delete_leaf(index).is_ok()
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[no_mangle]
pub extern "C" fn set_leaf(ctx: *mut RLN, index: usize, input_buffer: *const Buffer) -> bool {
    let rln = unsafe { &mut *ctx };
    let input_data = <&[u8]>::from(unsafe { &*input_buffer });
    rln.set_leaf(index, input_data).is_ok()
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[no_mangle]
pub extern "C" fn set_next_leaf(ctx: *mut RLN, input_buffer: *const Buffer) -> bool {
    let rln = unsafe { &mut *ctx };
    let input_data = <&[u8]>::from(unsafe { &*input_buffer });
    rln.set_next_leaf(input_data).is_ok()
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[no_mangle]
pub extern "C" fn set_leaves_from(
    ctx: *mut RLN,
    index: usize,
    input_buffer: *const Buffer,
) -> bool {
    let rln = unsafe { &mut *ctx };
    let input_data = <&[u8]>::from(unsafe { &*input_buffer });
    rln.set_leaves_from(index, input_data).is_ok()
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[no_mangle]
pub extern "C" fn init_tree_with_leaves(ctx: *mut RLN, input_buffer: *const Buffer) -> bool {
    let rln = unsafe { &mut *ctx };
    let input_data = <&[u8]>::from(unsafe { &*input_buffer });
    rln.init_tree_with_leaves(input_data).is_ok()
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[no_mangle]
pub extern "C" fn get_root(ctx: *const RLN, output_buffer: *mut Buffer) -> bool {
    let rln = unsafe { &*ctx };
    let mut output_data: Vec<u8> = Vec::new();
    if rln.get_root(&mut output_data).is_ok() {
        unsafe { *output_buffer = Buffer::from(&output_data[..]) };
        std::mem::forget(output_data);
        true
    } else {
        std::mem::forget(output_data);
        false
    }
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[no_mangle]
pub extern "C" fn get_proof(ctx: *const RLN, index: usize, output_buffer: *mut Buffer) -> bool {
    let rln = unsafe { &*ctx };
    let mut output_data: Vec<u8> = Vec::new();
    if rln.get_proof(index, &mut output_data).is_ok() {
        unsafe { *output_buffer = Buffer::from(&output_data[..]) };
        std::mem::forget(output_data);
        true
    } else {
        std::mem::forget(output_data);
        false
    }
}

////////////////////////////////////////////////////////
// zkSNARKs APIs
////////////////////////////////////////////////////////
#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[no_mangle]
pub extern "C" fn prove(
    ctx: *mut RLN,
    input_buffer: *const Buffer,
    output_buffer: *mut Buffer,
) -> bool {
    let rln = unsafe { &mut *ctx };
    let input_data = <&[u8]>::from(unsafe { &*input_buffer });
    let mut output_data: Vec<u8> = Vec::new();

    if rln.prove(input_data, &mut output_data).is_ok() {
        unsafe { *output_buffer = Buffer::from(&output_data[..]) };
        std::mem::forget(output_data);
        true
    } else {
        std::mem::forget(output_data);
        false
    }
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[no_mangle]
pub extern "C" fn verify(
    ctx: *const RLN,
    proof_buffer: *const Buffer,
    proof_is_valid_ptr: *mut bool,
) -> bool {
    let rln = unsafe { &*ctx };
    let proof_data = <&[u8]>::from(unsafe { &*proof_buffer });
    if match rln.verify(proof_data) {
        Ok(verified) => verified,
        Err(_) => return false,
    } {
        unsafe { *proof_is_valid_ptr = true };
    } else {
        unsafe { *proof_is_valid_ptr = false };
    };
    true
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[no_mangle]
pub extern "C" fn generate_rln_proof(
    ctx: *mut RLN,
    input_buffer: *const Buffer,
    output_buffer: *mut Buffer,
) -> bool {
    let rln = unsafe { &mut *ctx };
    let input_data = <&[u8]>::from(unsafe { &*input_buffer });
    let mut output_data: Vec<u8> = Vec::new();

    if rln.generate_rln_proof(input_data, &mut output_data).is_ok() {
        unsafe { *output_buffer = Buffer::from(&output_data[..]) };
        std::mem::forget(output_data);
        true
    } else {
        std::mem::forget(output_data);
        false
    }
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[no_mangle]
pub extern "C" fn verify_rln_proof(
    ctx: *const RLN,
    proof_buffer: *const Buffer,
    proof_is_valid_ptr: *mut bool,
) -> bool {
    let rln = unsafe { &*ctx };
    let proof_data = <&[u8]>::from(unsafe { &*proof_buffer });
    if match rln.verify_rln_proof(proof_data) {
        Ok(verified) => verified,
        Err(_) => return false,
    } {
        unsafe { *proof_is_valid_ptr = true };
    } else {
        unsafe { *proof_is_valid_ptr = false };
    };
    true
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[no_mangle]
pub extern "C" fn verify_with_roots(
    ctx: *const RLN,
    proof_buffer: *const Buffer,
    roots_buffer: *const Buffer,
    proof_is_valid_ptr: *mut bool,
) -> bool {
    let rln = unsafe { &*ctx };
    let proof_data = <&[u8]>::from(unsafe { &*proof_buffer });
    let roots_data = <&[u8]>::from(unsafe { &*roots_buffer });
    if match rln.verify_with_roots(proof_data, roots_data) {
        Ok(verified) => verified,
        Err(_) => return false,
    } {
        unsafe { *proof_is_valid_ptr = true };
    } else {
        unsafe { *proof_is_valid_ptr = false };
    };
    true
}

////////////////////////////////////////////////////////
// Utils
////////////////////////////////////////////////////////
#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[no_mangle]
pub extern "C" fn key_gen(ctx: *const RLN, output_buffer: *mut Buffer) -> bool {
    let rln = unsafe { &*ctx };
    let mut output_data: Vec<u8> = Vec::new();
    if rln.key_gen(&mut output_data).is_ok() {
        unsafe { *output_buffer = Buffer::from(&output_data[..]) };
        std::mem::forget(output_data);
        true
    } else {
        std::mem::forget(output_data);
        false
    }
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[no_mangle]
pub extern "C" fn seeded_key_gen(
    ctx: *const RLN,
    input_buffer: *const Buffer,
    output_buffer: *mut Buffer,
) -> bool {
    let rln = unsafe { &*ctx };
    let input_data = <&[u8]>::from(unsafe { &*input_buffer });
    let mut output_data: Vec<u8> = Vec::new();
    if rln.seeded_key_gen(input_data, &mut output_data).is_ok() {
        unsafe { *output_buffer = Buffer::from(&output_data[..]) };
        std::mem::forget(output_data);
        true
    } else {
        std::mem::forget(output_data);
        false
    }
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[no_mangle]
pub extern "C" fn extended_key_gen(ctx: *const RLN, output_buffer: *mut Buffer) -> bool {
    let rln = unsafe { &*ctx };
    let mut output_data: Vec<u8> = Vec::new();
    if rln.extended_key_gen(&mut output_data).is_ok() {
        unsafe { *output_buffer = Buffer::from(&output_data[..]) };
        std::mem::forget(output_data);
        true
    } else {
        std::mem::forget(output_data);
        false
    }
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[no_mangle]
pub extern "C" fn seeded_extended_key_gen(
    ctx: *const RLN,
    input_buffer: *const Buffer,
    output_buffer: *mut Buffer,
) -> bool {
    let rln = unsafe { &*ctx };
    let input_data = <&[u8]>::from(unsafe { &*input_buffer });
    let mut output_data: Vec<u8> = Vec::new();
    if rln
        .seeded_extended_key_gen(input_data, &mut output_data)
        .is_ok()
    {
        unsafe { *output_buffer = Buffer::from(&output_data[..]) };
        std::mem::forget(output_data);
        true
    } else {
        std::mem::forget(output_data);
        false
    }
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[no_mangle]
pub extern "C" fn recover_id_secret(
    ctx: *const RLN,
    input_proof_buffer_1: *const Buffer,
    input_proof_buffer_2: *const Buffer,
    output_buffer: *mut Buffer,
) -> bool {
    let rln = unsafe { &*ctx };
    let input_proof_data_1 = <&[u8]>::from(unsafe { &*input_proof_buffer_1 });
    let input_proof_data_2 = <&[u8]>::from(unsafe { &*input_proof_buffer_2 });
    let mut output_data: Vec<u8> = Vec::new();
    if rln
        .recover_id_secret(input_proof_data_1, input_proof_data_2, &mut output_data)
        .is_ok()
    {
        unsafe { *output_buffer = Buffer::from(&output_data[..]) };
        std::mem::forget(output_data);
        true
    } else {
        std::mem::forget(output_data);
        false
    }
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[no_mangle]
pub extern "C" fn hash(
    ctx: *mut RLN,
    input_buffer: *const Buffer,
    output_buffer: *mut Buffer,
) -> bool {
    let rln = unsafe { &mut *ctx };
    let input_data = <&[u8]>::from(unsafe { &*input_buffer });
    let mut output_data: Vec<u8> = Vec::new();

    if rln.hash(input_data, &mut output_data).is_ok() {
        unsafe { *output_buffer = Buffer::from(&output_data[..]) };
        std::mem::forget(output_data);
        true
    } else {
        std::mem::forget(output_data);
        false
    }
}
