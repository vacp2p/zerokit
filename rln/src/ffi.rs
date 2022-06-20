use crate::public::RLN;
use std::slice;

/// Buffer struct is taken from
/// https://github.com/celo-org/celo-threshold-bls-rs/blob/master/crates/threshold-bls-ffi/src/ffi.rs
///
/// Also heavily inspired by https://github.com/kilic/rln/blob/master/src/ffi.rs

#[repr(C)]
#[derive(Clone, Debug, PartialEq)]
pub struct Buffer {
    pub ptr: *const u8,
    pub len: usize,
}

impl From<&[u8]> for Buffer {
    fn from(src: &[u8]) -> Self {
        Self {
            ptr: &src[0] as *const u8,
            len: src.len(),
        }
    }
}

impl<'a> From<&Buffer> for &'a [u8] {
    fn from(src: &Buffer) -> &'a [u8] {
        unsafe { slice::from_raw_parts(src.ptr, src.len) }
    }
}

// TODO: check if there are security implications for this clippy. It seems we should have pub unsafe extern "C" fn ...
// #[allow(clippy::not_unsafe_ptr_arg_deref)]

////////////////////////////////////////////////////////
// RLN APIs
////////////////////////////////////////////////////////

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[no_mangle]
pub extern "C" fn new(tree_height: usize, ctx: *mut *mut RLN) -> bool {
    let rln = RLN::new(tree_height);
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
pub extern "C" fn set_leaf(ctx: *mut RLN, index: usize, input_buffer: *const Buffer) -> bool {
    let rln = unsafe { &mut *ctx };
    let input_data = <&[u8]>::from(unsafe { &*input_buffer });
    rln.set_leaf(index, input_data).is_ok()
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[no_mangle]
pub extern "C" fn set_leaves(ctx: *mut RLN, input_buffer: *const Buffer) -> bool {
    let rln = unsafe { &mut *ctx };
    let input_data = <&[u8]>::from(unsafe { &*input_buffer });
    rln.set_leaves(input_data).is_ok()
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
    ctx: *const RLN,
    input_buffer: *const Buffer,
    output_buffer: *mut Buffer,
) -> bool {
    let rln = unsafe { &*ctx };
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
