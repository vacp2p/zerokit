// This crate implements the public Foreign Function Interface (FFI) for the RLN module

use std::slice;

use crate::public::{hash as public_hash, poseidon_hash as public_poseidon_hash, RLN};

// Macro to call methods with arbitrary amount of arguments,
// First argument to the macro is context,
// second is the actual method on `RLN`
// rest are all other arguments to the method
macro_rules! call {
    ($instance:expr, $method:ident $(, $arg:expr)*) => {
        {
            let new_instance: &mut RLN = $instance.process();
            match new_instance.$method($($arg.process()),*) {
                Ok(()) => {
                    true
                }
                Err(err) => {
                    eprintln!("execution error: {err}");
                    false
                }
            }
        }
    }
}

// Macro to call methods with arbitrary amount of arguments,
// which have the last argument is output buffer pointer
// First argument to the macro is context,
// second is the actual method on `RLN`
// third is the aforementioned output buffer argument
// rest are all other arguments to the method
macro_rules! call_with_output_arg {
    // this variant is needed for the case when
    // there are zero other arguments
    ($instance:expr, $method:ident, $output_arg:expr) => {
        {
            let mut output_data: Vec<u8> = Vec::new();
            let new_instance = $instance.process();
            match new_instance.$method(&mut output_data) {
                Ok(()) => {
                    unsafe { *$output_arg = Buffer::from(&output_data[..]) };
                    std::mem::forget(output_data);
                    true
                }
                Err(err) => {
                    std::mem::forget(output_data);
                    eprintln!("execution error: {err}");
                    false
                }
            }
        }
    };
    ($instance:expr, $method:ident, $output_arg:expr, $( $arg:expr ),* ) => {
        {
            let mut output_data: Vec<u8> = Vec::new();
            let new_instance = $instance.process();
            match new_instance.$method($($arg.process()),*, &mut output_data) {
                Ok(()) => {
                    unsafe { *$output_arg = Buffer::from(&output_data[..]) };
                    std::mem::forget(output_data);
                    true
                }
                Err(err) => {
                    std::mem::forget(output_data);
                    eprintln!("execution error: {err}");
                    false
                }
            }
        }
    };

}

// Macro to call methods with arbitrary amount of arguments,
// which are not implemented in a ctx RLN object
// First argument is the method to call
// Second argument is the output buffer argument
// The remaining arguments are all other inputs to the method
macro_rules! no_ctx_call_with_output_arg {
    ($method:ident, $output_arg:expr, $( $arg:expr ),* ) => {
        {
            let mut output_data: Vec<u8> = Vec::new();
            match $method($($arg.process()),*, &mut output_data) {
                Ok(()) => {
                    unsafe { *$output_arg = Buffer::from(&output_data[..]) };
                    std::mem::forget(output_data);
                    true
                }
                Err(err) => {
                    std::mem::forget(output_data);
                    eprintln!("execution error: {err}");
                    false
                }
            }
        }
    }
}

// Macro to call methods with arbitrary amount of arguments,
// which have the last argument as bool
// First argument to the macro is context,
// second is the actual method on `RLN`
// third is the aforementioned bool argument
// rest are all other arguments to the method
macro_rules! call_with_bool_arg {
    ($instance:expr, $method:ident, $bool_arg:expr, $( $arg:expr ),* ) => {
        {
            let new_instance = $instance.process();
            if match new_instance.$method($($arg.process()),*,) {
                Ok(result) => result,
                Err(err) => {
                    eprintln!("execution error: {err}");
                    return false
                },
            } {
                unsafe { *$bool_arg = true };
            } else {
                unsafe { *$bool_arg = false };
            };
            true
        }
    }
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

impl ProcessArg for *const Buffer {
    type ReturnType = &'static [u8];
    fn process(self) -> Self::ReturnType {
        <&[u8]>::from(unsafe { &*self })
    }
}

impl<'a> ProcessArg for *const RLN<'a> {
    type ReturnType = &'a RLN<'a>;
    fn process(self) -> Self::ReturnType {
        unsafe { &*self }
    }
}

impl<'a> ProcessArg for *mut RLN<'a> {
    type ReturnType = &'a mut RLN<'a>;
    fn process(self) -> Self::ReturnType {
        unsafe { &mut *self }
    }
}

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
    match RLN::new(tree_height, input_buffer.process()) {
        Ok(rln) => {
            unsafe { *ctx = Box::into_raw(Box::new(rln)) };
            true
        }
        Err(err) => {
            eprintln!("could not instantiate rln: {err}");
            false
        }
    }
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[no_mangle]
pub extern "C" fn new_with_params(
    tree_height: usize,
    circom_buffer: *const Buffer,
    zkey_buffer: *const Buffer,
    vk_buffer: *const Buffer,
    tree_config: *const Buffer,
    ctx: *mut *mut RLN,
) -> bool {
    match RLN::new_with_params(
        tree_height,
        circom_buffer.process().to_vec(),
        zkey_buffer.process().to_vec(),
        vk_buffer.process().to_vec(),
        tree_config.process(),
    ) {
        Ok(rln) => {
            unsafe { *ctx = Box::into_raw(Box::new(rln)) };
            true
        }
        Err(err) => {
            eprintln!("could not instantiate rln: {err}");
            false
        }
    }
}

////////////////////////////////////////////////////////
// Merkle tree APIs
////////////////////////////////////////////////////////
#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[no_mangle]
pub extern "C" fn set_tree(ctx: *mut RLN, tree_height: usize) -> bool {
    call!(ctx, set_tree, tree_height)
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[no_mangle]
pub extern "C" fn delete_leaf(ctx: *mut RLN, index: usize) -> bool {
    call!(ctx, delete_leaf, index)
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[no_mangle]
pub extern "C" fn set_leaf(ctx: *mut RLN, index: usize, input_buffer: *const Buffer) -> bool {
    call!(ctx, set_leaf, index, input_buffer)
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[no_mangle]
pub extern "C" fn get_leaf(ctx: *mut RLN, index: usize, output_buffer: *mut Buffer) -> bool {
    call_with_output_arg!(ctx, get_leaf, output_buffer, index)
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[no_mangle]
pub extern "C" fn leaves_set(ctx: *mut RLN) -> usize {
    ctx.process().leaves_set()
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[no_mangle]
pub extern "C" fn set_next_leaf(ctx: *mut RLN, input_buffer: *const Buffer) -> bool {
    call!(ctx, set_next_leaf, input_buffer)
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[no_mangle]
pub extern "C" fn set_leaves_from(
    ctx: *mut RLN,
    index: usize,
    input_buffer: *const Buffer,
) -> bool {
    call!(ctx, set_leaves_from, index, input_buffer)
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[no_mangle]
pub extern "C" fn init_tree_with_leaves(ctx: *mut RLN, input_buffer: *const Buffer) -> bool {
    call!(ctx, init_tree_with_leaves, input_buffer)
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[no_mangle]
pub extern "C" fn atomic_operation(
    ctx: *mut RLN,
    index: usize,
    leaves_buffer: *const Buffer,
    indices_buffer: *const Buffer,
) -> bool {
    call!(ctx, atomic_operation, index, leaves_buffer, indices_buffer)
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[no_mangle]
pub extern "C" fn seq_atomic_operation(
    ctx: *mut RLN,
    leaves_buffer: *const Buffer,
    indices_buffer: *const Buffer,
) -> bool {
    call!(
        ctx,
        atomic_operation,
        ctx.process().leaves_set(),
        leaves_buffer,
        indices_buffer
    )
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[no_mangle]
pub extern "C" fn get_root(ctx: *const RLN, output_buffer: *mut Buffer) -> bool {
    call_with_output_arg!(ctx, get_root, output_buffer)
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[no_mangle]
pub extern "C" fn get_proof(ctx: *const RLN, index: usize, output_buffer: *mut Buffer) -> bool {
    call_with_output_arg!(ctx, get_proof, output_buffer, index)
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
    call_with_output_arg!(ctx, prove, output_buffer, input_buffer)
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[no_mangle]
pub extern "C" fn verify(
    ctx: *const RLN,
    proof_buffer: *const Buffer,
    proof_is_valid_ptr: *mut bool,
) -> bool {
    call_with_bool_arg!(ctx, verify, proof_is_valid_ptr, proof_buffer)
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[no_mangle]
pub extern "C" fn generate_rln_proof(
    ctx: *mut RLN,
    input_buffer: *const Buffer,
    output_buffer: *mut Buffer,
) -> bool {
    call_with_output_arg!(ctx, generate_rln_proof, output_buffer, input_buffer)
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[no_mangle]
pub extern "C" fn generate_rln_proof_with_witness(
    ctx: *mut RLN,
    input_buffer: *const Buffer,
    output_buffer: *mut Buffer,
) -> bool {
    call_with_output_arg!(
        ctx,
        generate_rln_proof_with_witness,
        output_buffer,
        input_buffer
    )
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[no_mangle]
pub extern "C" fn verify_rln_proof(
    ctx: *const RLN,
    proof_buffer: *const Buffer,
    proof_is_valid_ptr: *mut bool,
) -> bool {
    call_with_bool_arg!(ctx, verify_rln_proof, proof_is_valid_ptr, proof_buffer)
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[no_mangle]
pub extern "C" fn verify_with_roots(
    ctx: *const RLN,
    proof_buffer: *const Buffer,
    roots_buffer: *const Buffer,
    proof_is_valid_ptr: *mut bool,
) -> bool {
    call_with_bool_arg!(
        ctx,
        verify_with_roots,
        proof_is_valid_ptr,
        proof_buffer,
        roots_buffer
    )
}

////////////////////////////////////////////////////////
// Utils
////////////////////////////////////////////////////////
#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[no_mangle]
pub extern "C" fn key_gen(ctx: *const RLN, output_buffer: *mut Buffer) -> bool {
    call_with_output_arg!(ctx, key_gen, output_buffer)
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[no_mangle]
pub extern "C" fn seeded_key_gen(
    ctx: *const RLN,
    input_buffer: *const Buffer,
    output_buffer: *mut Buffer,
) -> bool {
    call_with_output_arg!(ctx, seeded_key_gen, output_buffer, input_buffer)
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[no_mangle]
pub extern "C" fn extended_key_gen(ctx: *const RLN, output_buffer: *mut Buffer) -> bool {
    call_with_output_arg!(ctx, extended_key_gen, output_buffer)
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[no_mangle]
pub extern "C" fn seeded_extended_key_gen(
    ctx: *const RLN,
    input_buffer: *const Buffer,
    output_buffer: *mut Buffer,
) -> bool {
    call_with_output_arg!(ctx, seeded_extended_key_gen, output_buffer, input_buffer)
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[no_mangle]
pub extern "C" fn recover_id_secret(
    ctx: *const RLN,
    input_proof_buffer_1: *const Buffer,
    input_proof_buffer_2: *const Buffer,
    output_buffer: *mut Buffer,
) -> bool {
    call_with_output_arg!(
        ctx,
        recover_id_secret,
        output_buffer,
        input_proof_buffer_1,
        input_proof_buffer_2
    )
}

////////////////////////////////////////////////////////
// Persistent metadata APIs
////////////////////////////////////////////////////////

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[no_mangle]
pub extern "C" fn set_metadata(ctx: *mut RLN, input_buffer: *const Buffer) -> bool {
    call!(ctx, set_metadata, input_buffer)
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[no_mangle]
pub extern "C" fn get_metadata(ctx: *const RLN, output_buffer: *mut Buffer) -> bool {
    call_with_output_arg!(ctx, get_metadata, output_buffer)
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[no_mangle]
pub extern "C" fn flush(ctx: *mut RLN) -> bool {
    call!(ctx, flush)
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[no_mangle]
pub extern "C" fn hash(input_buffer: *const Buffer, output_buffer: *mut Buffer) -> bool {
    no_ctx_call_with_output_arg!(public_hash, output_buffer, input_buffer)
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[no_mangle]
pub extern "C" fn poseidon_hash(input_buffer: *const Buffer, output_buffer: *mut Buffer) -> bool {
    no_ctx_call_with_output_arg!(public_poseidon_hash, output_buffer, input_buffer)
}
