use crate::public::RLN;
use std::slice;

/// Buffer struct is taken from
/// https://github.com/celo-org/celo-threshold-bls-rs/blob/master/crates/threshold-bls-ffi/src/ffi.rs
///
/// Also heavily inspired by https://github.com/kilic/rln/blob/master/src/ffi.rs

// TODO Update mul to rln references
// TODO Make sure get_root etc is on right LE form
// TODO Add other FFI interfaces (update_next_member etc) while making sure it
// is according to new RLN spec

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

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[no_mangle]
pub extern "C" fn get_root(ctx: *const RLN, output_buffer: *mut Buffer) -> bool {
    let rln = unsafe { &*ctx };
    let mut output_data: Vec<u8> = Vec::new();
    match rln.get_root(&mut output_data) {
        Ok(_) => true,
        Err(_) => false,
    };
    unsafe { *output_buffer = Buffer::from(&output_data[..]) };
    std::mem::forget(output_data);
    true
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[no_mangle]
pub extern "C" fn new_circuit(ctx: *mut *mut RLN) -> bool {
    println!("rln ffi: new");
    let mul = RLN::new();

    unsafe { *ctx = Box::into_raw(Box::new(mul)) };

    true
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[no_mangle]
pub extern "C" fn prove(ctx: *const RLN, output_buffer: *mut Buffer) -> bool {
    println!("RLN ffi: prove");
    let mul = unsafe { &*ctx };
    let mut output_data: Vec<u8> = Vec::new();

    match mul.prove(&mut output_data) {
        Ok(proof_data) => proof_data,
        Err(_) => return false,
    };
    unsafe { *output_buffer = Buffer::from(&output_data[..]) };
    std::mem::forget(output_data);
    true
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[no_mangle]
pub extern "C" fn verify(
    ctx: *const RLN,
    proof_buffer: *const Buffer,
    result_ptr: *mut u32,
) -> bool {
    println!("RLN ffi: verify");
    let mul = unsafe { &*ctx };
    let proof_data = <&[u8]>::from(unsafe { &*proof_buffer });
    if match mul.verify(proof_data) {
        Ok(verified) => verified,
        Err(_) => return false,
    } {
        unsafe { *result_ptr = 0 };
    } else {
        unsafe { *result_ptr = 1 };
    };
    true
}
