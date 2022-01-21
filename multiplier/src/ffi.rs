use crate::public::Multiplier;
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

#[no_mangle]
pub extern "C" fn new(ctx: *mut *mut Multiplier) -> bool {
    println!("multiplier ffi: new");
    let mul = Multiplier::new();

    unsafe { *ctx = Box::into_raw(Box::new(mul)) };

    true
}

#[no_mangle]
pub extern "C" fn prove(
    ctx: *const Multiplier,
    output_buffer: *mut Buffer
) -> bool {
    println!("multiplier ffi: prove");
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

// prove
// verify
// params?
