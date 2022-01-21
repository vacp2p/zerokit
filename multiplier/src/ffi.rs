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
pub extern "C" fn foobar() -> bool {
    true
}

// prove
// verify
// params?
