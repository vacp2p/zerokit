#![cfg(not(target_arch = "wasm32"))]

pub mod ffi_rln;
pub mod ffi_tree;
pub mod ffi_utils;

// TODO(PR10): drop `stateless` feature gate once V1 FFI surface is removed.
#[cfg(not(feature = "stateless"))]
pub mod ffi_rln_v3;

#[cfg(feature = "headers")]
pub fn generate_headers() -> std::io::Result<()> {
    safer_ffi::headers::builder().to_file("rln.h")?.generate()
}
